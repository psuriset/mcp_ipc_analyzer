#!/usr/bin/python3
#
# agent.py (v6) - RHEL 8 Advanced IPC Analysis Agent
#
# This version traces a wide range of IPC mechanisms:
# - Network Sockets (TCP/UDP, IPv4/IPv6)
# - Unix Domain Sockets
# - System V Shared Memory
# - System V Message Queues
# It also enriches data with Parent Process ID (PPID).
#

import json
import socket
import sys
import traceback
from datetime import datetime
from bcc import BPF
from ctypes import (
    Structure,
    Union,
    c_char,
    c_int,
    c_long,
    c_ulong,
    c_uint,
    c_uint8,
    c_uint16,
    c_uint64,
    POINTER,
    cast,
)

# Add parent directory to path to allow importing protocols
sys.path.append('.')
from protocols import get_protocol

# --- CTypes Data Structures ---
TASK_COMM_LEN = 16
UNIX_PATH_MAX = 108

class CommonData(Structure):
    _fields_ = [
        ("ts", c_uint64),
        ("pid", c_uint),
        ("ppid", c_uint),
        ("comm", c_char * TASK_COMM_LEN),
    ]

class NetData(Structure):
    _fields_ = [
        ("ip_version", c_uint8),
        ("saddr", c_uint64 * 2),
        ("daddr", c_uint64 * 2),
        ("sport", c_uint16),
        ("dport", c_uint16),
    ]

class UnixSockData(Structure):
    _fields_ = [
        ("path", c_char * UNIX_PATH_MAX),
    ]

class ShmData(Structure):
    _fields_ = [
        ("shmid", c_int),
        ("shmaddr", c_ulong),
    ]

class MsgqData(Structure):
    _fields_ = [
        ("msqid", c_int),
        ("msgtype", c_long),
    ]

class SpecificData(Union):
    _fields_ = [
        ("net", NetData),
        ("unix_sock", UnixSockData),
        ("shm", ShmData),
        ("msgq", MsgqData),
    ]

class Event(Structure):
    _fields_ = [
        ("common", CommonData),
        ("type", c_uint),
        ("data", SpecificData),
    ]


# The enhanced eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/un.h> // For Unix sockets
#include <linux/shm.h>  // For Shared Memory
#include <linux/msg.h>  // For Message Queues

// Enum to identify the type of IPC event
enum event_type {
    EVENT_NET_CONNECT,
    EVENT_NET_ACCEPT,
    EVENT_NET_UDP,
    EVENT_UNIX_CONNECT,
    EVENT_SHM_ATTACH,
    EVENT_MSGQ_SEND,
};

// Common data header for all events
struct common_data_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

// Union to hold data specific to each event type
union specific_data_t {
    // Network Socket Data
    struct {
        u8 ip_version;
        unsigned __int128 saddr;
        unsigned __int128 daddr;
        u16 sport;
        u16 dport;
    } net;

    // Unix Domain Socket Data
    struct {
        char path[108]; // UNIX_PATH_MAX from struct sockaddr_un
    } unix_sock;

    // Shared Memory Data
    struct {
        int shmid;
        unsigned long shmaddr;
    } shm;

    // Message Queue Data
    struct {
        int msqid;
        long msgtype;
    } msgq;
};

// The main event structure sent from kernel to user-space
struct event_t {
    struct common_data_t common;
    enum event_type type;
    union specific_data_t data;
};

BPF_PERF_OUTPUT(events);

// Helper function to fill common data
static void fill_common_data(struct common_data_t *common) {
    common->ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    common->pid = id >> 32;
    bpf_get_current_comm(&common->comm, sizeof(common->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    common->ppid = task->real_parent->tgid;
}

// --- Network Socket Tracing ---
static int trace_net_event(struct pt_regs *ctx, struct sock *sk, enum event_type type) {
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET && family != AF_INET6) return 0;

    struct event_t event = {};
    event.type = type;
    fill_common_data(&event.common);

    event.data.net.ip_version = (family == AF_INET) ? 4 : 6;
    if (event.data.net.ip_version == 4) {
        event.data.net.saddr = sk->__sk_common.skc_rcv_saddr;
        event.data.net.daddr = sk->__sk_common.skc_daddr;
    } else {
        bpf_probe_read_kernel(&event.data.net.saddr, sizeof(event.data.net.saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&event.data.net.daddr, sizeof(event.data.net.daddr), &sk->__sk_common.skc_v6_daddr);
    }
    event.data.net.sport = sk->__sk_common.skc_num;
    event.data.net.dport = sk->__sk_common.skc_dport;

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) { return trace_net_event(ctx, sk, EVENT_NET_CONNECT); }
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) { return trace_net_event(ctx, sk, EVENT_NET_CONNECT); }
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (sk == NULL) return 0;
    return trace_net_event(ctx, sk, EVENT_NET_ACCEPT);
}
int kprobe__udp_send_skb(struct pt_regs *ctx, struct sock *sk) { return trace_net_event(ctx, sk, EVENT_NET_UDP); }

// --- Unix Domain Socket Tracing ---
int kprobe__unix_stream_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr_un *addr) {
    struct event_t event = {};
    event.type = EVENT_UNIX_CONNECT;
    fill_common_data(&event.common);
    bpf_probe_read_user(&event.data.unix_sock.path, sizeof(event.data.unix_sock.path), addr->sun_path);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// --- Shared Memory Tracing ---
int kprobe__sys_shmat(struct pt_regs *ctx, int shmid, char __user *shmaddr) {
    struct event_t event = {};
    event.type = EVENT_SHM_ATTACH;
    fill_common_data(&event.common);
    event.data.shm.shmid = shmid;
    event.data.shm.shmaddr = (unsigned long)shmaddr;
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// --- Message Queue Tracing ---
int kprobe__sys_msgsnd(struct pt_regs *ctx, int msqid, struct msgbuf __user *msgp) {
    struct event_t event = {};
    event.type = EVENT_MSGQ_SEND;
    fill_common_data(&event.common);
    event.data.msgq.msqid = msqid;
    bpf_probe_read_user(&event.data.msgq.msgtype, sizeof(event.data.msgq.msgtype), &msgp->mtype);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# --- Python User-Space Processing ---

def int_to_ip(addr, ip_version):
    try:
        if ip_version == 4:
            return socket.inet_ntop(socket.AF_INET, addr[0].to_bytes(4, 'little'))
        elif ip_version == 6:
            full_addr = (addr[1] << 64) | addr[0]
            return socket.inet_ntop(socket.AF_INET6, full_addr.to_bytes(16, 'big'))
        return "Unknown"
    except Exception:
        return "ConversionError"

def format_event(event):
    """Formats an event from the kernel into a structured JSON object."""
    common = {
        "timestamp": datetime.now().isoformat(),
        "process": {
            "pid": event.common.pid,
            "ppid": event.common.ppid,
            "command": event.common.comm.decode('utf-8', 'replace')
        }
    }

    # Network Connect Event
    if event.type == 0: # EVENT_NET_CONNECT
        common["ipc_mechanism"] = "outbound_network_socket"
        common["details"] = {
            "transport_protocol": "TCP",
            "local_address": int_to_ip(event.data.net.saddr, event.data.net.ip_version),
            "local_port": event.data.net.sport,
            "remote_address": int_to_ip(event.data.net.daddr, event.data.net.ip_version),
            "remote_port": event.data.net.dport,
            "application_protocol": get_protocol(event.data.net.dport)
        }
    # Network Accept Event
    elif event.type == 1: # EVENT_NET_ACCEPT
        common["ipc_mechanism"] = "inbound_network_socket"
        common["details"] = {
            "transport_protocol": "TCP",
            "local_address": int_to_ip(event.data.net.daddr, event.data.net.ip_version),
            "local_port": event.data.net.dport,
            "remote_address": int_to_ip(event.data.net.saddr, event.data.net.ip_version),
            "remote_port": event.data.net.sport,
            "application_protocol": get_protocol(event.data.net.dport)
        }
    # UDP Event
    elif event.type == 2: # EVENT_NET_UDP
        common["ipc_mechanism"] = "outbound_network_socket"
        common["details"] = {
            "transport_protocol": "UDP",
            "local_address": int_to_ip(event.data.net.saddr, event.data.net.ip_version),
            "local_port": event.data.net.sport,
            "remote_address": int_to_ip(event.data.net.daddr, event.data.net.ip_version),
            "remote_port": event.data.net.dport,
            "application_protocol": get_protocol(event.data.net.dport)
        }
    # Unix Socket Connect Event
    elif event.type == 3: # EVENT_UNIX_CONNECT
        common["ipc_mechanism"] = "unix_domain_socket"
        common["details"] = {
            "path": event.data.unix_sock.path.decode('utf-8', 'replace')
        }
    # Shared Memory Attach Event
    elif event.type == 4: # EVENT_SHM_ATTACH
        common["ipc_mechanism"] = "systemv_shared_memory"
        common["details"] = {
            "action": "attach",
            "shmid": event.data.shm.shmid,
            "shmaddr": hex(event.data.shm.shmaddr)
        }
    # Message Queue Send Event
    elif event.type == 5: # EVENT_MSGQ_SEND
        common["ipc_mechanism"] = "systemv_message_queue"
        common["details"] = {
            "action": "send",
            "msqid": event.data.msgq.msqid,
            "msgtype": event.data.msgq.msgtype
        }
    else:
        common["ipc_mechanism"] = "unknown"
        common["details"] = {"error": "Unrecognized event type"}

    return common

def print_event_callback(cpu, data, size):
    """Callback function for BPF perf buffer."""
    try:
        # Cast the raw data pointer to our new Event structure
        event = cast(data, POINTER(Event)).contents
        formatted_event = format_event(event)
        print(json.dumps(formatted_event))
        sys.stdout.flush()
    except Exception:
        traceback.print_exc(file=sys.stderr)

if __name__ == "__main__":
    b = BPF(text=bpf_program)

    # Attach Network Probes
    b.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="kprobe__tcp_v6_connect")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="kretprobe__inet_csk_accept")
    b.attach_kprobe(event="udp_send_skb", fn_name="kprobe__udp_send_skb")

    # Attach Unix Socket Probes
    b.attach_kprobe(event="unix_stream_connect", fn_name="kprobe__unix_stream_connect")

    # Attach Shared Memory Probes
    shmat_fn_name = b.get_syscall_fnname("shmat")
    b.attach_kprobe(event=shmat_fn_name, fn_name="kprobe__sys_shmat")

    # Attach Message Queue Probes
    msgsnd_fn_name = b.get_syscall_fnname("msgsnd")
    b.attach_kprobe(event=msgsnd_fn_name, fn_name="kprobe__sys_msgsnd")

    # Open perf buffer and start polling
    b["events"].open_perf_buffer(print_event_callback)
    sys.stderr.write("Agent started. Tracing TCP, UDP, Unix Sockets, Shared Memory, and Message Queues... Press Ctrl+C to stop.\n")
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.stderr.write("Agent stopped.\n")
        exit(0)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        exit(1)