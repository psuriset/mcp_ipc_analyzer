#!/usr/bin/python3
#
# agent.py (v5) - RHEL 8 Process Network Analysis Agent
#
# This version correctly handles IPv4/IPv6 addresses from the kernel
# and produces structured JSON output for each network event.
#

import json
import socket
import sys
import traceback
import signal
from datetime import datetime
from bcc import BPF

# Add parent directory to path to allow importing protocols
sys.path.append('.')
from protocols import get_protocol

# The eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

enum event_type {
    EVENT_TCP_CONNECT,
    EVENT_TCP_ACCEPT,
    EVENT_UDP_SEND,
};

struct data_t {
    u64 ts;
    u32 pid;
    u8 ip_version;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

static int process_tcp_event(struct pt_regs *ctx, struct sock *sk, enum event_type type) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t data = {};
    u16 family = sk->__sk_common.skc_family;

    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = type;
    data.ip_version = (family == AF_INET) ? 4 : 6;
    
    if (data.ip_version == 4) {
        data.saddr = sk->__sk_common.skc_rcv_saddr;
        data.daddr = sk->__sk_common.skc_daddr;
    } else {
        bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_v6_daddr);
    }

    data.sport = sk->__sk_common.skc_num;
    data.dport = sk->__sk_common.skc_dport;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return process_tcp_event(ctx, sk, EVENT_TCP_CONNECT);
}

int trace_tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    return process_tcp_event(ctx, sk, EVENT_TCP_CONNECT);
}

int trace_tcp_accept(struct pt_regs *ctx, struct sock *sk) {
    if (sk == NULL) return 0;
    return process_tcp_event(ctx, sk, EVENT_TCP_ACCEPT);
}

int trace_udp_send(struct pt_regs *ctx, struct sock *sk) {
    return process_tcp_event(ctx, sk, EVENT_UDP_SEND);
}
"""

def int_to_ip(addr, ip_version):
    try:
        if ip_version == 4:
            ipv4_addr_int = addr[0]
            return socket.inet_ntop(socket.AF_INET, ipv4_addr_int.to_bytes(4, 'little'))
        elif ip_version == 6:
            full_addr = (addr[1] << 64) | addr[0]
            return socket.inet_ntop(socket.AF_INET6, full_addr.to_bytes(16, 'big'))
        return "Unknown"
    except Exception:
        return "ConversionError"

def print_event(cpu, data, size):
    try:
        event = b["events"].event(data)
        
        ipc_mechanism = "unknown"
        transport_protocol = "unknown"
        identified_app_protocol = "unknown"
        
        if event.type == 0:
            ipc_mechanism = "outbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(event.dport)
        elif event.type == 1:
            ipc_mechanism = "inbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(event.sport)
        elif event.type == 2:
            ipc_mechanism = "outbound_udp_datagram"
            transport_protocol = "UDP"
            identified_app_protocol = get_protocol(event.dport)

        output = {
            "timestamp": datetime.now().isoformat(),
            "process_details": { "pid": event.pid, "command": event.comm.decode('utf-8', 'replace') },
            "network_ipc_mechanism": ipc_mechanism,
            "transport_protocol": transport_protocol,
            "communication_target": {
                "remote_address": int_to_ip(event.daddr, event.ip_version),
                "remote_port": event.dport,
                "identified_application_protocol": identified_app_protocol,
            },
            "source": { "local_address": int_to_ip(event.saddr, event.ip_version), "local_port": event.sport }
        }
        
        print(json.dumps(output)) # Print as a single line for easier parsing
        sys.stdout.flush()

    except Exception:
        # Use stderr for errors to not corrupt the JSON output stream
        traceback.print_exc(file=sys.stderr)

# Global flag to control the main loop
running = True

def signal_handler(signum, frame):
    """Handles SIGTERM and SIGINT to gracefully shut down the agent."""
    global running
    running = False
    sys.stderr.write(f"Caught signal {signum}, stopping agent...\n")

if __name__ == "__main__":
    # Register the signal handler for SIGTERM and SIGINT
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    b = BPF(text=bpf_program)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect")
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_tcp_v6_connect")
    b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_tcp_accept")
    b.attach_kprobe(event="udp_send_skb", fn_name="trace_udp_send")

    b["events"].open_perf_buffer(print_event)

    try:
        while running:
            b.perf_buffer_poll(timeout=200)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        exit(1)
    finally:
        sys.stderr.write("Agent stopped.\n")
        exit(0)
