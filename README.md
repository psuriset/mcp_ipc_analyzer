# RHEL Advanced IPC Analyzer

## 1. Overview

This project provides a powerful **standalone eBPF agent** and a **Model-Context-Protocol (MCP) server** to perform deep, real-time analysis of Inter-Process Communication (IPC) on a RHEL 8 system.

It is designed for two primary use cases:
1.  **Direct, Real-Time Monitoring:** Run the standalone eBPF agent to get a raw, detailed stream of various IPC events as they happen.
2.  **AI-Powered Analysis:** Use the MCP server to provide tools for a Large Language Model (LLM) to analyze system behavior in a structured way.

---

## 2. The Advanced eBPF Agent

The core of this project is a sophisticated eBPF agent that traces a wide variety of IPC mechanisms at the kernel level with minimal overhead.

### Key Features:
- **Comprehensive IPC Tracing:** Captures much more than just network traffic.
  - **Network Sockets:** TCP and UDP connections (IPv4/IPv6).
  - **Unix Domain Sockets:** Local communication between processes.
  - **System V Shared Memory:** Traces processes attaching to shared memory segments.
  - **System V Message Queues:** Traces processes sending messages to message queues.
- **Rich Data Enrichment:** Each event is enriched with process details, including PID, command, and Parent Process ID (PPID).
- **Kernel Compatibility:** Dynamically resolves syscall names to ensure compatibility across different kernel versions.
- **Structured JSON Output:** Streams events as single-line JSON objects, perfect for parsing with tools like `jq`.

### How to Run the Agent Standalone

This is the recommended method for raw data collection and direct analysis.

**Command:**
```bash
# Run from the root of the mcp_ipc_analyzer directory
sudo python3 -u ebpf_agent/agent.py
```

**Example Output Stream:**
You will see a real-time stream of JSON objects.

*Network Event Example:*
```json
{"timestamp": "2023-10-27T15:30:01.123456", "process": {"pid": 12345, "ppid": 1234, "command": "curl"}, "ipc_mechanism": "outbound_network_socket", "details": {"transport_protocol": "TCP", "local_address": "192.168.1.10", "local_port": 54321, "remote_address": "142.250.191.196", "remote_port": 443, "application_protocol": "HTTPS/TLS"}}
```

*Unix Socket Example:*
```json
{"timestamp": "2023-10-27T15:31:05.654321", "process": {"pid": 54321, "ppid": 1, "command": "systemd"}, "ipc_mechanism": "unix_domain_socket", "details": {"path": "/run/systemd/journal/stdout"}}
```

*Shared Memory Example:*
```json
{"timestamp": "2023-10-27T15:32:10.987654", "process": {"pid": 11223, "ppid": 11220, "command": "my_app"}, "ipc_mechanism": "systemv_shared_memory", "details": {"action": "attach", "shmid": 123456, "shmaddr": "0x7f1234567890"}}
```

---

## 3. The MCP Server

The MCP server provides a higher-level, model-agnostic interface for an AI to interact with the system's state.

### How to Run the Server
```bash
sudo python3 main.py
```

### Server Tools

1.  **`get_process_connection_snapshot` (Primary Tool):**
    - **Functionality:** Provides a one-time snapshot of all running processes and their *currently active* network connections.
    - **Use Case:** Best for a comprehensive, static overview of the system's network state.

2.  **`get_live_network_events` (Streaming):**
    - **Functionality:** Runs the advanced eBPF agent for a specified duration and streams the captured events.
    - **Note:** This tool now captures all IPC events from the enhanced agent, not just network connections.
    - **Use Case:** Best for observing system behavior and all types of IPC as it happens.

3.  **`generate_ipc_analysis_prompt`:**
    - **Functionality:** Automates analysis by running the snapshot tool and formatting the output into a detailed prompt for an LLM.

---

## 4. Prerequisites & Installation

- Python 3.7+
- BCC and Kernel Headers for the eBPF agent. Install with:
  ```bash
  # For RHEL/Fedora based systems
  sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3
  ```
- Install Python libraries:
  ```bash
  pip3 install -r requirements.txt
  ```