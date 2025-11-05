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
{"timestamp": "2023-10-27T15:32:10.987654", "process": {"pid": 11223, "ppid": 11220, "command": "python3"}, "ipc_mechanism": "systemv_shared_memory", "details": {"action": "attach", "shmid": 123456, "shmaddr": "0x7f1234567890"}}
```

---

## 3. The MCP Server

The MCP server provides a higher-level, model-agnostic interface for an AI to interact with the system's state.

### Server Tools

#### 1. `get_process_connection_snapshot`
- **Functionality:** Provides a one-time snapshot of all running processes and their *currently active* network connections.
- **Use Case:** Best for a comprehensive, static overview of the system's network state.

#### 2. `get_live_ipc_events`
- **Functionality:** Runs the advanced eBPF agent for a specified duration and streams all captured IPC events.
- **Note:** This tool captures all IPC events from the enhanced agent, including network, Unix sockets, shared memory, and message queues.
- **Use Case:** Best for observing the complete picture of system behavior and all types of IPC as it happens.

#### 3. `generate_ipc_analysis_prompt`
- **Functionality:** Automates analysis by running the snapshot tool and formatting the output into a detailed prompt ready to be sent to an LLM.
- **Use Case:** The quickest way to go from raw data to expert-level analysis.

##### Example Generated Prompt:
The `analysis_prompt` field in the tool's output will contain a prompt similar to the following:

```text
As an expert Linux Systems Analyst, your task is to analyze a snapshot of processes and their network connections from a RHEL 8 system to identify Inter-Process Communication (IPC) patterns.

Here is the snapshot of processes with active or listening network connections:
--- PROCESS CONNECTION SNAPSHOT ---
{
  "process_connections": [
    {
      "pid": 1234,
      "name": "sshd",
      "user": "root",
      "command": "/usr/sbin/sshd -D",
      "connections": [
        {
          "transport_protocol": "TCP",
          "identified_application_protocol": "SSH",
          "local_address": "0.0.0.0:22",
          "remote_address": "N/A",
          "status": "LISTEN"
        }
      ]
    },
    {
      "pid": 5678,
      "name": "curl",
      "user": "user1",
      "command": "curl https://www.google.com",
      "connections": [
        {
          "transport_protocol": "TCP",
          "identified_application_protocol": "HTTPS/TLS",
          "local_address": "192.168.1.10:54321",
          "remote_address": "142.250.191.196:443",
          "status": "ESTABLISHED"
        }
      ]
    }
  ]
}
--- END PROCESS CONNECTION SNAPSHOT ---

Based on the data provided, perform the following analysis:
1.  **Identify Key Services:** List the processes that are acting as servers (i.e., in a 'LISTEN' state). What services are they providing based on their port and process name?
2.  **Identify Key Clients:** List the processes that have established outbound connections. What external services are they communicating with?
3.  **Provide a High-Level Summary:** Write a brief summary of the system's role based on this snapshot. Is it primarily a web server, a database server, a client machine, or a mix of roles?

Present your analysis in a clear, structured format.
```

### How to Use the MCP Server

Once the server is running, you can interact with it by calling its tools from another terminal using a command like `curl`. The server listens on port `8000`.

**1. List Available Tools:**
You can see a list of all available tools and their descriptions by calling the `/openapi.json` endpoint or by visiting the interactive documentation at `http://127.0.0.1:8000/docs`.

**2. Call a Specific Tool:**
To call a tool, you send a POST request to its endpoint. For tools that take parameters (like `get_live_ipc_events`), you provide them in a JSON body.

**Example: Calling `get_live_ipc_events`**
This command will run the eBPF agent for 10 seconds and stream all the IPC events it captures directly to your terminal.

```bash
curl -X POST http://127.0.0.1:8000/get_live_ipc_events \
-H "Content-Type: application/json" \
-d '{
  "duration_seconds": 10
}'
```

---

## 4. Prerequisites & Installation

- Python 3.7+
- **BCC and Kernel Headers:** The eBPF agent requires these to be installed.
  ```bash
  # For RHEL/Fedora based systems
  sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3
  ```

### Setup and Running

1.  **Create and activate a Python virtual environment:** This isolates the project's dependencies.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    *(Note: On Windows, the activation command is `venv\Scripts\activate`)*

2.  **Install Python libraries:**
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Run the desired component:**
    - To run the **standalone eBPF agent**:
      ```bash
      sudo python3 -u ebpf_agent/agent.py
      ```
    - To run the **MCP Server**:
      ```bash
      sudo python3 main.py
      ```