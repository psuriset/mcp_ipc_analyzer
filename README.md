# RHEL IPC Analysis MCP Server (Model Agnostic)

## 1. Overview

This project provides a sophisticated, multi-tool Model-Context-Protocol (MCP) server designed to give an AI model a deep, agentic understanding of a RHEL 8 system's processes and network communications.

This server is **model-agnostic**. It provides tools to gather raw data and a specialized tool to generate a high-quality prompt for analysis by any powerful Large Language Model (LLM), such as the one in Cursor.

## 2. Tools Provided

1.  **`get_process_connection_snapshot` (Primary Tool):** This is the most direct and powerful tool. It provides a complete, one-time snapshot of all running processes and their currently active and listening network connections, including the identified application protocol. **This should be your first choice for a comprehensive system overview.**

2.  **`get_live_network_events` (Streaming):** This tool uses a high-performance eBPF agent to monitor only *new* network connections in real-time. It is best for observing changes as they happen.

3.  **`generate_ipc_analysis_prompt`:** This tool automates the analysis process by calling the snapshot tool and formatting its output into a detailed prompt for an LLM.

## 3. Prerequisites & Installation

- Python 3.10+
- BCC and Kernel Headers for the eBPF agent. Install with:
  ```bash
  sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3.13
  ```
- Install Python libraries:
  ```bash
  cd rhel_ipc_analyzer
  python3.13 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```

## 4. How to Run the Server

The server must be run with root privileges.

```bash
sudo python3 main.py
```

The server will start and be available at `http://<your-server-ip>:8000`.

## 5. How to Use the Server's Tools

### Tool 1: Get Process Connection Snapshot (Recommended)

This provides a full picture of the system's current network state.

**Example `curl` command:**
```bash
curl -X POST http://127.0.0.1:8000/mcp/call_tool \
-H "Content-Type: application/json" \
-d '{
  "tool_name": "get_process_connection_snapshot",
  "parameters": {}
}'
```

**Example Output Snippet:**
```json
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
```

### Tool 2: Generate IPC Analysis Prompt

This automates the analysis by generating a prompt for your favorite LLM.

**Example `curl` command:**
```bash
curl -X POST http://127.0.0.1:8000/mcp/call_tool \
-H "Content-Type: application/json" \
-d '{
  "tool_name": "generate_ipc_analysis_prompt",
  "parameters": {}
}' > analysis_request.json
```
Then, copy the `analysis_prompt` from the `analysis_request.json` file and paste it into Cursor.

### Tool 3: Get Live Network Events (Streaming)

Use this to see new connections as they happen.

**Example `curl` command:**
```bash
curl -X POST http://127.0.0.1:8000/mcp/call_tool \
-H "Content-Type: application/json" \
-d '{
  "tool_name": "get_live_network_events",
  "parameters": {
    "duration_seconds": 10
  }
}'
```
