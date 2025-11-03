# RHEL IPC Analysis MCP Server (Model Agnostic)

## 1. Overview

This project provides a sophisticated, multi-tool Model-Context-Protocol (MCP) server designed to give an AI model a deep, agentic understanding of a RHEL system's processes and network communications and allow killing processes.

This server is **model-agnostic**. It provides tools to gather raw data and a specialized tool to generate a high-quality prompt for analysis by any powerful Large Language Model (LLM).

## 2. Tools Provided

1.  **`get_process_connection_snapshot` (Primary Tool):** This is the most direct and powerful tool. It provides a complete, one-time snapshot of all running processes and their currently active and listening network connections, including the identified application protocol. **This should be your first choice for a comprehensive system overview.**

2.  **`get_live_network_events` (Streaming):** This tool uses a high-performance eBPF agent to monitor only *new* network connections in real-time. It is best for observing changes as they happen.

3.  **`generate_ipc_analysis_prompt`:** This tool automates the analysis process by calling the snapshot tool and formatting its output into a detailed prompt for an LLM.

4.  **`send_signal_to_pid` (Dangerous!):** This tool allows to send a signal to almost any process on the machine, so you can e.g. send 'SIGINT' (and if that does not help even 'SIGKILL') to a process you want to terminate. This is dangerous to expose to AI and given this MCP server does not have any authentication, currently you are also exposing that to anybody on the network. Only use on test machines!

## 3. Prerequisites & Installation

- Python 3.10+
- BCC and Kernel Headers for the eBPF agent. Install with:
  ```bash
  # dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3.13
  ```
- Mine bcc lib was installed to older Python, so workaround it:
  ```bash
  # ln -s /usr/lib/python3.9/site-packages/bcc /usr/lib/python3.13/site-packages/bcc
  ```
- Install Python libraries:
  ```bash
  # cd rhel_ipc_analyzer
  # python3.13 -m venv venv --system-site-packages
  # source venv/bin/activate
  # pip install -r requirements.txt
  ```

## 4. How to Run the Server

The server must be run with root privileges.

```bash
sudo python3 main.py
```

The server will start and be available at `http://<your-server-ip>:8000`.

## 5. How to Use the Server's Tools

To connect to MCP server running on remote machine, configure your AI agent
to know about it. E.g. for Gemini CLI, you can use command like this:

```bash
gemini mcp add --transport http mcp_ipc_analyzer_on_machine1 http://machine1.example.com:8000/mcp
```

This will create a config file like this:

```bash
$ cat .gemini/settings.json
{
  "mcpServers": {
    "mcp_ipc_analyzer_on_machine1": {
      "httpUrl": "http://machine1.example.com:8000/mcp"
    }
  }
}
```

For demonstation purposes, all MCP server tools are also exposed via regular
API endpoints, so you can use them like this:

### Tool 1: Get Process Connection Snapshot (Recommended)

This provides a full picture of the system's current network state.

**Example `curl` command:**
```bash
curl --silent http://machine1.example.com:8000/get_process_connection_snapshot | jq .
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
curl --silent http://machine1.example.com:8000/generate_ipc_analysis_prompt | jq .
```

Then, copy the `analysis_prompt` from the `analysis_request.json` file and paste it into your AI agent.

### Tool 3: Get Live Network Events (Streaming)

Use this to see new connections as they happen.

**Example `curl` command (stream events for 10 seconds):**
```bash
curl --silent --no-buffer -X POST http://machine1.example.com:8000/get_live_network_events --json '{"duration": 10}' | jq .
```

### Tool 4: Send signal to PID (Dangerous!)

Assuming you have process with PID 12345 running on a machine and you want to send `SIGINT` to it (to kill it effectively):

**Example `curl` command:**
```bash
curl --silent -X POST http://machine1.example.com:8000/send_signal_to_pid --json '{"pid": 12345, "sig_str": "SIGINT"}' | jq .
{
  "pid": 12345,
  "sig_str": "SIGINT",
  "message": "Signal sent to the process",
  "process_status": {
    "status": "No such process"
  }
}
```
