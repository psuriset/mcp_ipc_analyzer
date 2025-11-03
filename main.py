#!/usr/bin/python3
#
# main.py - RHEL IPC Analysis MCP Server (Model Agnostic)
#
# This version enriches the snapshot tool to include identified
# application protocols for each network connection.
#

import asyncio
import json
import psutil
import socket
import signal
import os
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi_mcp import FastApiMCP

from models import MonitorParams, SignalParams
from ebpf_agent.protocols import get_protocol

AGENT_SCRIPT_PATH = "./ebpf_agent/agent.py"

app = FastAPI(
    debug=True,
    summary=f"An MCP server for {socket.gethostname()} machine with tools to gather system data, analyze inter process communication and signal processes.",
)


@app.get("/health", summary="Health Check")
async def health_check():
    return {"status": "ok"}


# --- Tool Implementation ---
@app.get(
    "/get_process_connection_snapshot",
    operation_id="get_process_connection_snapshot",
    summary=f"Provides a comprehensive snapshot of all running processes on machine {socket.gethostname()} and their currently active/listening network connections (TCP/UDP), including identified application protocols.",
)
def get_process_connection_snapshot():
    proc_list = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline"]):
        try:
            connections = []
            for conn in proc.connections(kind="inet"):
                # Identify the application protocol based on the port
                app_protocol = "Unknown"
                if conn.status == "LISTEN":
                    app_protocol = get_protocol(conn.laddr.port)
                elif conn.raddr:
                    app_protocol = get_protocol(conn.raddr.port)

                connections.append(
                    {
                        "transport_protocol": (
                            "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        ),
                        "identified_application_protocol": app_protocol,
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": (
                            f"{conn.raddr.ip}:{conn.raddr.port}"
                            if conn.raddr
                            else "N/A"
                        ),
                        "status": conn.status,
                    }
                )

            if connections:
                proc_list.append(
                    {
                        "pid": proc.info["pid"],
                        "name": proc.info["name"],
                        "user": proc.info["username"],
                        "command": (
                            " ".join(proc.info["cmdline"])
                            if proc.info["cmdline"]
                            else ""
                        ),
                        "connections": connections,
                    }
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return {"process_connections": proc_list}


async def _collect_agent_output(duration: int):
    """Runs the eBPF agent for a specified duration and yields events as they are captured."""
    command = ["python3", "-u", AGENT_SCRIPT_PATH]
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    try:
        # Run the agent for the specified duration
        end_time = asyncio.get_running_loop().time() + duration
        while True:
            # Calculate remaining time to prevent readline from blocking indefinitely
            timeout = end_time - asyncio.get_running_loop().time()
            if timeout <= 0:
                break

            try:
                line = await asyncio.wait_for(
                    process.stdout.readline(), timeout=timeout
                )
                if not line:
                    break  # End of stream from agent

                # Yield the processed event, ignoring malformed lines
                try:
                    yield json.loads(line.decode("utf-8").strip())
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            except asyncio.TimeoutError:
                # This is the expected way to exit the loop after the duration
                break
    finally:
        # Ensure the agent subprocess is terminated
        if process.returncode is None:
            process.terminate()
            await process.wait()


async def _get_live_network_events(duration: MonitorParams):
    """The async generator that produces the event stream for the API endpoint."""
    yield json.dumps(
        {
            "type": "status",
            "message": f"Network agent starting for {duration.duration_seconds} seconds.",
        }
    ) + "\n"
    async for event in _collect_agent_output(duration.duration_seconds):
        yield json.dumps(event) + "\n"
    yield json.dumps({"type": "status", "message": "Monitoring finished."}) + "\n"


@app.post(
    "/get_live_network_events",
    operation_id="get_live_network_events",
    summary=f"Runs a high-performance eBPF agent on machine {socket.gethostname()} to capture only *new* network connections in real-time. Useful for monitoring changes.",
)
async def get_live_network_events(duration: MonitorParams):
    return StreamingResponse(
        _get_live_network_events(duration), media_type="text/event-stream"
    )


@app.get(
    "/generate_ipc_analysis_prompt",
    operation_id="generate_ipc_analysis_prompt",
    summary=f"Gathers data on machine {socket.gethostname()} using the other tools and constructs a detailed prompt for an LLM to perform a system IPC analysis.",
)
async def generate_ipc_analysis_prompt():
    process_connections = get_process_connection_snapshot()
    analysis_prompt = f"""
As an expert Linux Systems Analyst, your task is to analyze a snapshot of processes and their network connections from a RHEL 8 system to identify Inter-Process Communication (IPC) patterns.

Here is the snapshot of processes with active or listening network connections:
--- PROCESS CONNECTION SNAPSHOT ---
{json.dumps(process_connections, indent=2)}
--- END PROCESS CONNECTION SNAPSHOT ---

Based on the data provided, perform the following analysis:
1.  **Identify Key Services:** List the processes that are acting as servers (i.e., in a 'LISTEN' state). What services are they providing based on their port and process name?
2.  **Identify Key Clients:** List the processes that have established outbound connections. What external services are they communicating with?
3.  **Provide a High-Level Summary:** Write a brief summary of the system's role based on this snapshot. Is it primarily a web server, a database server, a client machine, or a mix of roles?

Present your analysis in a clear, structured format.
"""
    return {
        "analysis_prompt": analysis_prompt,
        "data_summary": {
            "processes_with_connections": len(
                process_connections.get("process_connections", [])
            )
        },
    }


@app.post(
    "/send_signal_to_pid",
    operation_id="send_signal_to_pid",
    summary=f"Send given signal to process identified by given PID on machine {socket.gethostname()}. This is very dangerous, as it could kill any process on the machine. E.g. use signal 'SIGINT' to send 'interrupt from keyboard (CTRL + C)' or if it does not make process to stop, send 'SIGKILL' to 'Kill signal - it cannot be caught, blocked, or ignored'.",
)
async def send_signal_to_pid(params: SignalParams):
    if not params.sig_str.startswith("SIG"):
        return {"error": f"Provided signal name '{params.sig_str}' does not start with 'SIG', so does not look like valid signal. You can use e.g. 'SIGINT'."}
    sig = getattr(signal, params.sig_str, None)
    if sig is None:
        return {"error": f"Provided signal name '{params.sig_str}' not defined in Python's 'signal' module. You can use e.g. 'SIGINT'."}
    if not isinstance(sig, signal.Signals):
        return {"error": f"Provided signal name '{params.sig_str}' is not a valid signal in Python's 'signal' module. You can use e.g. 'SIGINT'."}
    if params.pid < 0:
        return {"error": f"PID {params.pid} can not be negative."}
    if params.pid in (0, 1, 2):
        return {"error": f"Process with PID {params.pid} is considered too important for the system, so denying to send a signal."}
    if params.pid == os.getpid():
        return {"error": f"Process with PID {params.pid} is the MCP server itself, so denying to send a signal."}
    if not psutil.pid_exists(params.pid):
        return {"error": f"Process with PID {params.pid} does not exist."}
    try:
        os.kill(params.pid, sig)
    except Exception as e:
        return {"error": f"Failed to send a signal {sig.name} to process {params.pid}: {e}"}
    else:
        try:
            current = psutil.Process(params.pid).as_dict()
        except psutil.NoSuchProcess:
            current = {"status": "No such process"}
        return {"pid": params.pid, "sig_str": sig.name, "message": "Signal sent to the process", "process_status": current}


if __name__ == "__main__":
    mcp = FastApiMCP(
        app,
        name=f"IPC Analysis MCP Server for {socket.gethostname()} machine",
        description=f"An MCP server for {socket.gethostname()} machine with tools to gather system data, analyze inter process communication and signal processes.",
        include_operations=[
            "get_process_connection_snapshot",
            "get_live_network_events",
            "generate_ipc_analysis_prompt",
            "send_signal_to_pid",
        ],
    )
    mcp.mount_http()

    import uvicorn
    print("Starting RHEL IPC Analysis MCP Server...")
    print("Access the OpenAPI docs at http://127.0.0.1:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
