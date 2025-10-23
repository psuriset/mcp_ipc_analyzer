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
import sys
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import StreamingResponse
from fastapi_mcp import FastApiMCP

from models import MonitorParams
from ebpf_agent.protocols import get_protocol

AGENT_SCRIPT_PATH = "./ebpf_agent/agent.py"

app = FastAPI(debug=True)
mcp = FastApiMCP(
    app,
    name="RHEL IPC Analysis MCP Server (Model Agnostic)",
    description="An MCP server with tools to gather system data and analyze process IPC.",
    include_operations=["get_process_connection_snapshot", "get_live_network_events", "generate_ipc_analysis_prompt"],
)
mcp.mount_http()

@app.get("/health", summary="Health Check")
async def health_check():
    return {"status": "ok"}

# --- Tool Implementation ---
@app.get("/get_process_connection_snapshot", operation_id="get_process_connection_snapshot", summary="Provides a comprehensive snapshot of all running processes and their currently active/listening network connections (TCP/UDP), including identified application protocols.")
def get_process_connection_snapshot():
    proc_list = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        try:
            connections = []
            for conn in proc.connections(kind='inet'):
                # Identify the application protocol based on the port
                app_protocol = "Unknown"
                if conn.status == 'LISTEN':
                    app_protocol = get_protocol(conn.laddr.port)
                elif conn.raddr:
                    app_protocol = get_protocol(conn.raddr.port)

                connections.append({
                    "transport_protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "identified_application_protocol": app_protocol,
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "status": conn.status,
                })

            if connections:
                proc_list.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "user": proc.info['username'],
                    "command": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    "connections": connections
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return {"process_connections": proc_list}

async def _collect_agent_output(duration: int) -> list:
    command = ["sudo", "python3", "-u", AGENT_SCRIPT_PATH]
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    async def reader_task():
        while True:
            line = await process.stdout.readline()
            if not line: break
            yield json.loads(line.decode('utf-8').strip()))
    try:
        await asyncio.wait_for(reader_task(), timeout=duration)
    except asyncio.TimeoutError:
        pass
    finally:
        if process.returncode is None:
            process.terminate()
            await process.wait()

async def _get_live_network_events(duration: MonitorParams):
    yield json.dumps({"type": "status", "message": f"Network agent starting for {duration.duration_seconds} seconds."})
    collected_events = await _collect_agent_output(duration.duration_seconds)
    for event in collected_events:
        yield json.dumps(event)
    yield json.dumps({"type": "status", "message": "Monitoring finished."})

@app.post("/get_live_network_events", operation_id="get_live_network_events", summary="Runs a high-performance eBPF agent to capture only *new* network connections in real-time. Useful for monitoring changes.")
async def get_live_network_events(duration: MonitorParams):
    return StreamingResponse(
      _get_live_network_events(duration),
      media_type="text/event-stream"
    )

@app.get("/generate_ipc_analysis_prompt", operation_id="generate_ipc_analysis_prompt", summary="Gathers data using the other tools and constructs a detailed prompt for an LLM to perform a system IPC analysis.")
async def generate_ipc_analysis_prompt():
    process_connections = get_connection_snapshot()
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
            "processes_with_connections": len(process_connections.get("process_connections", []))
        }
    }

if __name__ == "__main__":
    import uvicorn
    print("Starting RHEL IPC Analysis MCP Server...")
    print("Access the OpenAPI docs at http://127.0.0.1:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)