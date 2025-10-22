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
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel, Field

# --- Configuration ---
# Add the ebpf_agent subdirectory to the path to allow importing protocols
sys.path.insert(0, './ebpf_agent')
from protocols import get_protocol

AGENT_SCRIPT_PATH = "./ebpf_agent/agent.py"

# --- MCP Server Setup ---
app = FastAPI(
    title="RHEL IPC Analysis MCP Server (Model Agnostic)",
    description="An MCP server with tools to gather system data and analyze process IPC.",
    version="2.3.2", # Incremented version for the protocol fix
)

# --- Pydantic Models for Tool Parameters ---
class MonitorParams(BaseModel):
    duration_seconds: int = Field(
        default=10,
        title="Monitoring Duration",
        description="The number of seconds to run the network monitoring agent.",
    )

class AnalystParams(BaseModel):
    monitoring_duration_seconds: int = Field(
        default=10,
        title="Analysis Monitoring Duration",
        description="The number of seconds to monitor network events for the analysis prompt.",
    )

# --- Tool Definitions ---
TOOLS = {
    "get_process_connection_snapshot": {
        "description": "Provides a comprehensive snapshot of all running processes and their currently active/listening network connections (TCP/UDP), including identified application protocols.",
        "parameters": {},
    },
    "get_live_network_events": {
        "description": "Runs a high-performance eBPF agent to capture only *new* network connections in real-time. Useful for monitoring changes.",
        "parameters": MonitorParams.model_json_schema(),
    },
    "generate_ipc_analysis_prompt": {
        "description": "Gathers data using the other tools and constructs a detailed prompt for an LLM to perform a system IPC analysis.",
        "parameters": AnalystParams.model_json_schema(),
    },
}

# --- MCP Endpoints ---
@app.get("/", summary="Health Check", include_in_schema=False)
async def health_check():
    return {"status": "ok"}

@app.get("/mcp/list_tools", summary="List Available Tools")
async def list_tools():
    tool_list = [{"name": name, **details} for name, details in TOOLS.items()]
    return {"tools": tool_list}

@app.post("/mcp/call_tool", summary="Call a Tool")
async def call_tool(request: Request):
    try:
        body = await request.json()
        tool_name = body.get("tool_name")
        params = body.get("parameters", {})

        if tool_name not in TOOLS:
            raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found.")

        if tool_name == "get_process_connection_snapshot":
            result = get_connection_snapshot()
            return Response(content=json.dumps(result, indent=2), media_type="application/json")

        elif tool_name == "get_live_network_events":
            p = MonitorParams(**params)
            return EventSourceResponse(stream_agent_output(p.duration_seconds), media_type="text/event-stream")

        elif tool_name == "generate_ipc_analysis_prompt":
            p = AnalystParams(**params)
            result = await run_prompt_generation()
            return Response(content=json.dumps(result, indent=2), media_type="application/json")

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error calling tool: {str(e)}")

# --- Tool Implementation ---
def get_connection_snapshot():
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
    output_list = []
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    async def reader_task():
        while True:
            line = await process.stdout.readline()
            if not line: break
            output_list.append(json.loads(line.decode('utf-8').strip()))
    try:
        await asyncio.wait_for(reader_task(), timeout=duration)
    except asyncio.TimeoutError:
        pass
    finally:
        if process.returncode is None:
            process.terminate()
            await process.wait()
    return output_list

async def stream_agent_output(duration: int):
    yield json.dumps({"type": "status", "message": f"Network agent starting for {duration} seconds."})
    collected_events = await _collect_agent_output(duration)
    for event in collected_events:
        yield json.dumps(event)
    yield json.dumps({"type": "status", "message": "Monitoring finished."})

async def run_prompt_generation():
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