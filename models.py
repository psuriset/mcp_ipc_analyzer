from pydantic import BaseModel, Field


class MonitorParams(BaseModel):
    duration_seconds: int = Field(
        default=10,
        title="Monitoring Duration",
        description="The number of seconds to run the network monitoring agent.",
    )

class SignalParams(BaseModel):
    pid: int = Field(
        title="PID of a process",
        description="Numeric PID of a process we want to send signal to.",
    )
    pid: str = Field(
        title="Signal name",
        description="Name of the signal from Python's 'signal' module. Use signal 'SIGINT' to send 'interrupt from keyboard (CTRL + C)' or if it does not make the process to stop, send 'SIGKILL' to 'Kill signal - it cannot be caught, blocked, or ignored'.",
    )
