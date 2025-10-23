from pydantic import BaseModel, Field

class MonitorParams(BaseModel):
    duration_seconds: int = Field(
        default=10,
        title="Monitoring Duration",
        description="The number of seconds to run the network monitoring agent.",
    )
