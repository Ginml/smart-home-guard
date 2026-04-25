from datetime import datetime

from pydantic import BaseModel, Field

from backend.models.enums import ClassLabel


class TopSourceIp(BaseModel):
    ip: str
    count: int


class FlowResult(BaseModel):
    id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol_name: str
    flow_duration: float
    rate: float
    fin_flag_number: int
    syn_flag_number: int
    rst_flag_number: int
    psh_flag_number: int
    ack_flag_number: int
    urg_flag_number: int
    ece_flag_number: int
    cwr_flag_number: int
    predicted_category: ClassLabel
    confidence: float
    features: dict


class AnalysisSummary(BaseModel):
    total_flows: int
    benign_count: int
    spoofing_count: int
    recon_count: int
    brute_force_count: int
    protocol_counts: dict[str, int]
    top_source_ips: list[TopSourceIp]


class AnalyzeResponse(BaseModel):
    session_id: str
    flows: list[FlowResult]
    summary: AnalysisSummary
    processing_time_ms: float


class ScanStartRequest(BaseModel):
    interface: str = Field(..., min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    user_id: str


class ScanStartResponse(BaseModel):
    session_id: str
    status: str


class ScanStopRequest(BaseModel):
    session_id: str


class ScanStopResponse(BaseModel):
    session_id: str
    total_flows: int
    threat_count: int
    ended_at: datetime | None = None
    error: str | None = None


class ScanStatusResponse(BaseModel):
    running: bool
    session_id: str | None = None
    interface: str | None = None
    flows_captured: int = 0
    threats: int = 0
    last_update: datetime | None = None
    error: str | None = None
