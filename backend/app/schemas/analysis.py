from typing import Any, Literal
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)


class RotDecodeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    shift: int = Field(ge=0, le=25)


class PortScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    # Numbers and ranges, e.g. [80, "443", "1000-1010", "1:1024"].
    # Expansion and validation happen in app.modules.web.parse_ports.
    ports: list[int | str] = Field(default_factory=lambda: [22, 80, 443])


class AesEncryptRequest(BaseModel):
    plaintext: str = Field(min_length=1, max_length=4096)
    key: str = Field(min_length=1, max_length=128)


class AesDecryptRequest(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=16384)
    key: str = Field(min_length=1, max_length=128)
    nonce: str = Field(min_length=1, max_length=64)


class RsaSignRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    private_key: str = Field(min_length=1, max_length=8192)


class RsaVerifyRequest(BaseModel):
    value: str = Field(min_length=1, max_length=4096)
    public_key: str = Field(min_length=1, max_length=4096)
    signature: str = Field(min_length=1, max_length=4096)


class Finding(BaseModel):
    title: str
    severity: Literal[
        "info", "low", "medium", "high", "critical", "unknown"
    ]
    evidence: str
    description: str | None = None
    category: str | None = None
    confidence: str | None = None
    reason: str | None = None
    source_ip: str | None = None
    failed_attempts: int | None = None
    time_window: str | None = None
    targeted_usernames: list[str] | None = None
    distinct_destination_ports: list[int] | None = None
    observed_count: int | None = None
    data_source: str | None = None


class AnalysisResponse(BaseModel):
    success: bool
    module: str
    summary: str
    risk_level: str = "unknown"
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)