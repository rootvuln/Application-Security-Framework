"""API routes.

Single-file router for the whole HTTP surface. Every path is served under the
``/api`` prefix; the per-capability routers exist only so Swagger UI stays
grouped by module.
"""

from __future__ import annotations

import ssl
import subprocess

import httpx
from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.core.config import MAX_FILE_SIZE, MAX_LOG_SIZE
from app.core.risk import risk_level_for_findings
from app.modules.cryptography import (
    decode_base64,
    decode_brainfuck,
    decode_morse,
    decrypt_aes_gcm,
    encode_base64,
    encode_brainfuck,
    encode_morse,
    encrypt_aes_gcm,
    generate_rsa_key_pair,
    hashes_for_text,
    identify,
    identify_hash,
    rot,
    secure_token,
    sha256_text,
    sign_rsa,
    verify_rsa,
)
from app.modules.forensics import analyze_bytes as analyze_forensic_bytes
from app.modules.log_analysis import analyze_bytes as analyze_log_bytes
from app.modules.malware_triage import analyze_bytes as analyze_malware_bytes
from app.modules.osint import analyze_target
from app.modules.web import (
    bounded_tcp_scan,
    dns_records,
    inspect_headers,
    inspect_tls,
    run_nmap_profile,
    run_rustscan_profile,
    scanner_capabilities,
)
from app.schemas.analysis import (
    AesDecryptRequest,
    AesEncryptRequest,
    AnalysisRequest,
    AnalysisResponse,
    PortScanRequest,
    RotDecodeRequest,
    RsaSignRequest,
    RsaVerifyRequest,
)
from app.services import session_store


# ── Shared helpers ────────────────────────────────────────────────────────────


def session_id_for(request: Request) -> str:
    return getattr(request.state, "session_id", "anonymous")


def remember(request: Request, result: AnalysisResponse) -> AnalysisResponse:
    """Store the response in session history and return it unchanged."""
    session_store.remember(session_id_for(request), result.model_dump())
    return result


# ── Session ───────────────────────────────────────────────────────────────────

session_router = APIRouter(tags=["Session"])

SUPPORTED_MODULES = frozenset(
    {"web-network", "forensics", "osint", "cryptography", "log-analysis", "malware"}
)


@session_router.post("/analyze/{module}")
def analyze(module: str, _request: AnalysisRequest):
    """Kept for compatibility; module-specific endpoints do the real work."""
    if module not in SUPPORTED_MODULES:
        raise HTTPException(status_code=404, detail="Unknown module")
    raise HTTPException(
        status_code=501,
        detail=(
            f"The generic analysis route does not execute {module} workflows. "
            "Use the module-specific endpoint documented in Swagger."
        ),
    )


@session_router.get("/session/history")
def session_history(request: Request):
    return {
        "success": True,
        "module": "session",
        "results": session_store.history(session_id_for(request)),
    }


@session_router.delete("/session/history")
def clear_session_history(request: Request):
    session_store.clear(session_id_for(request))
    return {
        "success": True,
        "module": "session",
        "summary": "Session history cleared",
    }


@session_router.get("/reports/{result_index}")
def get_report(result_index: int, request: Request):
    result = session_store.latest(session_id_for(request), result_index)
    if result is None:
        raise HTTPException(status_code=404, detail="Session result not found")
    return result

# ── Osint ─────────────────────────────────────────────────────────────────────

osint_router = APIRouter(tags=["OSINT"])


@osint_router.post("/osint/analyze", response_model=AnalysisResponse)
def osint_analysis(request: AnalysisRequest, http_request: Request):
    try:
        details, findings = analyze_target(request.target)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return remember(
        http_request,
        AnalysisResponse(
            success=True,
            module="osint",
            summary="Passive OSINT analysis completed",
            risk_level=risk_level_for_findings(findings),
            findings=findings,
            details=details,
        ),
    )

# ── Web Network ───────────────────────────────────────────────────────────────

web_network_router = APIRouter(tags=["Web & Network"])


@web_network_router.post("/web-network/dns", response_model=AnalysisResponse)
def dns_analysis(request: AnalysisRequest):
    try:
        details = dns_records(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(
        success=True,
        module="web-network",
        summary="DNS records retrieved",
        details=details,
    )


@web_network_router.post("/web-network/headers", response_model=AnalysisResponse)
def header_analysis(request: AnalysisRequest):
    try:
        details, findings = inspect_headers(request.target)
    except (ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(
        success=True,
        module="web-network",
        summary="HTTP security headers inspected",
        risk_level=risk_level_for_findings(findings),
        findings=findings,
        details=details,
    )


@web_network_router.post("/web-network/tls", response_model=AnalysisResponse)
def tls_analysis(request: AnalysisRequest):
    try:
        details = inspect_tls(request.target)
    except (ValueError, OSError, ssl.SSLError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(
        success=True,
        module="web-network",
        summary="TLS certificate inspected",
        details=details,
    )


@web_network_router.post("/web-network/tcp", response_model=AnalysisResponse)
def tcp_analysis(request: PortScanRequest):
    try:
        details = bounded_tcp_scan(request.target, request.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(
        success=True,
        module="web-network",
        summary="Bounded TCP connectivity check completed",
        details=details,
    )


@web_network_router.get("/web-network/scanners")
def scanner_status():
    return {
        "success": True,
        "module": "web-network",
        "tools": scanner_capabilities(),
    }


@web_network_router.post("/web-network/nmap", response_model=AnalysisResponse)
def nmap_analysis(request: PortScanRequest):
    try:
        details = run_nmap_profile(request.target, request.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Nmap scan timed out") from exc
    return AnalysisResponse(
        success=details["return_code"] == 0,
        module="web-network",
        summary="Nmap scan completed",
        errors=[] if details["return_code"] == 0 else ["Nmap returned a non-zero exit code"],
        details=details,
    )


@web_network_router.post("/web-network/rustscan", response_model=AnalysisResponse)
def rustscan_analysis(request: PortScanRequest):
    try:
        details = run_rustscan_profile(request.target, request.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="RustScan timed out") from exc
    return AnalysisResponse(
        success=details["return_code"] == 0,
        module="web-network",
        summary="RustScan completed",
        errors=[] if details["return_code"] == 0 else ["RustScan returned a non-zero exit code"],
        details=details,
    )

# ── Cryptography ──────────────────────────────────────────────────────────────

cryptography_router = APIRouter(tags=["Cryptography"])


def _ok(summary: str, details: dict) -> AnalysisResponse:
    return AnalysisResponse(
        success=True, module="cryptography", summary=summary, details=details
    )


@cryptography_router.post("/analyze/cryptography/hash", response_model=AnalysisResponse)
def hash_text(request: AnalysisRequest):
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="SHA-256 hash generated",
        risk_level="unknown",
        findings=[],
        errors=[],
        details=sha256_text(request.target),
    )


@cryptography_router.post("/cryptography/hashes", response_model=AnalysisResponse)
def hash_suite(request: AnalysisRequest):
    return _ok("Hash suite completed", hashes_for_text(request.target))


@cryptography_router.post("/cryptography/base64/encode", response_model=AnalysisResponse)
def base64_encode(request: AnalysisRequest):
    return _ok("Base64 encoding completed", encode_base64(request.target))


@cryptography_router.post("/cryptography/base64/decode", response_model=AnalysisResponse)
def base64_decode(request: AnalysisRequest):
    try:
        details = decode_base64(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Base64 decoding completed", details)


@cryptography_router.post("/cryptography/hash-identify", response_model=AnalysisResponse)
def hash_identification(request: AnalysisRequest):
    details = identify_hash(request.target)
    count = details.get("match_count", 0)
    summary = (
        f"Identified {count} candidate hash algorithm(s)"
        if count
        else "No recognized hash algorithm matched the input"
    )
    return _ok(summary, details)


@cryptography_router.post("/cryptography/cipher-identify", response_model=AnalysisResponse)
def cipher_identification(request: AnalysisRequest):
    return _ok("Encoding and cipher identification completed", identify(request.target))


@cryptography_router.post("/cryptography/rot/decode", response_model=AnalysisResponse)
def rot_decode(request: RotDecodeRequest):
    return _ok(
        f"ROT{request.shift} decoding completed",
        {
            "cipher": f"ROT{request.shift}",
            "shift": request.shift,
            "value": rot(request.target, -request.shift),
        },
    )


@cryptography_router.post("/cryptography/morse/decode", response_model=AnalysisResponse)
def morse_decode(request: AnalysisRequest):
    try:
        details = {"encoding": "morse", "value": decode_morse(request.target)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Morse decoding completed", details)


@cryptography_router.post("/cryptography/morse/encode", response_model=AnalysisResponse)
def morse_encode(request: AnalysisRequest):
    try:
        details = encode_morse(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Morse encoding completed", details)


@cryptography_router.post("/cryptography/brainfuck/encode", response_model=AnalysisResponse)
def brainfuck_encode(request: AnalysisRequest):
    try:
        details = encode_brainfuck(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Brainfuck program generated", details)


@cryptography_router.post("/cryptography/brainfuck/decode", response_model=AnalysisResponse)
def brainfuck_decode(request: AnalysisRequest):
    try:
        details = {"language": "Brainfuck", "value": decode_brainfuck(request.target)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Brainfuck interpretation completed", details)


@cryptography_router.post("/cryptography/aes-gcm/encrypt", response_model=AnalysisResponse)
def aes_encrypt(request: AesEncryptRequest):
    try:
        details = encrypt_aes_gcm(request.plaintext, request.key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("AES-GCM encryption completed", details)


@cryptography_router.post("/cryptography/aes-gcm/decrypt", response_model=AnalysisResponse)
def aes_decrypt(request: AesDecryptRequest):
    try:
        details = decrypt_aes_gcm(request.ciphertext, request.key, request.nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("AES-GCM decryption completed", details)


@cryptography_router.post("/cryptography/rsa/key-pair", response_model=AnalysisResponse)
def rsa_key_pair():
    return _ok("RSA key pair generated", generate_rsa_key_pair())


@cryptography_router.post("/cryptography/rsa/sign", response_model=AnalysisResponse)
def rsa_sign(request: RsaSignRequest):
    try:
        details = sign_rsa(request.value, request.private_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("RSA signature created", details)


@cryptography_router.post("/cryptography/rsa/verify", response_model=AnalysisResponse)
def rsa_verify(request: RsaVerifyRequest):
    try:
        details = verify_rsa(request.value, request.public_key, request.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("RSA signature verified", details)


@cryptography_router.post("/cryptography/token", response_model=AnalysisResponse)
def token_generation(request: AnalysisRequest):
    try:
        details = secure_token(int(request.target))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _ok("Secure token generated", details)

# ── Uploads ───────────────────────────────────────────────────────────────────

uploads_router = APIRouter(tags=["Uploads"])


@uploads_router.post("/forensics/analyze", response_model=AnalysisResponse)
async def forensic_analysis(http_request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB limit")
    try:
        details, findings = analyze_forensic_bytes(
            data, file.filename or "uploaded-file", file.content_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return remember(
        http_request,
        AnalysisResponse(
            success=True,
            module="forensics",
            summary="Static forensic analysis completed",
            risk_level=risk_level_for_findings(findings),
            findings=findings,
            details=details,
        ),
    )


@uploads_router.post("/log-analysis/analyze", response_model=AnalysisResponse)
async def log_analysis(http_request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_LOG_SIZE + 1)
    try:
        details, findings = analyze_log_bytes(data, file.filename or "uploaded-log")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    summary = "Log analysis completed"
    if details.get("packet_count") is not None:
        count = details["packet_count"]
        summary = (
            f"Decoded {count} packet{'' if count == 1 else 's'} from a "
            f"{details.get('format', 'packet')} capture"
        )
        if findings:
            summary += f" — {len(findings)} finding{'' if len(findings) == 1 else 's'}"
    return remember(
        http_request,
        AnalysisResponse(
            success=True,
            module="log-analysis",
            summary=summary,
            risk_level=risk_level_for_findings(findings),
            findings=findings,
            details=details,
        ),
    )


@uploads_router.post("/malware/triage", response_model=AnalysisResponse)
async def malware_triage(http_request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_FILE_SIZE + 1)
    try:
        details, findings = analyze_malware_bytes(
            data, file.filename or "uploaded-file", file.content_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return remember(
        http_request,
        AnalysisResponse(
            success=True,
            module="malware",
            summary="Static malware triage completed",
            risk_level=risk_level_for_findings(findings),
            findings=findings,
            details=details,
        ),
    )

# ── Aggregate router ────────────────────────────────────────────────────────

router = APIRouter(prefix="/api")
router.include_router(session_router)
router.include_router(osint_router)
router.include_router(web_network_router)
router.include_router(cryptography_router)
router.include_router(uploads_router)

__all__ = ["router"]
