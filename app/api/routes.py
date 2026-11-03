import httpx
import ssl
import subprocess
from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.modules.web.dns import dns_records
from app.modules.web.headers import inspect_headers
from app.modules.web.scanners import (
    run_nmap_profile,
    run_rustscan_profile,
    scanner_capabilities,
)
from app.modules.web.tcp import bounded_tcp_scan
from app.modules.web.tls import inspect_tls
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
from app.modules.cryptography.hash_tools import identify_hash, sha256_text
from app.modules.cryptography.lab import (
    decode_base64,
    decode_brainfuck,
    decode_morse,
    decrypt_aes_gcm,
    encode_base64,
    encrypt_aes_gcm,
    generate_rsa_key_pair,
    hashes_for_text,
    identify,
    rot,
    secure_token,
    sign_rsa,
    verify_rsa,
)
from app.modules.forensics.analyzer import MAX_FILE_SIZE, analyze_bytes
from app.modules.osint.analyzer import analyze_target as analyze_osint_target
from app.modules.log_analysis.analyzer import MAX_LOG_SIZE, analyze_bytes as analyze_log_bytes
from app.modules.malware_triage.analyzer import analyze_bytes as analyze_malware_bytes
from app.core.risk import risk_level_for_findings

router = APIRouter(prefix="/api", tags=["Analysis"])
SESSION_RESULTS: dict[str, list[dict]] = {}
MAX_SESSION_RESULTS = 100
MAX_SESSIONS = 1000


def _remember(request: Request, result: AnalysisResponse) -> AnalysisResponse:
    session_id = getattr(request.state, "session_id", "anonymous")
    if session_id not in SESSION_RESULTS and len(SESSION_RESULTS) >= MAX_SESSIONS:
        oldest_key = next(iter(SESSION_RESULTS))
        SESSION_RESULTS.pop(oldest_key, None)
    results = SESSION_RESULTS.setdefault(session_id, [])
    results.append(result.model_dump())
    del results[:-MAX_SESSION_RESULTS]
    return result


@router.post("/analyze/{module}", response_model=AnalysisResponse)
def analyze(module: str, _request: AnalysisRequest):
    supported_modules = {
        "web-network",
        "forensics",
        "osint",
        "cryptography",
        "log-analysis",
        "malware",
    }

    if module not in supported_modules:
        raise HTTPException(status_code=404, detail="Unknown module")

    raise HTTPException(
        status_code=501,
        detail=(
            f"The generic analysis route does not execute {module} workflows. "
            "Use the module-specific endpoint documented in Swagger."
        ),
    )


@router.post("/osint/analyze", response_model=AnalysisResponse)
def osint_analysis(request: AnalysisRequest, http_request: Request):
    try:
        details, raw_findings = analyze_osint_target(request.target)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _remember(http_request, AnalysisResponse(
        success=True,
        module="osint",
        summary="Passive OSINT analysis completed",
        risk_level=risk_level_for_findings(raw_findings),
        findings=raw_findings,
        details=details,
    ))


@router.post("/log-analysis/analyze", response_model=AnalysisResponse)
async def log_analysis(http_request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_LOG_SIZE + 1)
    try:
        details, findings = analyze_log_bytes(data, file.filename or "uploaded-log")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _remember(http_request, AnalysisResponse(
        success=True,
        module="log-analysis",
        summary="Log analysis completed",
        risk_level=risk_level_for_findings(findings),
        findings=findings,
        details=details,
    ))


@router.post("/malware/triage", response_model=AnalysisResponse)
async def malware_triage(http_request: Request, file: UploadFile = File(...)):
    data = await file.read(MAX_FILE_SIZE + 1)
    try:
        details, findings = analyze_malware_bytes(data, file.filename or "uploaded-file", file.content_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _remember(http_request, AnalysisResponse(
        success=True,
        module="malware",
        summary="Static malware triage completed",
        risk_level=risk_level_for_findings(findings),
        findings=findings,
        details=details,
    ))


@router.get("/session/history")
def session_history(request: Request):
    results = SESSION_RESULTS.get(getattr(request.state, "session_id", "anonymous"), [])
    return {"success": True, "module": "session", "results": list(reversed(results))}


@router.delete("/session/history")
def clear_session_history(request: Request):
    SESSION_RESULTS.pop(getattr(request.state, "session_id", "anonymous"), None)
    return {"success": True, "module": "session", "summary": "Session history cleared"}


@router.get("/reports/{result_index}")
def get_report(result_index: int, request: Request):
    results = list(reversed(SESSION_RESULTS.get(getattr(request.state, "session_id", "anonymous"), [])))
    if result_index < 0 or result_index >= len(results):
        raise HTTPException(status_code=404, detail="Session result not found")
    return results[result_index]

@router.post("/analyze/cryptography/hash", response_model=AnalysisResponse)
def hash_text(request: AnalysisRequest):
    result = sha256_text(request.target)

    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="SHA-256 hash generated",
        risk_level="unknown",
        findings=[],
        errors=[],
        details=result,
    )


@router.post("/cryptography/hashes", response_model=AnalysisResponse)
def hash_suite(request: AnalysisRequest):
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="Hash suite completed",
        details=hashes_for_text(request.target),
    )


@router.post("/cryptography/base64/encode", response_model=AnalysisResponse)
def base64_encode(request: AnalysisRequest):
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="Base64 encoding completed",
        details=encode_base64(request.target),
    )


@router.post("/cryptography/base64/decode", response_model=AnalysisResponse)
def base64_decode(request: AnalysisRequest):
    try:
        details = decode_base64(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="Base64 decoding completed", details=details)


@router.post("/cryptography/hash-identify", response_model=AnalysisResponse)
def hash_identification(request: AnalysisRequest):
    details = identify_hash(request.target)
    count = details.get("match_count", 0)
    summary = (
        f"Identified {count} candidate hash algorithm(s)"
        if count
        else "No recognized hash algorithm matched the input"
    )
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary=summary,
        details=details,
    )


@router.post("/cryptography/cipher-identify", response_model=AnalysisResponse)
def cipher_identification(request: AnalysisRequest):
    details = identify(request.target)
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="Encoding and cipher identification completed",
        details=details,
    )


@router.post("/cryptography/rot/decode", response_model=AnalysisResponse)
def rot_decode(request: RotDecodeRequest):
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary=f"ROT{request.shift} decoding completed",
        details={
            "cipher": f"ROT{request.shift}",
            "shift": request.shift,
            "value": rot(request.target, -request.shift),
        },
    )


@router.post("/cryptography/morse/decode", response_model=AnalysisResponse)
def morse_decode(request: AnalysisRequest):
    try:
        details = {"encoding": "morse", "value": decode_morse(request.target)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="Morse decoding completed", details=details)


@router.post("/cryptography/brainfuck/decode", response_model=AnalysisResponse)
def brainfuck_decode(request: AnalysisRequest):
    try:
        details = {"language": "Brainfuck", "value": decode_brainfuck(request.target)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="Brainfuck interpretation completed", details=details)


@router.post("/cryptography/aes-gcm/encrypt", response_model=AnalysisResponse)
def aes_encrypt(request: AesEncryptRequest):
    try:
        details = encrypt_aes_gcm(request.plaintext, request.key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="AES-GCM encryption completed", details=details)


@router.post("/cryptography/aes-gcm/decrypt", response_model=AnalysisResponse)
def aes_decrypt(request: AesDecryptRequest):
    try:
        details = decrypt_aes_gcm(request.ciphertext, request.key, request.nonce)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="AES-GCM decryption completed", details=details)


@router.post("/cryptography/rsa/key-pair", response_model=AnalysisResponse)
def rsa_key_pair():
    return AnalysisResponse(
        success=True,
        module="cryptography",
        summary="RSA key pair generated",
        details=generate_rsa_key_pair(),
    )


@router.post("/cryptography/rsa/sign", response_model=AnalysisResponse)
def rsa_sign(request: RsaSignRequest):
    try:
        details = sign_rsa(request.value, request.private_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="RSA signature created", details=details)


@router.post("/cryptography/rsa/verify", response_model=AnalysisResponse)
def rsa_verify(request: RsaVerifyRequest):
    try:
        details = verify_rsa(request.value, request.public_key, request.signature)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="RSA signature verified", details=details)


@router.post("/cryptography/token", response_model=AnalysisResponse)
def token_generation(request: AnalysisRequest):
    try:
        details = secure_token(int(request.target))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AnalysisResponse(success=True, module="cryptography", summary="Secure token generated", details=details)


@router.post("/forensics/analyze", response_model=AnalysisResponse)
async def forensic_analysis(http_request: Request, file: UploadFile = File(...)):
    filename = file.filename or "uploaded-file"
    data = await file.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MB limit")
    try:
        details, findings = analyze_bytes(data, filename, file.content_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    risk_level = risk_level_for_findings(findings)
    return _remember(http_request, AnalysisResponse(
        success=True,
        module="forensics",
        summary="Static forensic analysis completed",
        risk_level=risk_level,
        findings=findings,
        details=details,
    ))


@router.post("/web-network/dns", response_model=AnalysisResponse)
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


@router.post("/web-network/headers", response_model=AnalysisResponse)
def header_analysis(request: AnalysisRequest):
    try:
        details, findings = inspect_headers(request.target)
    except (ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    risk_level = risk_level_for_findings(findings)
    return AnalysisResponse(
        success=True,
        module="web-network",
        summary="HTTP security headers inspected",
        risk_level=risk_level,
        findings=findings,
        details=details,
    )


@router.post("/web-network/tls", response_model=AnalysisResponse)
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


@router.post("/web-network/tcp", response_model=AnalysisResponse)
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


@router.get("/web-network/scanners")
def scanner_status():
    return {"success": True, "module": "web-network", "tools": scanner_capabilities()}


@router.post("/web-network/nmap", response_model=AnalysisResponse)
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


@router.post("/web-network/rustscan", response_model=AnalysisResponse)
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