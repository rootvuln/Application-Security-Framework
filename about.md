# CyberSuite

CyberSuite is a defensive cybersecurity analysis API built with Python,
FastAPI, and Pydantic. It exposes independent analysis modules through
consistent JSON responses so a frontend can render each module without knowing
the internal implementation.

The platform performs bounded, evidence-based analysis for authorized use. It
does not execute uploaded files, perform credential attacks, or run
unrestricted network scans.

## Frontend Integration Standard

### Base URL

```text
http://127.0.0.1:8000
```

FastAPI documentation:

- Swagger UI: `GET /docs`
- OpenAPI schema: `GET /openapi.json`
- Health check: `GET /api/health`

### Shared analysis response

All analysis endpoints using `AnalysisResponse` return this shape:

```json
{
  "success": true,
  "module": "osint",
  "summary": "Passive OSINT analysis completed",
  "risk_level": "unknown",
  "findings": [],
  "errors": [],
  "details": {}
}
```

Frontend rules:

| Field | Type | Usage |
| --- | --- | --- |
| `success` | boolean | Show completed or failed request state |
| `module` | string | Select the module result renderer |
| `summary` | string | Display the result heading |
| `risk_level` | string | Display the overall risk badge |
| `findings` | array | Render security findings |
| `errors` | array | Render non-fatal or request errors |
| `details` | object | Render module-specific cards and tables |

### Finding object

Findings use a consistent structure:

```json
{
  "title": "Finding title",
  "severity": "info",
  "evidence": "Observed evidence",
  "description": "Human-readable explanation",
  "category": "category",
  "confidence": "medium",
  "data_source": "source"
}
```

Supported severity values are `info`, `low`, `medium`, `high`, `critical`,
and `unknown`. A frontend should not treat an unavailable provider or missing
metadata as malicious evidence.

## Module Directory

```text
app/
├── main.py
├── api/routes.py
├── core/risk.py
├── schemas/analysis.py
└── modules/
    ├── cryptography/
    ├── forensics/
    ├── log_analysis/
    ├── malware_triage/
    ├── osint/
    └── web/
```

`app/main.py` creates the FastAPI application and provides CORS, rate
limiting, session cookies, audit logging, and health checks.

`app/api/routes.py` validates requests, dispatches module workflows, converts
results into the shared response model, and stores recent results in the
current session.

`app/schemas/analysis.py` defines shared Pydantic request, finding, and
response models.

## 1. OSINT Module

### Purpose

Passive intelligence collection for public domains and IP addresses, with
optional inspection of one explicitly supplied TCP port.

### Endpoint

```http
POST /api/osint/analyze
Content-Type: application/json
```

Request:

```json
{
  "target": "example.com:443"
}
```

Accepted target formats:

- `8.8.8.8`
- `72.60.204.211:8057`
- `example.com`
- `example.com:8057`
- `2001:4860:4860::8888`
- `[2001:4860:4860::8888]:443`

The parser returns the original input, host, target type, and optional port.
Ports must be from 1 through 65535.

### Details contract

```json
{
  "target": "example.com",
  "original_input": "example.com:443",
  "target_host": "example.com",
  "target_type": "domain",
  "port": 443,
  "target_port": 443,
  "addresses": [],
  "reverse_dns": null,
  "records": {},
  "domain_intelligence": {},
  "registration": {},
  "ip_intelligence": {},
  "port_intelligence": {},
  "tls": {},
  "website": {},
  "reputation": {},
  "risk_assessment": {},
  "coverage": {},
  "data_sources": [],
  "limitations": []
}
```

### Frontend cards

| Card | Fields to render |
| --- | --- |
| Target overview | `target`, `target_type`, `port`, `original_input` |
| Resolved addresses | `addresses`, `reverse_dns` |
| DNS records | `records.A`, `records.AAAA`, `records.MX`, `records.NS`, `records.TXT`, `records.CNAME` |
| Email security | `domain_intelligence.spf`, `domain_intelligence.dmarc` |
| Registration | `registration.registrar`, dates, `domain_status`, `nameservers`, `redacted` |
| IP intelligence | `ip_intelligence.classification`, `asn`, `isp`, `organization`, `country` |
| Port service | `port_intelligence.status`, `port`, `service`, `protocol`, `banner`, confidence |
| Website | `website.status`, `status_code`, `title`, `meta_description`, headers, URLs |
| TLS | `tls.status`, subject, issuer, validity, expiration, protocol, cipher |
| Reputation | `reputation.status`, provider, lookup time, evidence |
| Coverage | Each check status and explanation |

### OSINT behavior

- DNS records include A, AAAA, MX, NS, TXT, and CNAME.
- SPF and DMARC are checked and basic record format is validated.
- RDAP provides registration, nameserver, status, registrar, and IP allocation
  information when available.
- ASN and organization data are returned only when obtained from RDAP or a
  configured provider.
- Only the user-supplied port is checked; no port ranges are scanned.
- HTTP metadata is bounded by strict timeouts and response-size limits.
- Redirect destinations are validated before they are followed.
- TLS uses certificate verification and never silently disables validation.
- Reputation is optional and reports `not_configured` without credentials.

Coverage statuses are standardized as:

```text
completed | unavailable | not_applicable | not_configured | failed
```

Optional reputation configuration:

```text
CYBERSUITE_REPUTATION_URL
CYBERSUITE_REPUTATION_API_KEY
```

## 2. Web and Network Module

### Purpose

Reusable active-but-bounded network utilities for DNS, HTTP headers, TLS,
single-port TCP checks, and explicitly requested scanner profiles.

### Endpoints

| Method | Endpoint | Frontend use |
| --- | --- | --- |
| POST | `/api/web-network/dns` | DNS record card |
| POST | `/api/web-network/headers` | HTTP security-header card |
| POST | `/api/web-network/tls` | Certificate and TLS card |
| POST | `/api/web-network/tcp` | Bounded TCP result |
| GET | `/api/web-network/scanners` | Show available scanner capabilities |
| POST | `/api/web-network/nmap` | Run configured Nmap profile |
| POST | `/api/web-network/rustscan` | Run configured RustScan profile |

The request target is supplied as an `AnalysisRequest` unless the endpoint
uses a specialized request model. Scanner requests use `PortScanRequest`:

```json
{
  "target": "example.com",
  "ports": [22, 80, 443]
}
```

Target validation rejects localhost, private, loopback, link-local, reserved,
multicast, unspecified, and internal destinations. HTTP redirects are
validated to prevent SSRF.

## 3. Log Analysis Module

### Purpose

Bounded analysis of uploaded security logs with event categorization,
correlation, IP validation, and chronological timelines.

### Endpoint

```http
POST /api/log-analysis/analyze
Content-Type: multipart/form-data
file=<log file>
```

Supported file types:

- `.log`
- `.txt`
- `.json`
- `.jsonl`
- `.ndjson`

Supported encodings are UTF-8, UTF-16, CP1252, and Latin-1. Empty lines and
comment lines beginning with `#` are ignored.

### Details contract

Frontend sections can use:

| Section | Fields |
| --- | --- |
| Summary | `summary.total_events`, failed/successful counts, `unique_ips` |
| Authentication | `authentication_analysis.top_failed_login_sources` |
| Brute force | `authentication_analysis.possible_brute_force` |
| Suspicious logins | `authentication_analysis.suspicious_login_sequences` |
| Network | `network_analysis.observed_ips`, `possible_scanning_sources` |
| Timeline | `timeline` |
| Categories | `event_categories` |
| Warnings | `warnings` |

Recognized event categories include `authentication_failure`,
`successful_authentication`, `scanning_activity`, `connection_failure`,
`dns_event`, `network_event`, and `other`.

Limits:

- Maximum file size: 10 MB
- Maximum processed lines: 100,000

PCAP signatures are delegated to the Forensics module instead of being parsed
as text.

## 4. Malware Triage Module

### Purpose

Static-only PE and ELF file analysis. Uploaded files are never executed,
sandboxed, modified, or sent to external services.

### Endpoint

```http
POST /api/malware/triage
Content-Type: multipart/form-data
file=<binary file>
```

Frontend sections can render:

- File type, MIME information, and hashes
- PE or ELF architecture and format
- Sections, permissions, entropy, and sizes
- Imports, exports, dependencies, symbols, and relocations
- Categorized strings
- Findings, evidence, and risk assessment

The upload limit is 10 MB. Analysis is static and bounded.

## 5. Forensics Module

### Purpose

Static file and packet-capture analysis for hashes, signatures, metadata, and
forensic findings.

### Endpoint

```http
POST /api/forensics/analyze
Content-Type: multipart/form-data
file=<binary file>
```

The frontend can display:

- File signature and detected format
- SHA-256 and other hashes
- Capture metadata for PCAP files
- Static forensic findings
- Warnings and limitations

The module does not execute files or perform active packet operations.

## 6. Cryptography Module

### Purpose

Local cryptographic, encoding, decoding, signing, and identification tools.

### Endpoints

| Endpoint | Operation |
| --- | --- |
| `POST /api/analyze/cryptography/hash` | SHA-256 hash |
| `POST /api/cryptography/hashes` | Hash suite |
| `POST /api/cryptography/base64/encode` | Base64 encoding |
| `POST /api/cryptography/base64/decode` | Base64 decoding |
| `POST /api/cryptography/cipher-identify` | Encoding/cipher identification |
| `POST /api/cryptography/rot/decode` | ROT decoding |
| `POST /api/cryptography/morse/decode` | Morse decoding |
| `POST /api/cryptography/brainfuck/decode` | Brainfuck decoding |
| `POST /api/cryptography/aes-gcm/encrypt` | AES-GCM encryption |
| `POST /api/cryptography/aes-gcm/decrypt` | AES-GCM decryption |
| `POST /api/cryptography/rsa/key-pair` | RSA key generation |
| `POST /api/cryptography/rsa/sign` | RSA signing |
| `POST /api/cryptography/rsa/verify` | RSA verification |
| `POST /api/cryptography/token` | Secure token generation |

Request fields depend on the operation. Common fields are `target`,
`plaintext`, `ciphertext`, `key`, `nonce`, `value`, `private_key`,
`public_key`, and `signature`. Pydantic validation returns explicit errors for
invalid or missing values.

## 7. Session and Report Module

### Endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/session/history` | Return recent results for the current session |
| DELETE | `/api/session/history` | Clear current session results |
| GET | `/api/reports/{result_index}` | Retrieve one stored result |

Results are associated with an HTTP-only session cookie. The backend retains
up to 100 recent results per session.

## Risk and Error Handling

The shared `risk_level` is calculated from the highest finding severity.
`unknown` means there is not enough evidence to classify the result as safe or
risky; it does not mean safe.

Frontend clients should:

1. Check the HTTP status code.
2. Check `success`.
3. Render `errors` when present.
4. Render `findings` independently from `details`.
5. Treat unavailable, failed, and not-configured coverage as distinct states.
6. Never display missing data as a confirmed negative result.

## Installation and Local Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m app.main
```

This repository is packaged as an application-focused deployment. Frontend
integration should use the API endpoints, shared response contract, and
module-specific details documented above.

## Security Boundaries

CyberSuite intentionally does not provide:

- Malware execution, sandboxing, or YARA scanning
- Machine-learning classification
- Automatic blocking or incident response
- Credential attacks, brute force, or authentication attempts
- Exploitation or vulnerability scanning
- Unrestricted port-range or network-wide scanning
- Unrestricted website crawling
- Automatic claims that a target is malicious without evidence

Use CyberSuite only with explicit authorization for the systems and data being
analyzed.
