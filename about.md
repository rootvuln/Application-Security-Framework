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

## Project Structure

```text
app/
├── main.py                  FastAPI app: CORS, rate limit, cookies, audit log, health
├── api/
│   ├── __init__.py          re-exports router
│   └── routes.py            every /api endpoint in one file
├── core/
│   ├── config.py            single source of tunables: limits, rate limit, CORS, cookie name
│   └── risk.py              shared risk scoring helpers
├── services/
│   └── session_store.py     bounded in-memory session result store
├── schemas/analysis.py      shared Pydantic request, finding and response models
└── modules/                 pure analysis logic, no FastAPI imports
    ├── cryptography/
    ├── forensics/
    ├── log_analysis/        incl. pcap_analysis.py
    ├── malware_triage/      incl. sections.py, rules.py, strings.py, entropy.py
    ├── osint/
    └── web/
```

`app/main.py` creates the FastAPI application and provides CORS, rate limiting,
session cookies, audit logging, and health checks.

`app/api/routes.py` is the whole HTTP surface in one file: it validates
requests, dispatches to `app/modules/*`, converts the outcome into the shared
response model, and stores recent results for the session history. Inside the
file the handlers are grouped with one small router per capability
(`session_router`, `osint_router`, `web_network_router`,
`cryptography_router`, `uploads_router`) so Swagger UI still groups them; the
aggregate `router = APIRouter(prefix="/api")` at the bottom mounts all five.

`app/core/config.py` holds every tunable (upload ceilings, string extraction
limits, rate-limit window, allowed origins, cookie name). Modules import from
here instead of redefining constants, so a limit changes in exactly one place.

`app/services/session_store.py` keeps a bounded, per-session ring of recent
results used by the session history and report endpoints.

`app/schemas/analysis.py` defines shared Pydantic request, finding, and
response models.

Frontend layout:

```text
frontend/src/
├── main.jsx / App.jsx        shell, sidebar, route table, health badge
├── api/client.js             fetch wrapper for the /api envelope
├── lib/format.js             formatting helpers (bytes, duration, clock, percent)
├── components/
│   ├── layout/Sidebar.jsx    navigation
│   └── ui/                   SectionCard, CopyButton, TagList
└── features/<module>/        one self-contained page file per capability area
    ├── dashboard/            DashboardPage.jsx
    ├── osint/                OSINTPage.jsx
    ├── web_network/          WebNetworkPage.jsx
    ├── cryptography/         CryptographyPage.jsx
    ├── forensics/            ForensicsPage.jsx
    ├── malware/              MalwarePage.jsx
    ├── log_analysis/         LogAnalysisPage.jsx
    └── session/              SessionHistoryPage.jsx
```

Each page file is self-contained: layout, tab state, data fetching, and its own
presentational sub-components all live together. Only pieces used by more than
one feature sit higher up, in `src/components/ui/` (`SectionCard`,
`CopyButton`, `TagList`) or `src/lib/format.js`.

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

`ports` accepts numbers and ranges, mixed freely — each entry may also be a
comma-separated string:

```json
{
  "target": "example.com",
  "ports": ["22,80,443", "1000-1010", "8080:8090"]
}
```

| Form | Meaning |
| --- | --- |
| `80` / `"80"` | single port |
| `"80,443"` | list of ports |
| `"1000-1010"` | inclusive range (hyphen) |
| `"8080:8090"` | inclusive range (colon, nmap style) |

Ranges are expanded and de-duplicated server-side. Limits: at most 512 ports
per request, and no single range may span more than 512 ports. Ports are probed
concurrently, so the whole scan is bounded by roughly
`ceil(ports / 64) x 1s` rather than one second per port. The TCP checker
reports `open`, `closed` (connection refused), or `filtered` (no response —
typically a firewall, not a closed port).


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
- `.pcap`
- `.pcapng`

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
- Maximum decoded packets per capture: 200,000

### Packet capture analysis

`.pcap` and `.pcapng` uploads are decoded rather than treated as opaque text.
Containers supported: classic PCAP in both byte orders and both microsecond and
nanosecond timestamp variants, plus PCAPNG (Section Header, Interface
Description, Enhanced Packet, and Simple Packet blocks, with `if_tsresol`
honoured). Link types decoded: Ethernet (including VLAN tags), raw IPv4/IPv6,
Linux SLL, and BSD loopback.

From the decoded frames the module produces:

| Section | Fields |
| --- | --- |
| Summary | `format`, `packet_count`, `bytes`, `duration_seconds`, `first_timestamp`, `last_timestamp` |
| Attacker IPs | `attacker_ips[]` with `ip`, `failure_count`, `success_count`, `verdict` |
| IP statistics | `ip_statistics.top_source_ips`, `top_dest_ips`, `top_conversations` |
| Port activity | `port_activity[]` with `port`, `count`, `service` |
| Raw stats | `raw_stats.protocols`, packet/byte totals and duration |
| Packet details | `capture.top_talkers`, `dns_queries`, `http_requests`, `http_hosts`, `tls_server_names`, `suspicious_services`, `cleartext_credentials` |
| Hashes | `hashes.md5`, `sha1`, `sha256`, `sha512` |

Findings raised from captures:

- Possible port scan — one source contacting at least 15 distinct ports with at
  least 10 SYN probes.
- SYN flood — at least 100 SYN packets with ACK volume far below SYN volume.
- Credentials sent over cleartext HTTP — Basic auth headers or password fields
  in request bodies.
- Traffic to commonly abused ports — only for non-SYN traffic, so scan probes do
  not inflate the count.
- Unusually long DNS labels — 45+ character label, an indicator of tunnelling.
- Large data transfer — a single flow above 5 MB.
- High ICMP volume — at least 200 ICMP packets.

DNS question names, HTTP request lines/headers, and TLS ClientHello SNI values
are read from cleartext payloads only; encrypted traffic is never decrypted.
Payload inspection is truncated per packet and sample collections are capped.

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
- Sections, permissions, entropy, sizes, and a per-section description
- Imports, exports, dependencies, symbols (with kind and binding), and relocations
- Hardening flags and structural anomalies
- Static pattern-rule matches
- Extracted printable strings with search and category filters
- Categorized strings
- Findings, evidence, and risk assessment

The upload limit is 10 MB. Analysis is static and bounded.

### Section descriptions

Every parsed section carries a short explanation of what it holds, so the table
reads as more than a list of names: `.text` is executable code, `.plt` holds
linker stubs, `.got.plt` is the lazily patched address table, `.dynsym` /
`.dynstr` feed dynamic linking, `.eh_frame` drives unwinding, `.init_array` is a
constructor hook, `.bss` occupies memory but no file bytes, and `.upx*` /
`.vmp*` / `.themida` belong to packers and protectors. Sections are also grouped
(coarse `code`, `read_only`, `data`, `linking`, `metadata`, `packed`) for
colour-coding. Unknown names are reported without an invented description.

### ELF hardening and anomalies

From the program headers, dynamic section and imported symbols the module
derives:

| Check | Source |
| --- | --- |
| PIE | `e_type` (`ET_DYN` + interpreter) |
| NX | `PT_GNU_STACK` without `PF_X` |
| Stack canary | `__stack_chk_fail` import |
| RELRO | `PT_GNU_RELRO`, upgraded to `full` with `BIND_NOW` |
| Text relocations | `DT_TEXTREL` |
| Stripped | absence of `.symtab` |
| Search path | `DT_RPATH` / `DT_RUNPATH` |

Structural anomalies raised as findings: executable stack, RWX load segment,
writable code section, non-executable `.text`, high-entropy section, packer
section names, entry point outside every executable section, missing stack
declaration, and an uncommon target architecture.

### Static pattern rules

Ten literal byte/string rules are evaluated (UPX and generic packer markers,
reverse-shell commands, miner indicators, credential-dumping strings,
persistence commands, anti-debug APIs, privilege-escalation strings,
exfiltration helpers, hard-coded IPv4 literals). A match is reported with its
rule id, severity and byte offset. This is deliberately **not** a YARA engine:
it cannot express boolean conditions, offsets or wildcards, and a match is an
indicator rather than a verdict.

### String extraction

Printable ASCII runs of four or more characters are extracted from the raw
bytes (section names and dependency names are excluded so the list is not
diluted by linker metadata). Up to 5,000 strings are scanned and the first 800,
each truncated to 200 characters, are returned in `details.strings` together
with `details.string_analysis` (`total_extracted`, `returned`, `truncated`,
`category_counts`). Each string is also matched against the URL, domain, IPv4,
file-path, interpreter-path, shell, API, persistence, registry and
encoded-blob patterns reported under `categorized_strings`; the UI turns that
into a searchable list with per-row category tags.

### Analysis limitations

The response states these explicitly: nothing is executed, emulated, unpacked or
detonated; no disassembly is performed; section entropy covers raw bytes only;
and no reputation or sandbox service is queried.

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
| `POST /api/cryptography/cipher-identify` | Encoding/cipher identification (Base64, Base32, hex, binary, decimal codes, URL encoding, Morse, Brainfuck, ROT-N, Atbash, hashes) |
| `POST /api/cryptography/hash-identify` | Hash algorithm identification |
| `POST /api/cryptography/rot/decode` | ROT decoding |
| `POST /api/cryptography/morse/encode` | Morse encoding |
| `POST /api/cryptography/morse/decode` | Morse decoding |
| `POST /api/cryptography/brainfuck/encode` | Brainfuck program generation |
| `POST /api/cryptography/brainfuck/decode` | Brainfuck execution |
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
