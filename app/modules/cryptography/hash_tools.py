from __future__ import annotations

import hashlib
import re
from typing import Any


def sha256_text(text: str) -> dict[str, str]:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return {
        "algorithm": "SHA-256",
        "hash": digest,
        "input_type": "text",
    }


HASH_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "bcrypt",
                "category": "Password Hash",
                "hashcat": "3200",
                "john": "bcrypt",
                "confidence": "high",
                "description": "Blowfish-based adaptive password hashing function.",
            }
        ],
    },
    {
        "pattern": re.compile(
            r"^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9+/=]+\$[./A-Za-z0-9+/=]+$"
        ),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "Argon2",
                "category": "Password Hash",
                "hashcat": "13400",
                "john": "argon2",
                "confidence": "high",
                "description": "Memory-hard password hashing function (winner of Password Hashing Competition).",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "SHA-512 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "1800",
                "john": "sha512crypt",
                "confidence": "high",
                "description": "Standard Linux/Unix shadow file password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "SHA-256 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "7400",
                "john": "sha256crypt",
                "confidence": "high",
                "description": "Standard Linux/Unix shadow file password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "MD5 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "500",
                "john": "md5crypt",
                "confidence": "high",
                "description": "Legacy FreeBSD/Linux MD5 crypt password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "Apache MD5 (apr1)",
                "category": "Web Server",
                "hashcat": "1600",
                "john": "md5crypt-long",
                "confidence": "high",
                "description": "Apache htpasswd MD5 format.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "phpass / WordPress / phpBB3",
                "category": "Web Application",
                "hashcat": "400",
                "john": "phpass",
                "confidence": "high",
                "description": "Portable PHP password hashing framework used by WordPress and phpBB3.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^md5[0-9a-fA-F]{32}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "PostgreSQL MD5",
                "category": "Database",
                "hashcat": "12",
                "john": "postgres",
                "confidence": "high",
                "description": "PostgreSQL user password authentication format.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\*[0-9a-fA-F]{40}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MySQL 4.1+ / MySQL 5+",
                "category": "Database",
                "hashcat": "300",
                "john": "mysql-sha1",
                "confidence": "high",
                "description": "MySQL PASSWORD() format with leading asterisk (Double SHA-1).",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0100[0-9a-fA-F]{88}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2000",
                "category": "Database",
                "hashcat": "131",
                "john": "mssql",
                "confidence": "high",
                "description": "Microsoft SQL Server 2000 password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0100[0-9a-fA-F]{48}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2005 / 2008",
                "category": "Database",
                "hashcat": "132",
                "john": "mssql05",
                "confidence": "high",
                "description": "Microsoft SQL Server 2005/2008 SHA-1 password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0200[0-9a-fA-F]{136}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2012 / 2014",
                "category": "Database",
                "hashcat": "1731",
                "john": "mssql12",
                "confidence": "high",
                "description": "Microsoft SQL Server 2012/2014 SHA-512 password hash.",
            }
        ],
    },
]

HEX_LENGTH_ALGORITHMS: dict[int, list[dict[str, str]]] = {
    16: [
        {
            "name": "MySQL 3.23",
            "category": "Database",
            "hashcat": "200",
            "john": "mysql",
            "confidence": "high",
            "description": "Legacy MySQL old_password function.",
        },
        {
            "name": "Cisco-PIX MD5",
            "category": "Network",
            "hashcat": "2400",
            "john": "pix-md5",
            "confidence": "low",
            "description": "Legacy Cisco PIX firewall password hash.",
        },
    ],
    32: [
        {
            "name": "MD5",
            "category": "Raw Hash",
            "hashcat": "0",
            "john": "raw-md5",
            "confidence": "high",
            "description": "Message Digest 5 (128-bit).",
        },
        {
            "name": "NTLM",
            "category": "Windows",
            "hashcat": "1000",
            "john": "nt",
            "confidence": "high",
            "description": "Windows NT LAN Manager hash (MD4 of UTF-16LE).",
        },
        {
            "name": "MD4",
            "category": "Raw Hash",
            "hashcat": "900",
            "john": "raw-md4",
            "confidence": "medium",
            "description": "Message Digest 4 (128-bit).",
        },
        {
            "name": "LM",
            "category": "Windows",
            "hashcat": "3000",
            "john": "lm",
            "confidence": "low",
            "description": "Legacy Windows LAN Manager hash (DES-based).",
        },
    ],
    40: [
        {
            "name": "SHA-1",
            "category": "Raw Hash",
            "hashcat": "100",
            "john": "raw-sha1",
            "confidence": "high",
            "description": "Secure Hash Algorithm 1 (160-bit).",
        },
        {
            "name": "MySQL 4.1 / MySQL 5+",
            "category": "Database",
            "hashcat": "300",
            "john": "mysql-sha1",
            "confidence": "high",
            "description": "Double SHA-1 hash used in MySQL password auth.",
        },
        {
            "name": "RIPEMD-160",
            "category": "Raw Hash",
            "hashcat": "6000",
            "john": "ripemd-160",
            "confidence": "medium",
            "description": "RACE Integrity Primitives Evaluation Message Digest 160.",
        },
    ],
    56: [
        {
            "name": "SHA-224",
            "category": "Raw Hash",
            "hashcat": "1300",
            "john": "raw-sha224",
            "confidence": "high",
            "description": "SHA-2 family (224-bit).",
        },
        {
            "name": "SHA3-224",
            "category": "Raw Hash",
            "hashcat": "17300",
            "john": "raw-sha3-224",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (224-bit).",
        },
    ],
    64: [
        {
            "name": "SHA-256",
            "category": "Raw Hash",
            "hashcat": "1400",
            "john": "raw-sha256",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (256-bit).",
        },
        {
            "name": "SHA3-256",
            "category": "Raw Hash",
            "hashcat": "17400",
            "john": "raw-sha3-256",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (256-bit).",
        },
        {
            "name": "BLAKE2s-256",
            "category": "Raw Hash",
            "hashcat": "5400",
            "john": "blake2s",
            "confidence": "medium",
            "description": "Cryptographic hash optimized for 8 to 32-bit platforms.",
        },
        {
            "name": "Keccak-256",
            "category": "Raw Hash",
            "hashcat": "17800",
            "john": "keccak-256",
            "confidence": "medium",
            "description": "Ethereum/Web3 cryptographic hash.",
        },
    ],
    96: [
        {
            "name": "SHA-384",
            "category": "Raw Hash",
            "hashcat": "10800",
            "john": "raw-sha384",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (384-bit).",
        },
        {
            "name": "SHA3-384",
            "category": "Raw Hash",
            "hashcat": "17500",
            "john": "raw-sha3-384",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (384-bit).",
        },
    ],
    128: [
        {
            "name": "SHA-512",
            "category": "Raw Hash",
            "hashcat": "1700",
            "john": "raw-sha512",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (512-bit).",
        },
        {
            "name": "SHA3-512",
            "category": "Raw Hash",
            "hashcat": "17600",
            "john": "raw-sha3-512",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (512-bit).",
        },
        {
            "name": "Whirlpool",
            "category": "Raw Hash",
            "hashcat": "6100",
            "john": "whirlpool",
            "confidence": "medium",
            "description": "512-bit hash based on AES design principles.",
        },
        {
            "name": "BLAKE2b-512",
            "category": "Raw Hash",
            "hashcat": "600",
            "john": "blake2b",
            "confidence": "medium",
            "description": "Cryptographic hash optimized for 64-bit platforms.",
        },
    ],
}


def identify_hash(value: str) -> dict[str, Any]:
    stripped = str(value or "").strip()
    if not stripped:
        return {
            "input": value,
            "length": 0,
            "format": "empty",
            "bit_length": None,
            "possible_algorithms": [],
            "match_count": 0,
        }

    # 1. Check modular / prefixed patterns
    for entry in HASH_PATTERNS:
        if entry["pattern"].match(stripped):
            return {
                "input": stripped,
                "length": len(stripped),
                "format": entry["format"],
                "bit_length": None,
                "possible_algorithms": entry["algorithms"],
                "match_count": len(entry["algorithms"]),
            }

    # 2. Check JWT
    if (
        stripped.startswith("eyJ")
        and stripped.count(".") == 2
        and re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", stripped)
    ):
        jwt_entry = [
            {
                "name": "JSON Web Token (JWT)",
                "category": "Token / Signature",
                "hashcat": "16500",
                "john": "jwt",
                "confidence": "high",
                "description": "Compact, URL-safe means of representing claims.",
            }
        ]
        return {
            "input": stripped,
            "length": len(stripped),
            "format": "jwt",
            "bit_length": None,
            "possible_algorithms": jwt_entry,
            "match_count": 1,
        }

    # 3. Check Raw Hex digests
    if re.fullmatch(r"^[0-9a-fA-F]+$", stripped):
        length = len(stripped)
        if length in HEX_LENGTH_ALGORITHMS:
            algorithms = HEX_LENGTH_ALGORITHMS[length]
            return {
                "input": stripped,
                "length": length,
                "format": "hex",
                "bit_length": length * 4,
                "possible_algorithms": algorithms,
                "match_count": len(algorithms),
            }

    return {
        "input": stripped,
        "length": len(stripped),
        "format": "unknown",
        "bit_length": None,
        "possible_algorithms": [],
        "match_count": 0,
    }



HASH_PATTERNS: list[dict[str, Any]] = [
    {
        "pattern": re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "bcrypt",
                "category": "Password Hash",
                "hashcat": "3200",
                "john": "bcrypt",
                "confidence": "high",
                "description": "Blowfish-based adaptive password hashing function.",
            }
        ],
    },
    {
        "pattern": re.compile(
            r"^\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9+/=]+\$[./A-Za-z0-9+/=]+$"
        ),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "Argon2",
                "category": "Password Hash",
                "hashcat": "13400",
                "john": "argon2",
                "confidence": "high",
                "description": "Memory-hard password hashing function (winner of Password Hashing Competition).",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "SHA-512 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "1800",
                "john": "sha512crypt",
                "confidence": "high",
                "description": "Standard Linux/Unix shadow file password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "SHA-256 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "7400",
                "john": "sha256crypt",
                "confidence": "high",
                "description": "Standard Linux/Unix shadow file password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "MD5 Crypt (Unix)",
                "category": "Unix Shadow",
                "hashcat": "500",
                "john": "md5crypt",
                "confidence": "high",
                "description": "Legacy FreeBSD/Linux MD5 crypt password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "Apache MD5 (apr1)",
                "category": "Web Server",
                "hashcat": "1600",
                "john": "md5crypt-long",
                "confidence": "high",
                "description": "Apache htpasswd MD5 format.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\$[PH]\$[./A-Za-z0-9]{31}$"),
        "format": "modular_crypt",
        "algorithms": [
            {
                "name": "phpass / WordPress / phpBB3",
                "category": "Web Application",
                "hashcat": "400",
                "john": "phpass",
                "confidence": "high",
                "description": "Portable PHP password hashing framework used by WordPress and phpBB3.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^md5[0-9a-fA-F]{32}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "PostgreSQL MD5",
                "category": "Database",
                "hashcat": "12",
                "john": "postgres",
                "confidence": "high",
                "description": "PostgreSQL user password authentication format.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^\*[0-9a-fA-F]{40}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MySQL 4.1+ / MySQL 5+",
                "category": "Database",
                "hashcat": "300",
                "john": "mysql-sha1",
                "confidence": "high",
                "description": "MySQL PASSWORD() format with leading asterisk (Double SHA-1).",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0100[0-9a-fA-F]{88}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2000",
                "category": "Database",
                "hashcat": "131",
                "john": "mssql",
                "confidence": "high",
                "description": "Microsoft SQL Server 2000 password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0100[0-9a-fA-F]{48}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2005 / 2008",
                "category": "Database",
                "hashcat": "132",
                "john": "mssql05",
                "confidence": "high",
                "description": "Microsoft SQL Server 2005/2008 SHA-1 password hash.",
            }
        ],
    },
    {
        "pattern": re.compile(r"^0x0200[0-9a-fA-F]{136}$"),
        "format": "database",
        "algorithms": [
            {
                "name": "MSSQL 2012 / 2014",
                "category": "Database",
                "hashcat": "1731",
                "john": "mssql12",
                "confidence": "high",
                "description": "Microsoft SQL Server 2012/2014 SHA-512 password hash.",
            }
        ],
    },
]

HEX_LENGTH_ALGORITHMS: dict[int, list[dict[str, str]]] = {
    16: [
        {
            "name": "MySQL 3.23",
            "category": "Database",
            "hashcat": "200",
            "john": "mysql",
            "confidence": "high",
            "description": "Legacy MySQL old_password function.",
        },
        {
            "name": "Cisco-PIX MD5",
            "category": "Network",
            "hashcat": "2400",
            "john": "pix-md5",
            "confidence": "low",
            "description": "Legacy Cisco PIX firewall password hash.",
        },
    ],
    32: [
        {
            "name": "MD5",
            "category": "Raw Hash",
            "hashcat": "0",
            "john": "raw-md5",
            "confidence": "high",
            "description": "Message Digest 5 (128-bit).",
        },
        {
            "name": "NTLM",
            "category": "Windows",
            "hashcat": "1000",
            "john": "nt",
            "confidence": "high",
            "description": "Windows NT LAN Manager hash (MD4 of UTF-16LE).",
        },
        {
            "name": "MD4",
            "category": "Raw Hash",
            "hashcat": "900",
            "john": "raw-md4",
            "confidence": "medium",
            "description": "Message Digest 4 (128-bit).",
        },
        {
            "name": "LM",
            "category": "Windows",
            "hashcat": "3000",
            "john": "lm",
            "confidence": "low",
            "description": "Legacy Windows LAN Manager hash (DES-based).",
        },
    ],
    40: [
        {
            "name": "SHA-1",
            "category": "Raw Hash",
            "hashcat": "100",
            "john": "raw-sha1",
            "confidence": "high",
            "description": "Secure Hash Algorithm 1 (160-bit).",
        },
        {
            "name": "MySQL 4.1 / MySQL 5+",
            "category": "Database",
            "hashcat": "300",
            "john": "mysql-sha1",
            "confidence": "high",
            "description": "Double SHA-1 hash used in MySQL password auth.",
        },
        {
            "name": "RIPEMD-160",
            "category": "Raw Hash",
            "hashcat": "6000",
            "john": "ripemd-160",
            "confidence": "medium",
            "description": "RACE Integrity Primitives Evaluation Message Digest 160.",
        },
    ],
    56: [
        {
            "name": "SHA-224",
            "category": "Raw Hash",
            "hashcat": "1300",
            "john": "raw-sha224",
            "confidence": "high",
            "description": "SHA-2 family (224-bit).",
        },
        {
            "name": "SHA3-224",
            "category": "Raw Hash",
            "hashcat": "17300",
            "john": "raw-sha3-224",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (224-bit).",
        },
    ],
    64: [
        {
            "name": "SHA-256",
            "category": "Raw Hash",
            "hashcat": "1400",
            "john": "raw-sha256",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (256-bit).",
        },
        {
            "name": "SHA3-256",
            "category": "Raw Hash",
            "hashcat": "17400",
            "john": "raw-sha3-256",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (256-bit).",
        },
        {
            "name": "BLAKE2s-256",
            "category": "Raw Hash",
            "hashcat": "5400",
            "john": "blake2s",
            "confidence": "medium",
            "description": "Cryptographic hash optimized for 8 to 32-bit platforms.",
        },
        {
            "name": "Keccak-256",
            "category": "Raw Hash",
            "hashcat": "17800",
            "john": "keccak-256",
            "confidence": "medium",
            "description": "Ethereum/Web3 cryptographic hash.",
        },
    ],
    96: [
        {
            "name": "SHA-384",
            "category": "Raw Hash",
            "hashcat": "10800",
            "john": "raw-sha384",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (384-bit).",
        },
        {
            "name": "SHA3-384",
            "category": "Raw Hash",
            "hashcat": "17500",
            "john": "raw-sha3-384",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (384-bit).",
        },
    ],
    128: [
        {
            "name": "SHA-512",
            "category": "Raw Hash",
            "hashcat": "1700",
            "john": "raw-sha512",
            "confidence": "high",
            "description": "Secure Hash Algorithm 2 (512-bit).",
        },
        {
            "name": "SHA3-512",
            "category": "Raw Hash",
            "hashcat": "17600",
            "john": "raw-sha3-512",
            "confidence": "medium",
            "description": "Keccak/SHA-3 family (512-bit).",
        },
        {
            "name": "Whirlpool",
            "category": "Raw Hash",
            "hashcat": "6100",
            "john": "whirlpool",
            "confidence": "medium",
            "description": "512-bit hash based on AES design principles.",
        },
        {
            "name": "BLAKE2b-512",
            "category": "Raw Hash",
            "hashcat": "600",
            "john": "blake2b",
            "confidence": "medium",
            "description": "Cryptographic hash optimized for 64-bit platforms.",
        },
    ],
}


def identify_hash(value: str) -> dict[str, Any]:
    stripped = str(value or "").strip()
    if not stripped:
        return {
            "input": value,
            "length": 0,
            "format": "empty",
            "bit_length": None,
            "possible_algorithms": [],
            "match_count": 0,
        }

    # 1. Check modular / prefixed patterns
    for entry in HASH_PATTERNS:
        if entry["pattern"].match(stripped):
            return {
                "input": stripped,
                "length": len(stripped),
                "format": entry["format"],
                "bit_length": None,
                "possible_algorithms": entry["algorithms"],
                "match_count": len(entry["algorithms"]),
            }

    # 2. Check JWT
    if (
        stripped.startswith("eyJ")
        and stripped.count(".") == 2
        and re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", stripped)
    ):
        jwt_entry = [
            {
                "name": "JSON Web Token (JWT)",
                "category": "Token / Signature",
                "hashcat": "16500",
                "john": "jwt",
                "confidence": "high",
                "description": "Compact, URL-safe means of representing claims.",
            }
        ]
        return {
            "input": stripped,
            "length": len(stripped),
            "format": "jwt",
            "bit_length": None,
            "possible_algorithms": jwt_entry,
            "match_count": 1,
        }

    # 3. Check Raw Hex digests
    if re.fullmatch(r"^[0-9a-fA-F]+$", stripped):
        length = len(stripped)
        if length in HEX_LENGTH_ALGORITHMS:
            algorithms = HEX_LENGTH_ALGORITHMS[length]
            return {
                "input": stripped,
                "length": length,
                "format": "hex",
                "bit_length": length * 4,
                "possible_algorithms": algorithms,
                "match_count": len(algorithms),
            }

    return {
        "input": stripped,
        "length": len(stripped),
        "format": "unknown",
        "bit_length": None,
        "possible_algorithms": [],
        "match_count": 0,
    }