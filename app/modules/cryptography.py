"""Cryptography: hashing, encoding, classical ciphers and key material."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
from typing import Any
from urllib.parse import unquote_plus

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── hash_tools.py ─────────────────────────────────────────────────────────────

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


# ── lab.py ────────────────────────────────────────────────────────────────────

MAX_BRAINFUCK_STEPS = 100_000
MAX_BRAINFUCK_OUTPUT = 4_096
BRAINFUCK_INSTRUCTIONS = set("+-<>[],.")
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".",
    "--..--": ",", "..--..": "?", "-.-.--": "!", "-....-": "-",
}


def hashes_for_text(value: str) -> dict[str, str]:
    encoded = value.encode("utf-8")
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha512": hashlib.sha512(encoded).hexdigest(),
        "md5": hashlib.md5(encoded).hexdigest(),
        "sha1": hashlib.sha1(encoded).hexdigest(),
        "input_type": "text",
    }


def encode_base64(value: str) -> dict[str, str]:
    return {"encoding": "base64", "value": base64.b64encode(value.encode()).decode()}


def decode_base64(value: str) -> dict[str, str]:
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
        text = decoded.decode("utf-8")
    except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise ValueError("Input is not valid UTF-8 Base64") from exc
    return {"encoding": "base64", "value": text}


def encrypt_aes_gcm(plaintext: str, key: str) -> dict[str, str]:
    try:
        key_bytes = base64.b64decode(key.encode("ascii"), validate=True)
    except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise ValueError("AES key must be Base64 encoded") from exc
    if len(key_bytes) not in {16, 24, 32}:
        raise ValueError("AES key must decode to 16, 24, or 32 bytes")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext.encode(), None)
    return {
        "algorithm": "AES-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_aes_gcm(ciphertext: str, key: str, nonce: str) -> dict[str, str]:
    try:
        key_bytes = base64.b64decode(key.encode("ascii"), validate=True)
        nonce_bytes = base64.b64decode(nonce.encode("ascii"), validate=True)
        ciphertext_bytes = base64.b64decode(ciphertext.encode("ascii"), validate=True)
        plaintext = AESGCM(key_bytes).decrypt(nonce_bytes, ciphertext_bytes, None)
        return {"algorithm": "AES-GCM", "plaintext": plaintext.decode("utf-8")}
    except (InvalidTag, UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise ValueError("AES-GCM input is invalid or authentication failed") from exc


def generate_rsa_key_pair() -> dict[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "algorithm": "RSA-2048",
        "private_key": private_pem.decode(),
        "public_key": public_pem.decode(),
        "warning": "Keep the private key secret; it is returned only in this response.",
    }


def sign_rsa(value: str, private_key: str) -> dict[str, str]:
    try:
        key = serialization.load_pem_private_key(private_key.encode(), password=None)
        signature = key.sign(
            value.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid RSA private key") from exc
    return {"algorithm": "RSA-PSS-SHA256", "signature": base64.b64encode(signature).decode()}


def verify_rsa(value: str, public_key: str, signature: str) -> dict[str, Any]:
    try:
        key = serialization.load_pem_public_key(public_key.encode())
        key.verify(
            base64.b64decode(signature.encode("ascii"), validate=True),
            value.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return {"algorithm": "RSA-PSS-SHA256", "valid": False}
    return {"algorithm": "RSA-PSS-SHA256", "valid": True}


def secure_token(length: int) -> dict[str, Any]:
    if length < 16 or length > 128:
        raise ValueError("Token length must be between 16 and 128")
    return {"length": length, "token": secrets.token_urlsafe(length)[:length]}


def rot(value: str, shift: int) -> str:
    def translate(character: str) -> str:
        if "a" <= character <= "z":
            return chr((ord(character) - ord("a") + shift) % 26 + ord("a"))
        if "A" <= character <= "Z":
            return chr((ord(character) - ord("A") + shift) % 26 + ord("A"))
        return character
    return "".join(translate(character) for character in value)


def decode_morse(value: str) -> str:
    words = value.strip().split(" / ")
    decoded_words = []
    for word in words:
        letters = word.split()
        if not letters or any(letter not in MORSE for letter in letters):
            raise ValueError("Input contains an unknown Morse symbol")
        decoded_words.append("".join(MORSE[letter] for letter in letters))
    return " ".join(decoded_words)


MORSE_REVERSE = {symbol: code for code, symbol in MORSE.items()}


def encode_morse(value: str) -> dict[str, Any]:
    """Encode text as Morse code: letters are space-separated, words use " / "."""
    normalized = value.strip().upper()
    if not normalized:
        raise ValueError("Text to encode is required")
    encoded_words: list[str] = []
    for word in normalized.split():
        symbols: list[str] = []
        for character in word:
            code = MORSE_REVERSE.get(character)
            if code is None:
                raise ValueError(
                    f"Character {character!r} has no Morse representation"
                )
            symbols.append(code)
        encoded_words.append(" ".join(symbols))
    encoded = " / ".join(encoded_words)
    return {"encoding": "morse", "value": encoded, "characters": len(normalized)}


def decode_brainfuck(value: str) -> str:
    code = "".join(character for character in value if character in BRAINFUCK_INSTRUCTIONS)
    if not code or len(code) < 3:
        raise ValueError("Input does not contain enough Brainfuck instructions")
    brackets: dict[int, int] = {}
    stack: list[int] = []
    for index, character in enumerate(code):
        if character == "[":
            stack.append(index)
        elif character == "]":
            if not stack:
                raise ValueError("Brainfuck has an unmatched closing bracket")
            opening = stack.pop()
            brackets[opening] = index
            brackets[index] = opening
    if stack:
        raise ValueError("Brainfuck has an unmatched opening bracket")

    memory = [0] * 30_000
    pointer = instruction = steps = 0
    output: list[str] = []
    while instruction < len(code):
        if steps >= MAX_BRAINFUCK_STEPS:
            raise ValueError("Brainfuck execution limit exceeded")
        operation = code[instruction]
        if operation == ">":
            pointer = (pointer + 1) % len(memory)
        elif operation == "<":
            pointer = (pointer - 1) % len(memory)
        elif operation == "+":
            memory[pointer] = (memory[pointer] + 1) % 256
        elif operation == "-":
            memory[pointer] = (memory[pointer] - 1) % 256
        elif operation == ".":
            output.append(chr(memory[pointer]))
            if len("".join(output)) > MAX_BRAINFUCK_OUTPUT:
                raise ValueError("Brainfuck output limit exceeded")
        elif operation == "[" and memory[pointer] == 0:
            instruction = brackets[instruction]
        elif operation == "]" and memory[pointer] != 0:
            instruction = brackets[instruction]
        instruction += 1
        steps += 1
    return "".join(output)


def encode_brainfuck(value: str) -> dict[str, Any]:
    """Generate a Brainfuck program that prints `value`.

    Each character is written by stepping the current cell to the target byte
    and emitting ".", so the generated program is deterministic and can be
    verified by running it back through decode_brainfuck.
    """
    if not value:
        raise ValueError("Text to encode is required")
    program: list[str] = []
    current = 0
    for character in value:
        target = ord(character)
        if target > 255:
            raise ValueError("Brainfuck can only print byte-sized (0-255) characters")
        delta = (target - current) % 256
        if delta <= 128:
            program.append("+" * delta)
        else:
            program.append("-" * (256 - delta))
        program.append(".")
        current = target
    code = "".join(program)
    if len(code) > MAX_BRAINFUCK_STEPS:
        raise ValueError(
            "Encoded program exceeds the execution limit; encode shorter text"
        )
    return {
        "language": "Brainfuck",
        "value": code,
        "characters": len(value),
        "instructions": len(code),
    }


# ── Encoding / cipher identification ─────────────────────────────────────────

# Frequent English words used to score candidate plaintext. ROT detection used
# to rely on five words ("the", "this", "is", "hello", "you"), so a real ROT-13
# payload that did not contain one of them was reported as "no candidates".
_COMMON_WORDS = frozenset(
    """
    a about after again all also am an and any are as at back be because been
    before being below between both but by can could did do does doing down
    during each few for from further get give go had has have having he her
    here hers him himself his how i if in into is it its itself just know like
    make me more most my myself new no nor not now of off on once only or other
    our ours out over own same see she should so some such take than that the
    their them then there these they thing think this those through to too
    under until up very was way we well were what when where which while who
    why will with would you your

    attack bad base binary block break byte capture challenge cipher code
    crack crypto data decode encrypt encode flag format good great hack hash
    hello help hidden key known let line list message name need password
    plain problem quick real reverse run secret simple string text time tool
    try value word world write brown dog fox jumps lazy over
    """.split()
)

# Common English bigrams give partial credit for inflected or compound words
# that the word list does not contain.
_COMMON_BIGRAMS = (
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng",
    "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri",
    "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
)

_ATBASH_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
)

_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

# A shift must clear this score (roughly: two real English words) before it is
# reported, so plain text is never mislabelled as ROT-N.
_ROT_MIN_SCORE = 8.0


def _english_score(text: str) -> float:
    """Rough English-likeness score; higher means more readable.

    Whole common words are the strongest signal, common bigrams provide
    partial credit, and a plausible vowel ratio rejects consonant soup.
    """
    tokens = re.findall(r"[a-z]+", text.lower())
    if not tokens:
        return 0.0
    score = 0.0
    for token in tokens:
        if token in _COMMON_WORDS:
            score += len(token)
        elif len(token) >= 3:
            score += 0.75 * sum(1 for bigram in _COMMON_BIGRAMS if bigram in token)
    letters = "".join(tokens)
    if len(letters) >= 8:
        vowels = sum(letters.count(vowel) for vowel in "aeiou") / len(letters)
        if 0.30 <= vowels <= 0.55:
            score += 2.0
    return score


def _printable_text(data: bytes) -> str | None:
    """Decode bytes as UTF-8, rejecting binary junk (control characters)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    if printable / len(text) < 0.95:
        return None
    if not any(char.isalnum() for char in text):
        return None
    return text


def _add(
    candidates: list[dict[str, Any]],
    kind: str,
    confidence: str,
    decoded: str | None,
    note: str | None = None,
) -> None:
    entry: dict[str, Any] = {"type": kind, "confidence": confidence, "decoded": decoded}
    if note:
        entry["note"] = note
    candidates.append(entry)


def identify(value: str) -> dict[str, Any]:
    """Identify encodings, simple ciphers and hashes in ``value``.

    Candidates are ordered by confidence. Every decoder result is validated
    (printable text, functional round-trip) so the caller is not handed junk
    such as binary read as hex.
    """
    candidates: list[dict[str, Any]] = []
    stripped = value.strip()
    if not stripped:
        return {"input": value, "candidates": candidates}

    # Hash first: a 32/40/64 character hex blob is a digest, not hex text.
    hash_result = identify_hash(stripped)
    if hash_result["possible_algorithms"]:
        top = hash_result["possible_algorithms"][:3]
        _add(
            candidates,
            "hash",
            top[0]["confidence"],
            f"Likely: {', '.join(algo['name'] for algo in top)}",
            f"{hash_result.get('match_count', len(top))} candidate algorithm(s)",
        )

    # Base64 — tolerate missing '=' padding, then re-encode to confirm the
    # input really is canonical base64 rather than arbitrary alphanumeric text.
    base64_body = stripped.rstrip("=")
    if (
        (len(base64_body) >= 4 or stripped.endswith("="))
        and re.fullmatch(r"[A-Za-z0-9+/]+", base64_body)
    ):
        padded = base64_body + "=" * (-len(base64_body) % 4)
        try:
            raw_bytes = base64.b64decode(padded, validate=True)
            text = _printable_text(raw_bytes)
            if (
                text
                and base64.b64encode(raw_bytes).decode().rstrip("=") == base64_body
            ):
                _add(candidates, "base64", "high", text)
        except (ValueError, binascii.Error):
            pass

    # Base32 — needs at least two 8-character blocks to be worth decoding.
    if (
        len(stripped) >= 16
        and len(stripped) % 8 == 0
        and re.fullmatch(r"[A-Z2-7]+=*", stripped)
    ):
        try:
            text = _printable_text(base64.b32decode(stripped))
            if text:
                _add(candidates, "base32", "high", text)
        except (binascii.Error, ValueError):
            pass

    # Percent / URL encoding.
    if re.search(r"%[0-9A-Fa-f]{2}", stripped):
        unquoted = unquote_plus(stripped)
        if unquoted != stripped:
            _add(candidates, "url", "high", unquoted, "Percent-encoded (URL) text")

    # Hex — only when the bytes decode to readable text. Without this check
    # "01101000 01100101" was mis-reported as hex at high confidence.
    compact = re.sub(r"\s+", "", stripped)
    if (
        len(compact) >= 4
        and len(compact) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", compact)
        and not re.fullmatch(r"[01]+", compact)
    ):
        try:
            text = _printable_text(bytes.fromhex(compact))
            if text:
                _add(candidates, "hex", "high", text)
        except ValueError:
            pass

    # Binary — groups of eight bits.
    if re.fullmatch(r"(?:[01]{8}\s*)+", stripped):
        try:
            text = _printable_text(
                bytes(int(group, 2) for group in re.findall(r"[01]{8}", stripped))
            )
            if text:
                _add(candidates, "binary", "high", text)
        except (ValueError, UnicodeDecodeError):
            pass

    # Decimal character codes ("104 101 108 108 111").
    code_tokens = stripped.replace(",", " ").split()
    if len(code_tokens) >= 2 and all(token.isdigit() for token in code_tokens):
        numbers = [int(token) for token in code_tokens]
        if all(0 <= number <= 255 for number in numbers):
            try:
                text = _printable_text(bytes(numbers))
                if text:
                    _add(candidates, "decimal", "high", text, "Decimal character codes")
            except ValueError:
                pass

    # ROT-N — score all 25 shifts and keep the one that reads like English.
    # Scoring 25 shifts of a very large blob is wasted work; the decoders above
    # already cover bulk payloads, so only score reasonable input sizes.
    if len(stripped) <= 8192 and sum(char.isalpha() for char in stripped) >= 4:
        baseline = _english_score(stripped)
        scored = []
        for shift in range(1, 26):
            decoded = rot(stripped, shift)
            scored.append((_english_score(decoded), shift, decoded))
        scored.sort(key=lambda item: item[0], reverse=True)
        best_score, best_shift, best_text = scored[0]
        runner_up = scored[1][0] if len(scored) > 1 else 0.0
        if (
            best_score >= _ROT_MIN_SCORE
            and best_score > baseline
            and best_score >= runner_up * 1.5 + 1.0
        ):
            _add(
                candidates,
                f"rot{best_shift}",
                "medium",
                best_text,
                f"Reads as English at shift {best_shift}",
            )
        # No guess when nothing reads as English: for a payload such as
        # "grfggggggggggg" several shifts score alike, so an automatic pick
        # would be wrong more often than right. The UI lists all 25 shifts
        # instead of asserting a shift the evidence does not support.

    # Atbash — only when it produces something clearly more English.
    if (
        len(stripped) <= 8192
        and re.fullmatch(r"[A-Za-z\s]+", stripped)
        and sum(char.isalpha() for char in stripped) >= 4
    ):
        decoded = stripped.translate(_ATBASH_TABLE)
        if (
            _english_score(decoded) >= _ROT_MIN_SCORE
            and _english_score(decoded) > _english_score(stripped)
        ):
            _add(candidates, "atbash", "medium", decoded)

    # Morse.
    if re.fullmatch(r"[.\-/ ]+", stripped) and any(
        symbol in MORSE for symbol in stripped.split()
    ):
        try:
            _add(candidates, "morse", "medium", decode_morse(stripped))
        except ValueError:
            pass

    # Brainfuck.
    if stripped and set(stripped) <= BRAINFUCK_INSTRUCTIONS and len(stripped) >= 3:
        try:
            output = decode_brainfuck(stripped)
        except ValueError:
            _add(candidates, "brainfuck", "medium", None, "Program exceeded its step budget")
        else:
            if output:
                _add(candidates, "brainfuck", "high", output)

    candidates.sort(key=lambda item: _CONFIDENCE_RANK.get(item["confidence"], 3))

    if not candidates and _english_score(stripped) >= 5.0:
        _add(
            candidates,
            "plaintext",
            "low",
            None,
            "Readable text — no common encoding or cipher detected",
        )

    return {"input": value, "candidates": candidates}
