from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag


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


def identify(value: str) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    stripped = value.strip()
    try:
        decoded = decode_base64(stripped)
        if decoded["value"] and base64.b64encode(decoded["value"].encode()).decode().rstrip("=") == stripped.rstrip("="):
            candidates.append({"type": "base64", "confidence": "high", "decoded": decoded["value"]})
    except ValueError:
        pass

    for shift in range(1, 26):
        decoded = rot(value, shift)
        score = sum(word in decoded.lower().split() for word in ("the", "this", "you", "is", "hello"))
        if score:
            candidates.append({"type": f"rot{shift}", "confidence": "medium", "decoded": decoded})

    if re.fullmatch(r"[0-9a-fA-F]+(?:\s+[0-9a-fA-F]+)*", stripped) and len(stripped.replace(" ", "")) % 2 == 0:
        try:
            candidates.append({"type": "hex", "confidence": "high", "decoded": bytes.fromhex(stripped).decode()})
        except UnicodeDecodeError:
            pass

    if re.fullmatch(r"(?:[01]{8}\s*)+", stripped):
        candidates.append(
            {
                "type": "binary",
                "confidence": "high",
                "decoded": bytes(int(group, 2) for group in re.findall(r"[01]{8}", stripped)).decode(),
            }
        )

    if re.fullmatch(r"[.\-/ ]+", stripped) and any(symbol in MORSE for symbol in stripped.split()):
        try:
            candidates.append({"type": "morse", "confidence": "medium", "decoded": decode_morse(stripped)})
        except ValueError:
            pass

    if stripped and set(stripped) <= BRAINFUCK_INSTRUCTIONS and len(stripped) >= 3:
        try:
            candidates.append({"type": "brainfuck", "confidence": "high", "decoded": decode_brainfuck(stripped)})
        except ValueError:
            candidates.append({"type": "brainfuck", "confidence": "medium", "decoded": None})

    return {"input": value, "candidates": candidates}
