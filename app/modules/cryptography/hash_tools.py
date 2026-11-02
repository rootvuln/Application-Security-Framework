import hashlib


def sha256_text(text: str) -> dict:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return {
        "algorithm": "SHA-256",
        "hash": digest,
        "input_type": "text",
    }