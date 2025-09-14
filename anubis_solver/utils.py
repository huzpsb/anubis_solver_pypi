import hashlib

def sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode("utf-8")).digest()

def bytes_to_hex(data: bytes) -> str:
    return data.hex()
