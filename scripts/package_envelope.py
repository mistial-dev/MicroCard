"""MP05 envelope primitives; manifest and engine validation are separate."""
import hashlib

PREFIX = b"MP05MicroCard signed package v5\0"
HEADER = len(PREFIX) + 8
OVERHEAD = HEADER + 32 + 65 + 64
MAX_PACKAGE = 16384


def signing_prefix(manifest, image, key):
    if len(key) != 65 or key[0] != 4:
        raise ValueError("uncompressed SEC1 key required")
    if OVERHEAD + len(manifest) + len(image) > MAX_PACKAGE:
        raise ValueError("package exceeds quota")
    return (PREFIX + len(manifest).to_bytes(4, "little") + len(image).to_bytes(4, "little")
            + manifest + hashlib.sha256(image).digest() + key)


def create(manifest, image, key, sign):
    prefix = signing_prefix(manifest, image, key)
    signature = sign(prefix)
    if len(signature) != 64:
        raise ValueError("P1363 signature required")
    return prefix + signature + image


def verify(raw, verify_signature):
    if not OVERHEAD <= len(raw) <= MAX_PACKAGE or not raw.startswith(PREFIX):
        raise ValueError("invalid MP05 envelope")
    manifest_length = int.from_bytes(raw[len(PREFIX):len(PREFIX) + 4], "little")
    image_length = int.from_bytes(raw[len(PREFIX) + 4:HEADER], "little")
    if OVERHEAD + manifest_length + image_length != len(raw):
        raise ValueError("invalid package length")
    digest_start = HEADER + manifest_length
    key_start = digest_start + 32
    signature_start = key_start + 65
    image_start = signature_start + 64
    key = raw[key_start:signature_start]
    signature = raw[signature_start:image_start]
    order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if key[0] != 4 or not 0 < r < order or not 0 < s <= order // 2:
        raise ValueError("invalid key or signature shape")
    if not verify_signature(key, raw[:signature_start], signature):
        raise ValueError("invalid signature")
    image = raw[image_start:]
    if hashlib.sha256(image).digest() != raw[digest_start:key_start]:
        raise ValueError("image digest mismatch")
    return raw[HEADER:digest_start], image, key
