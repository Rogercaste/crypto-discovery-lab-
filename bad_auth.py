"""
auth.py — a deliberately bad authentication module.

Used as a scanner target in Stage 1 (source scanning) of the
crypto-discovery-lab. Every cryptographic operation here is wrong in
some way. The point is that a CBOM generator should find each one.
"""

import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# PROBLEM 1: MD5 for password hashing.
# MD5 has practical collisions and is too fast for password hashing
# anyway. Should be argon2id or bcrypt.
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# PROBLEM 2: SHA-1 for anything signature-related.
# SHA-1 has demonstrated collisions (SHAttered, 2017).
def fingerprint(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# PROBLEM 3: RSA-1024 key generation.
# Below NIST's 2048-bit minimum. Also quantum-vulnerable at any size.
def generate_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )


# PROBLEM 4: RSA signing with SHA-1.
# Compounds problems 2 and 3.
def sign_token(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )


# For contrast: this is "okay" classically but still quantum-vulnerable.
# A PQC-aware scanner should still flag it.
def sign_token_modern(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


