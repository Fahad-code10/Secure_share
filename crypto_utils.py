import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16   # 128-bit salt
NONCE_SIZE = 12  # 96-bit standard nonce for GCM
PBKDF2_ITERATIONS = 600_000  # OWASP standard recommendation

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit symmetric encryption key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                  # 256 bits for AES-256
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file_data(data: bytes, password: str) -> bytes:
    """
    Encrypts file data using AES-256-GCM.
    Envelope format: [Salt (16B)] + [Nonce (12B)] + [Ciphertext + Auth Tag (Variable)]
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    
    aesgcm = AESGCM(key)
    # Encrypt returns ciphertext with appended 16-byte MAC tag
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    
    return salt + nonce + ciphertext_and_tag

def decrypt_file_data(payload: bytes, password: str) -> bytes:
    """
    Extracts envelope metadata and decrypts the payload.
    Raises InvalidTag if the password is incorrect or data was tampered with.
    """
    if len(payload) < (SALT_SIZE + NONCE_SIZE + 16):
        raise ValueError("Encrypted payload is malformed or incomplete.")
    
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_and_tag = payload[SALT_SIZE + NONCE_SIZE:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # Decrypt verifies the MAC tag before returning plaintext
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)

def compute_sha256(data: bytes) -> str:
    """Calculates SHA-256 digest to verify integrity."""
    return hashlib.sha256(data).hexdigest()