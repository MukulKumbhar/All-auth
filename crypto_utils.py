"""
Cryptographic Utilities Module
Integrated Cryptography, Network Security and Privacy System
High-assurance cryptographic utilities providing AES-256-GCM authenticated encryption and RSA-2048 PSS digital signatures.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC_BYTES = b"INSC"  # 4 bytes magic
FORMAT_VERSION = 1     # 1 byte version (uint8)
SALT_SIZE = 16         # 16 bytes Scrypt salt
NONCE_SIZE = 12        # 12 bytes AES-GCM nonce


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails due to invalid password, tampering, or malformed data."""
    pass


class SignatureError(CryptoError):
    """Raised when digital signature operations fail."""
    pass


# ----------------------------------------------------------------------
# Module A: Symmetric Authenticated Encryption (AES-256-GCM + Scrypt)
# ----------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit (32-byte) key from user password using Scrypt.
    Parameters: N=2^14 (16384), r=8, p=1.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file_data(plaintext_bytes: bytes, password: str, original_filename: str = "document.bin") -> bytes:
    """
    Encrypt file data using AES-256-GCM.
    Key derived using Scrypt with fresh random 16-byte salt.
    Fresh random 12-byte nonce generated for every encryption.
    Header contains: Magic(4) + Version(1) + Salt(16) + Nonce(12) + FilenameLen(2) + FilenameBytes.
    Associated data binds header to authenticated tag.
    """
    if not password:
        raise ValueError("Password must not be empty.")
    if not isinstance(plaintext_bytes, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    filename_bytes = original_filename.encode("utf-8")
    if len(filename_bytes) > 65535:
        filename_bytes = filename_bytes[:65535]
    fn_len_bytes = len(filename_bytes).to_bytes(2, byteorder="big")

    header = MAGIC_BYTES + bytes([FORMAT_VERSION]) + salt + nonce + fn_len_bytes + filename_bytes

    aesgcm = AESGCM(key)
    # Header passed as associated_data ensures ciphertext and metadata are authenticated together
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext_bytes), header)

    return header + ciphertext


def decrypt_file_data(encrypted_payload: bytes, password: str) -> Tuple[str, bytes]:
    """
    Decrypt file payload previously encrypted with encrypt_file_data.
    Validates magic bytes, format version, and authenticates ciphertext using AES-GCM tag.
    Returns (original_filename, decrypted_plaintext_bytes).
    Raises DecryptionError on incorrect password, tampering, or malformed payload.
    """
    if not password:
        raise DecryptionError("Password cannot be empty.")
    if not isinstance(encrypted_payload, (bytes, bytearray)):
        raise DecryptionError("Encrypted payload must be bytes.")

    min_header_len = len(MAGIC_BYTES) + 1 + SALT_SIZE + NONCE_SIZE + 2
    if len(encrypted_payload) < min_header_len + 16:  # +16 for GCM auth tag
        raise DecryptionError("Malformed encrypted file: File size is smaller than valid header and tag.")

    magic = encrypted_payload[:4]
    if magic != MAGIC_BYTES:
        raise DecryptionError("Invalid file format: Missing 'INSC' magic header. Not an encrypted workbench file.")

    version = encrypted_payload[4]
    if version != FORMAT_VERSION:
        raise DecryptionError(f"Unsupported format version: {version}. Expected version {FORMAT_VERSION}.")

    offset = 5
    salt = encrypted_payload[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    nonce = encrypted_payload[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    fn_len = int.from_bytes(encrypted_payload[offset:offset + 2], byteorder="big")
    offset += 2

    if len(encrypted_payload) < offset + fn_len + 16:
        raise DecryptionError("Malformed encrypted file: Header filename length exceeds file boundary.")

    filename_bytes = encrypted_payload[offset:offset + fn_len]
    try:
        original_filename = filename_bytes.decode("utf-8")
    except UnicodeDecodeError:
        original_filename = "decrypted_file.bin"
    offset += fn_len

    header = encrypted_payload[:offset]
    ciphertext_with_tag = encrypted_payload[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, header)
        return original_filename, plaintext
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed: Incorrect password or corrupted/tampered ciphertext (authentication tag mismatch)."
        )
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")


# ----------------------------------------------------------------------
# Module B: Asymmetric Cryptography & Digital Signatures (RSA-PSS)
# ----------------------------------------------------------------------

def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a standard RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    """Export RSA public key to PEM string format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:
    """Export RSA private key to PEM string format (PKCS8 unencrypted for demonstration export)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("utf-8")


def load_public_key(pem_data: str) -> rsa.RSAPublicKey:
    """Load RSA public key from PEM string or bytes."""
    if isinstance(pem_data, str):
        data = pem_data.encode("utf-8")
    else:
        data = pem_data
    try:
        pubkey = serialization.load_pem_public_key(data)
        if not isinstance(pubkey, rsa.RSAPublicKey):
            raise SignatureError("Loaded key is not an RSA public key.")
        return pubkey
    except Exception as e:
        raise SignatureError(f"Failed to load public key: {str(e)}")


def load_private_key(pem_data: str) -> rsa.RSAPrivateKey:
    """Load RSA private key from PEM string or bytes."""
    if isinstance(pem_data, str):
        data = pem_data.encode("utf-8")
    else:
        data = pem_data
    try:
        privkey = serialization.load_pem_private_key(data, password=None)
        if not isinstance(privkey, rsa.RSAPrivateKey):
            raise SignatureError("Loaded key is not an RSA private key.")
        return privkey
    except Exception as e:
        raise SignatureError(f"Failed to load private key: {str(e)}")


def sign_data(private_key: rsa.RSAPrivateKey, data_bytes: bytes) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256 and MGF1.
    PSS padding provides provable security against existential forgery attacks.
    """
    if not isinstance(data_bytes, (bytes, bytearray)):
        raise TypeError("Data to sign must be bytes.")
    signature = private_key.sign(
        bytes(data_bytes),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key: rsa.RSAPublicKey, signature: bytes, data_bytes: bytes) -> bool:
    """
    Verify signature against data using RSA-PSS with SHA-256.
    Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            bytes(data_bytes),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def compute_sha256(data_bytes: bytes) -> str:
    """Compute SHA-256 hex digest of data bytes."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(data_bytes))
    return digest.finalize().hex()
