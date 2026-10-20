"""
Automated Unit Tests for Cryptography and Security Modules
Verifies:
- AES-256-GCM + Scrypt encryption & decryption round-trip
- Rejection of incorrect password (DecryptionError)
- Rejection of tampered ciphertext / header (DecryptionError)
- Rejection of malformed / short payload (DecryptionError)
- RSA-2048 PSS signature creation and verification
- Rejection of tampered signature or modified payload
- Data privacy masking utilities
- RBAC permission enforcement
"""

import pytest
import os
import sys

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto_utils import (
    encrypt_file_data,
    decrypt_file_data,
    derive_key,
    generate_rsa_key_pair,
    sign_data,
    verify_signature,
    serialize_public_key,
    load_public_key,
    compute_sha256,
    DecryptionError,
)
from masking_utils import mask_name, mask_email, mask_phone, apply_masking, get_sample_pii_dataset
from rbac_utils import check_permission, ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER, ACTION_ENCRYPT_FILE, ACTION_CLEAR_LOGS


# ----------------------------------------------------------------------
# 1. Symmetric Cryptography (AES-256-GCM + Scrypt) Tests
# ----------------------------------------------------------------------

def test_encryption_decryption_roundtrip():
    """Verify that file data encrypted with a password decrypts cleanly to original."""
    original_data = b"Confidential High-Security Operations Payload 2026! @#$%"
    filename = "report.pdf"
    password = "SuperStrongPassword123!"

    encrypted = encrypt_file_data(original_data, password, filename)

    assert encrypted != original_data
    assert encrypted.startswith(b"INSC")

    recovered_fn, decrypted = decrypt_file_data(encrypted, password)
    assert recovered_fn == filename
    assert decrypted == original_data


def test_decryption_with_incorrect_password():
    """Verify that attempting decryption with an incorrect password fails securely."""
    original_data = b"Top secret classified data bytes."
    password = "CorrectPassword123"
    wrong_password = "WrongPassword456"

    encrypted = encrypt_file_data(original_data, password)

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file_data(encrypted, wrong_password)
    assert "Decryption failed" in str(exc_info.value)


def test_ciphertext_tampering_detection():
    """Verify that tampering with ciphertext triggers AES-GCM authentication failure."""
    original_data = b"Financial transaction: transfer $1,000,000 to Alice."
    password = "AuditSecurePassword999"

    encrypted = bytearray(encrypt_file_data(original_data, password))

    # Tamper with the last byte of ciphertext/tag
    encrypted[-1] ^= 0xFF

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_file_data(bytes(encrypted), password)
    assert "tag mismatch" in str(exc_info.value).lower() or "failed" in str(exc_info.value).lower()


def test_header_tampering_detection():
    """Verify that tampering with metadata header (bound via associated data) fails decryption."""
    original_data = b"Healthcare confidential telemetry"
    password = "MedicalKey2026"

    encrypted = bytearray(encrypt_file_data(original_data, password))

    # Tamper with the salt or nonce byte inside header
    encrypted[10] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_file_data(bytes(encrypted), password)


def test_malformed_payload_rejection():
    """Verify that truncated or non-workbench files are rejected immediately."""
    with pytest.raises(DecryptionError) as exc1:
        decrypt_file_data(b"too_short", "pass")
    assert "smaller than valid header" in str(exc1.value)

    with pytest.raises(DecryptionError) as exc2:
        decrypt_file_data(b"FAKE_RANDOM_LONG_STRING_WITHOUT_MAGIC_HEADER_BYTES_1234567890", "pass")
    assert "Missing 'INSC' magic header" in str(exc2.value)


def test_empty_password_rejection():
    """Verify that empty passwords are not permitted."""
    with pytest.raises(ValueError):
        encrypt_file_data(b"Sample data", "")

    with pytest.raises(DecryptionError):
        decrypt_file_data(b"INSC" + b"\x00" * 40, "")


# ----------------------------------------------------------------------
# 2. Asymmetric Cryptography (RSA-PSS) Tests
# ----------------------------------------------------------------------

def test_rsa_signature_generation_and_verification():
    """Verify digital signature creation and successful verification."""
    privkey, pubkey = generate_rsa_key_pair(2048)
    document = b"Enterprise Security Protocol Dispatch Authorization Token 2026."

    sig = sign_data(privkey, document)
    assert len(sig) == 256  # 2048 bits / 8 = 256 bytes

    is_valid = verify_signature(pubkey, sig, document)
    assert is_valid is True


def test_rsa_tampered_document_rejection():
    """Verify that any modification to signed document invalidates the signature."""
    privkey, pubkey = generate_rsa_key_pair(2048)
    original_doc = b"Authorized Payment: $500.00"
    tampered_doc = b"Authorized Payment: $5,000,000.00"

    sig = sign_data(privkey, original_doc)
    is_valid = verify_signature(pubkey, sig, tampered_doc)
    assert is_valid is False


def test_rsa_key_serialization():
    """Verify PEM export and import round-trip."""
    privkey, pubkey = generate_rsa_key_pair(2048)
    pub_pem = serialize_public_key(pubkey)
    assert "-----BEGIN PUBLIC KEY-----" in pub_pem

    reloaded_pubkey = load_public_key(pub_pem)
    doc = b"Test roundtrip message"
    sig = sign_data(privkey, doc)
    assert verify_signature(reloaded_pubkey, sig, doc) is True


# ----------------------------------------------------------------------
# 3. Privacy Masking Tests
# ----------------------------------------------------------------------

def test_privacy_masking_functions():
    """Verify individual masking functions."""
    assert mask_name("Mukul Kumbhar") == "M***l K*****r"
    assert mask_email("mukul.k@cyberworkbench.org") == "m*****k@cyberworkbench.org"
    phone_masked = mask_phone("9876543210")
    assert phone_masked.endswith("3210")
    assert "******" in phone_masked


def test_dataframe_masking_integration():
    """Verify batch masking on DataFrame."""
    df = get_sample_pii_dataset()
    rules = {
        "Full_Name": "Name",
        "Email_Address": "Email",
        "Phone_Number": "Phone",
        "ID_Card_Number": "ID/Card",
    }
    sanitized = apply_masking(df, rules)

    assert "@" in sanitized["Email_Address"].iloc[0]
    assert "*" in sanitized["Email_Address"].iloc[0]
    assert "*" in sanitized["Full_Name"].iloc[0]
    assert sanitized["User_ID"].iloc[0] == df["User_ID"].iloc[0]  # Unmasked column untouched


# ----------------------------------------------------------------------
# 4. RBAC Tests
# ----------------------------------------------------------------------

def test_rbac_permission_enforcement():
    """Verify role permission policies."""
    # Admin can do everything
    admin_can_encrypt, _ = check_permission(ROLE_ADMIN, ACTION_ENCRYPT_FILE)
    admin_can_clear, _ = check_permission(ROLE_ADMIN, ACTION_CLEAR_LOGS)
    assert admin_can_encrypt is True
    assert admin_can_clear is True

    # Analyst can decrypt and mask, but cannot clear logs
    analyst_can_clear, _ = check_permission(ROLE_ANALYST, ACTION_CLEAR_LOGS)
    assert analyst_can_clear is False

    # Viewer cannot encrypt files
    viewer_can_encrypt, reason = check_permission(ROLE_VIEWER, ACTION_ENCRYPT_FILE)
    assert viewer_can_encrypt is False
    assert "Access Denied" in reason
