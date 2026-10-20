"""
Data Privacy and Masking Utilities
Integrated Cryptography, Network Security and Privacy System
Educational module demonstrating privacy preservation and data sanitization techniques on tabular/CSV data.
"""

import re
import pandas as pd
from typing import List, Optional


def mask_name(val: str) -> str:
    """
    Mask a full name or single name while preserving initial and general length.
    E.g. 'John Doe' -> 'J***n D*e', 'Alice' -> 'A***e'.
    """
    if pd.isna(val) or not str(val).strip():
        return ""
    val_str = str(val).strip()
    words = val_str.split()
    masked_words = []
    for w in words:
        if len(w) <= 2:
            masked_words.append(w[0] + "*")
        else:
            masked_words.append(w[0] + "*" * (len(w) - 2) + w[-1])
    return " ".join(masked_words)


def mask_email(val: str) -> str:
    """
    Mask an email address while preserving domain structure.
    E.g. 'alice.smith@university.edu' -> 'a***h@university.edu'.
    """
    if pd.isna(val) or not str(val).strip():
        return ""
    val_str = str(val).strip()
    if "@" not in val_str:
        return mask_name(val_str)

    parts = val_str.split("@", 1)
    local_part, domain = parts[0], parts[1]

    if len(local_part) <= 2:
        masked_local = local_part[0] + "***"
    else:
        masked_local = local_part[0] + "*" * (len(local_part) - 2) + local_part[-1]

    return f"{masked_local}@{domain}"


def mask_phone(val: str) -> str:
    """
    Mask a phone number preserving only the last 4 digits.
    E.g. '+1 (555) 234-5678' -> '***-***-5678', '9876543210' -> '******3210'.
    """
    if pd.isna(val) or not str(val).strip():
        return ""
    val_str = str(val).strip()
    digits = re.sub(r"\D", "", val_str)
    if len(digits) <= 4:
        return "****"
    last_four = digits[-4:]
    masked_part = "*" * (len(digits) - 4)
    return f"{masked_part}-{last_four}"


def mask_generic_id(val: str) -> str:
    """
    Mask general identifier or SSN/Aadhaar/Card number.
    E.g. '1234-5678-9012' -> '****-****-9012'.
    """
    if pd.isna(val) or not str(val).strip():
        return ""
    val_str = str(val).strip()
    if len(val_str) <= 4:
        return "*" * len(val_str)
    return "*" * (len(val_str) - 4) + val_str[-4:]


def detect_pii_columns(df: pd.DataFrame) -> dict:
    """
    Inspect DataFrame columns to detect potential PII columns.
    Returns mapping of column_name -> suggested_mask_type.
    """
    mapping = {}
    for col in df.columns:
        col_lower = str(col).lower().replace(" ", "_").replace("-", "_")
        if any(term in col_lower for term in ["email", "mail"]):
            mapping[col] = "Email"
        elif any(term in col_lower for term in ["phone", "mobile", "contact", "cell"]):
            mapping[col] = "Phone"
        elif any(term in col_lower for term in ["name", "fullname", "first_name", "last_name", "user"]):
            mapping[col] = "Name"
        elif any(term in col_lower for term in ["ssn", "card", "aadhar", "aadhaar", "id_number", "passport"]):
            mapping[col] = "ID/Card"
    return mapping


def apply_masking(df: pd.DataFrame, column_rules: dict) -> pd.DataFrame:
    """
    Apply specified masking rules to a DataFrame.
    column_rules is a dict: {column_name: mask_type}
    Supported mask_types: 'Name', 'Email', 'Phone', 'ID/Card', 'None'.
    """
    df_sanitized = df.copy()
    for col, mask_type in column_rules.items():
        if col not in df_sanitized.columns or mask_type == "None":
            continue

        if mask_type == "Name":
            df_sanitized[col] = df_sanitized[col].apply(mask_name)
        elif mask_type == "Email":
            df_sanitized[col] = df_sanitized[col].apply(mask_email)
        elif mask_type == "Phone":
            df_sanitized[col] = df_sanitized[col].apply(mask_phone)
        elif mask_type == "ID/Card":
            df_sanitized[col] = df_sanitized[col].apply(mask_generic_id)

    return df_sanitized


def get_sample_pii_dataset() -> pd.DataFrame:
    """Return a realistic sample dataset containing PII for quick demonstration."""
    data = {
        "User_ID": ["USR-101", "USR-102", "USR-103", "USR-104", "USR-105"],
        "Full_Name": ["Mukul Kumbhar", "Dr. Rajesh Sharma", "Alice Morgan", "Bob V. Henderson", "Priya Patel"],
        "Email_Address": [
            "mukul.k@cyberworkbench.org",
            "rajesh.sharma@cyberinstitute.in",
            "alice.m@securenet.io",
            "b.henderson@datacenter.net",
            "priya.p@networklabs.com",
        ],
        "Phone_Number": [
            "+91-98765-43210",
            "+91-91234-56789",
            "+1-415-555-0199",
            "+1-202-555-0143",
            "+91-99887-76655",
        ],
        "ID_Card_Number": [
            "8472-9102-3841",
            "1928-3746-5820",
            "4532-8819-2049",
            "7721-3948-1029",
            "6019-2847-5930",
        ],
        "Department": ["Security Ops", "Cryptography", "Infrastructure", "Threat Intel", "Compliance"],
        "Access_Level": ["Admin", "Analyst", "Viewer", "Analyst", "Viewer"],
    }
    return pd.DataFrame(data)
