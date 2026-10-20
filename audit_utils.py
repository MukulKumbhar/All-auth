"""
Security Event Log Module
Integrated Cryptography, Network Security and Privacy System
Maintains an in-memory session audit trail of security operations, decisions, and outcomes.
DISCLAIMER: This is an educational session-level audit demonstration, NOT a tamper-proof write-once compliance system.
NEVER logs raw passwords, private keys, personal identifying numbers, or confidential plaintext.
"""

from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd

# Event Types
EVENT_ENCRYPT = "FILE_ENCRYPTION"
EVENT_DECRYPT = "FILE_DECRYPTION"
EVENT_KEYGEN = "KEY_GENERATION"
EVENT_SIGN = "DIGITAL_SIGNATURE"
EVENT_VERIFY = "SIGNATURE_VERIFICATION"
EVENT_MASK = "DATA_MASKING"
EVENT_RBAC = "ACCESS_CONTROL_DECISION"
EVENT_AUTH = "ROLE_CHANGE"
EVENT_SYSTEM = "SYSTEM_EVENT"

# Status Categories
STATUS_SUCCESS = "SUCCESS"
STATUS_WARNING = "WARNING"
STATUS_DENIED = "ACCESS_DENIED"
STATUS_ERROR = "FAILURE"
STATUS_INFO = "INFO"


def create_log_entry(
    event_type: str,
    status: str,
    user_role: str,
    action_summary: str,
    details: Optional[str] = None,
) -> Dict[str, str]:
    """
    Format a safe security event entry.
    Strictly sanitized: no passwords, private keys, or raw contents allowed.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "Timestamp": timestamp,
        "Role": user_role,
        "Event Type": event_type,
        "Status": status,
        "Summary": action_summary,
        "Details": details or "Operation completed normally.",
    }


def logs_to_dataframe(events: List[Dict[str, str]]) -> pd.DataFrame:
    """Convert log entries into a pandas DataFrame."""
    if not events:
        return pd.DataFrame(columns=["Timestamp", "Role", "Event Type", "Status", "Summary", "Details"])
    return pd.DataFrame(events)


def get_initial_system_events() -> List[Dict[str, str]]:
    """Seed initial events to demonstrate startup and state tracking."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        {
            "Timestamp": now,
            "Role": "System",
            "Event Type": EVENT_SYSTEM,
            "Status": STATUS_INFO,
            "Summary": "Cybersecurity Workbench Initialized",
            "Details": "Cryptographic engine loaded (AES-256-GCM, Scrypt, RSA-PSS SHA-256).",
        },
        {
            "Timestamp": now,
            "Role": "Admin",
            "Event Type": EVENT_RBAC,
            "Status": STATUS_SUCCESS,
            "Summary": "Session Security Context Established",
            "Details": "Default administrative operator role active.",
        },
    ]
