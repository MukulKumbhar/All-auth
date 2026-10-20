"""
Role-Based Access Control (RBAC) Module
Integrated Cryptography, Network Security and Privacy System
Educational simulation demonstrating authorization matrices, least-privilege principles, and role enforcement.
NOTE: This is an educational demonstration of authorization logic, not real operating-system authentication.
"""

from typing import Dict, List, Tuple

# Supported Roles
ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Analyst"
ROLE_VIEWER = "Viewer"

AVAILABLE_ROLES = [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER]

# Defined Actions
ACTION_VIEW_DASHBOARD = "VIEW_DASHBOARD"
ACTION_ENCRYPT_FILE = "ENCRYPT_FILE"
ACTION_DECRYPT_FILE = "DECRYPT_FILE"
ACTION_GENERATE_KEYS = "GENERATE_KEYS"
ACTION_SIGN_FILE = "SIGN_FILE"
ACTION_VERIFY_SIGNATURE = "VERIFY_SIGNATURE"
ACTION_MASK_DATA = "MASK_DATA"
ACTION_EXPORT_SANITIZED = "EXPORT_SANITIZED"
ACTION_VIEW_LOGS = "VIEW_LOGS"
ACTION_CLEAR_LOGS = "CLEAR_LOGS"
ACTION_CONFIG_POLICIES = "CONFIG_POLICIES"

# Human-readable labels and descriptions
ACTION_METADATA = {
    ACTION_VIEW_DASHBOARD: {
        "title": "View Security Overview",
        "description": "Inspect system status, cryptographic metrics, and architecture summaries.",
    },
    ACTION_ENCRYPT_FILE: {
        "title": "Encrypt Files (AES-256-GCM)",
        "description": "Perform symmetric encryption and key derivation on confidential files.",
    },
    ACTION_DECRYPT_FILE: {
        "title": "Decrypt Files",
        "description": "Unlock authenticated ciphertext payloads using valid credentials.",
    },
    ACTION_GENERATE_KEYS: {
        "title": "Generate RSA-2048 Master Key Pairs",
        "description": "Issue new cryptographic public/private key pairs.",
    },
    ACTION_SIGN_FILE: {
        "title": "Generate Digital Signatures (RSA-PSS)",
        "description": "Sign payloads to ensure authenticity and non-repudiation.",
    },
    ACTION_VERIFY_SIGNATURE: {
        "title": "Verify Digital Signatures",
        "description": "Validate cryptographic signatures against public keys.",
    },
    ACTION_MASK_DATA: {
        "title": "Run PII Data Masking",
        "description": "Apply privacy-preserving algorithms on datasets.",
    },
    ACTION_EXPORT_SANITIZED: {
        "title": "Download Sanitized Datasets",
        "description": "Export masked data out of the security boundary.",
    },
    ACTION_VIEW_LOGS: {
        "title": "Inspect Security Audit Logs",
        "description": "Review operational events, security incidents, and access decisions.",
    },
    ACTION_CLEAR_LOGS: {
        "title": "Purge Security Audit Logs",
        "description": "Administrative authority to truncate the active session log.",
    },
    ACTION_CONFIG_POLICIES: {
        "title": "Modify System Security Policies",
        "description": "Alter cryptographic algorithms and baseline enforcement constraints.",
    },
}

# Role Permission Matrix
PERMISSIONS_MATRIX: Dict[str, List[str]] = {
    ROLE_ADMIN: [
        ACTION_VIEW_DASHBOARD,
        ACTION_ENCRYPT_FILE,
        ACTION_DECRYPT_FILE,
        ACTION_GENERATE_KEYS,
        ACTION_SIGN_FILE,
        ACTION_VERIFY_SIGNATURE,
        ACTION_MASK_DATA,
        ACTION_EXPORT_SANITIZED,
        ACTION_VIEW_LOGS,
        ACTION_CLEAR_LOGS,
        ACTION_CONFIG_POLICIES,
    ],
    ROLE_ANALYST: [
        ACTION_VIEW_DASHBOARD,
        ACTION_DECRYPT_FILE,
        ACTION_VERIFY_SIGNATURE,
        ACTION_MASK_DATA,
        ACTION_EXPORT_SANITIZED,
        ACTION_VIEW_LOGS,
    ],
    ROLE_VIEWER: [
        ACTION_VIEW_DASHBOARD,
        ACTION_VERIFY_SIGNATURE,
        ACTION_VIEW_LOGS,
    ],
}


def check_permission(role: str, action: str) -> Tuple[bool, str]:
    """
    Check if a role has permission to execute an action.
    Returns (is_permitted, explanation_reason).
    """
    if role not in PERMISSIONS_MATRIX:
        return False, f"Unknown role '{role}'. Access denied by default."

    allowed_actions = PERMISSIONS_MATRIX.get(role, [])
    action_info = ACTION_METADATA.get(action, {"title": action})

    if action in allowed_actions:
        return True, f"Access Granted: Role '{role}' possesses the '{action}' authority."
    else:
        return False, f"Access Denied: Role '{role}' lacks permission for '{action_info['title']}' ({action}). Principle of least privilege enforced."


def get_role_summary(role: str) -> Dict[str, any]:
    """Retrieve capabilities and descriptions for a given role."""
    descriptions = {
        ROLE_ADMIN: {
            "title": "System Administrator / Security Officer",
            "scope": "Full cryptographic authority. Can issue keys, encrypt/decrypt data, sign payloads, and manage audit logs.",
            "color": "#10B981",  # Emerald
            "allowed_count": len(PERMISSIONS_MATRIX[ROLE_ADMIN]),
        },
        ROLE_ANALYST: {
            "title": "Security Analyst / Data Investigator",
            "scope": "Investigative authority. Can decrypt authorized payloads, verify signatures, sanitize datasets, and review logs, but cannot sign documents or delete audit records.",
            "color": "#3B82F6",  # Blue
            "allowed_count": len(PERMISSIONS_MATRIX[ROLE_ANALYST]),
        },
        ROLE_VIEWER: {
            "title": "Auditor / Read-Only Observer",
            "scope": "Observational authority. Restricted to viewing dashboards, verifying signatures, and inspecting security events. Cannot run cryptographic transforms.",
            "color": "#94A3B8",  # Slate
            "allowed_count": len(PERMISSIONS_MATRIX[ROLE_VIEWER]),
        },
    }
    return descriptions.get(role, {"title": role, "scope": "Custom Role", "color": "#64748B", "allowed_count": 0})
