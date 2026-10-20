"""
Integrated Cryptography, Network Security and Privacy System
High-Assurance Cryptographic Suite demonstrating Authenticated Encryption,
Digital Signatures, Data Privacy Masking, Role-Based Access Control, and Security Logging.

Author: Mukul Kumbhar
Repository: https://github.com/MukulKumbhar/All-auth
"""

import streamlit as st
import pandas as pd
import io
import os
from datetime import datetime

# Import modular helper utilities
from crypto_utils import (
    encrypt_file_data,
    decrypt_file_data,
    generate_rsa_key_pair,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    sign_data,
    verify_signature,
    compute_sha256,
    DecryptionError,
    SignatureError,
)
from masking_utils import (
    apply_masking,
    detect_pii_columns,
    get_sample_pii_dataset,
    mask_name,
    mask_email,
    mask_phone,
    mask_generic_id,
)
from rbac_utils import (
    AVAILABLE_ROLES,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    PERMISSIONS_MATRIX,
    ACTION_METADATA,
    check_permission,
    get_role_summary,
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
)
from audit_utils import (
    create_log_entry,
    logs_to_dataframe,
    get_initial_system_events,
    EVENT_ENCRYPT,
    EVENT_DECRYPT,
    EVENT_KEYGEN,
    EVENT_SIGN,
    EVENT_VERIFY,
    EVENT_MASK,
    EVENT_RBAC,
    EVENT_AUTH,
    STATUS_SUCCESS,
    STATUS_WARNING,
    STATUS_DENIED,
    STATUS_ERROR,
    STATUS_INFO,
)

# ----------------------------------------------------------------------
# Page Configuration & Dark Cybersecurity Theme
# ----------------------------------------------------------------------

st.set_page_config(
    page_title="INS Cybersecurity Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject refined CSS for a dark navy cybersecurity dashboard
st.markdown(
    """
    <style>
    /* Global Background & Typography */
    .stApp {
        background-color: #0b1120;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Top Header Banner */
    .ins-banner {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0369a1 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 24px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .ins-banner h1 {
        color: #38bdf8;
        font-size: 1.85rem;
        font-weight: 700;
        margin: 0 0 8px 0;
        letter-spacing: -0.5px;
    }
    .ins-banner p {
        color: #cbd5e1;
        font-size: 0.95rem;
        margin: 0;
        line-height: 1.5;
    }
    
    /* Security Metric & Status Cards */
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 16px;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: #38bdf8;
        transform: translateY(-2px);
    }
    .metric-title {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #94a3b8;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 1.35rem;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Badges */
    .badge-success {
        display: inline-block;
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #059669;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-warning {
        display: inline-block;
        background-color: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #d97706;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-danger {
        display: inline-block;
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #dc2626;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-info {
        display: inline-block;
        background-color: rgba(56, 189, 248, 0.2);
        color: #38bdf8;
        border: 1px solid #0284c7;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }

    /* Educational Disclaimer Callout */
    .disclaimer-box {
        background-color: rgba(15, 23, 42, 0.75);
        border-left: 4px solid #38bdf8;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        font-size: 0.82rem;
        color: #94a3b8;
        margin-top: 20px;
    }

    /* Code & Output Blocks */
    code {
        color: #38bdf8 !important;
        background-color: #0f172a !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------
# Session State Initialization
# ----------------------------------------------------------------------

if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = get_initial_system_events()

if "current_role" not in st.session_state:
    st.session_state.current_role = ROLE_ADMIN

if "rsa_key_pair" not in st.session_state:
    # Initialize RSA-2048 key pair in session memory
    priv, pub = generate_rsa_key_pair(2048)
    st.session_state.rsa_key_pair = (priv, pub)
    st.session_state.rsa_public_pem = serialize_public_key(pub)

if "last_signature" not in st.session_state:
    st.session_state.last_signature = None

if "last_signed_data" not in st.session_state:
    st.session_state.last_signed_data = None


def log_event(event_type: str, status: str, summary: str, details: str = None):
    """Helper to append a safe log entry into session state."""
    entry = create_log_entry(
        event_type=event_type,
        status=status,
        user_role=st.session_state.current_role,
        action_summary=summary,
        details=details,
    )
    st.session_state.audit_logs.append(entry)


# ----------------------------------------------------------------------
# Sidebar Navigation & Context
# ----------------------------------------------------------------------

with st.sidebar:
    st.markdown("### 🛡️ Cryptographic Suite")
    st.markdown("**Enterprise Security & Privacy Platform**")
    st.caption("Engineered by Mukul Kumbhar")
    st.divider()

    # Active RBAC Role Selector
    st.markdown("#### 👤 Active Operator Role")
    selected_role = st.selectbox(
        "Select Security Role:",
        AVAILABLE_ROLES,
        index=AVAILABLE_ROLES.index(st.session_state.current_role),
        help="Toggle active RBAC identity to inspect authorization policy enforcement.",
    )
    if selected_role != st.session_state.current_role:
        old_role = st.session_state.current_role
        st.session_state.current_role = selected_role
        log_event(
            EVENT_AUTH,
            STATUS_INFO,
            f"Active Role Switched to {selected_role}",
            f"Security context transitioned from {old_role} to {selected_role}.",
        )
        st.rerun()

    role_info = get_role_summary(st.session_state.current_role)
    st.markdown(
        f"""
        <div style="background-color: #1e293b; border-left: 4px solid {role_info['color']}; padding: 8px 12px; border-radius: 4px; font-size: 0.8rem; margin-bottom: 16px;">
            <strong>{role_info['title']}</strong><br/>
            <span style="color: #94a3b8;">Permitted Actions: {role_info['allowed_count']} / {len(ACTION_METADATA)}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    # Navigation Menu
    menu_choice = st.radio(
        "Select Workbench Module:",
        [
            "Overview & Architecture",
            "Module A: File Encryption (AES-GCM)",
            "Module B: Digital Signatures (RSA-PSS)",
            "Module C: Privacy Protection (CSV)",
            "Module D: Access Control (RBAC)",
            "Module E: Security Event Log",
        ],
        index=0,
    )

    st.divider()

    # System Status Indicators
    st.markdown("#### ⚡ Security Telemetry")
    st.markdown(
        """
        - **Cipher**: `AES-256-GCM` (AEAD)
        - **KDF**: `Scrypt` (N=16384, r=8, p=1)
        - **Signatures**: `RSA-2048 PSS`
        - **Hash**: `SHA-256`
        - **Logs Recorded**: `{}`
        """.format(len(st.session_state.audit_logs))
    )


# ----------------------------------------------------------------------
# Top Header Banner
# ----------------------------------------------------------------------

st.markdown(
    """
    <div class="ins-banner">
        <h1>Integrated Cryptography, Network Security & Privacy Suite</h1>
        <p>A unified high-assurance cybersecurity platform providing authenticated data encryption, asymmetric digital signatures,
        automated PII sanitization, role-based access authorization, and centralized security telemetry.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ======================================================================
# MODULE F: Overview & Architecture
# ======================================================================
if menu_choice == "Overview & Architecture":
    st.subheader("🏛️ System Architecture & Cryptographic Standards")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Encryption Standard</div>
                <div class="metric-value">AES-256-GCM</div>
                <div class="metric-sub">NIST SP 800-38D AEAD</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Key Derivation</div>
                <div class="metric-value">Scrypt KDF</div>
                <div class="metric-sub">RFC 7914 Memory-Hard</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Digital Signature</div>
                <div class="metric-value">RSA-2048 PSS</div>
                <div class="metric-sub">FIPS 186-4 / MGF1 SHA-256</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-title">Security Events</div>
                <div class="metric-value">{} Logged</div>
                <div class="metric-sub">Active Telemetry Trail</div>
            </div>
            """.format(len(st.session_state.audit_logs)),
            unsafe_allow_html=True,
        )

    st.markdown("### 🧩 Core Subsystem Architecture")

    arch_col1, arch_col2 = st.columns([1.2, 0.8])
    with arch_col1:
        st.markdown(
            """
            | Subsystem | Primary Primitives | Security Objective | Cryptographic Specification |
            | :--- | :--- | :--- | :--- |
            | **Authenticated Storage** | AES-256-GCM + Scrypt | Confidentiality & Authenticity | 256-bit Key, 12-byte Nonce, 16-byte GCM Tag |
            | **Identity & Integrity** | RSA-2048 + SHA-256 | Authenticity & Non-Repudiation | PSS Padding, MGF1 Masking, Asymmetric Pairs |
            | **Privacy Engineering** | Regex / Pandas | Data Minimization (DPDP/GDPR) | Dynamic PII Redaction (Names, Emails, Phones, IDs) |
            | **Access Enforcement** | Authorization Matrix | Least Privilege (PoLP) | Multi-Role Access Control (Admin, Analyst, Viewer) |
            | **Telemetry & Audit** | In-Memory Buffer | Traceability & Forensic Audit | Sanitized Event Stream (Zero Secret Retention) |
            """
        )

        st.markdown("### 🛡️ Threat Resistance & Cryptographic Controls")
        with st.expander("🔐 Authenticated Confidentiality (AES-256-GCM vs CBC)", expanded=True):
            st.markdown(
                """
                - **Standards Compliance**: NIST SP 800-38D (Galois/Counter Mode).
                - **Attack Mitigation**: Eliminates padding oracle vulnerabilities and bit-flipping integrity tampering common in CBC and ECB modes.
                - **AEAD Mechanism**: Computes a 128-bit authentication tag concurrently with encryption, cryptographically binding ciphertext and metadata headers.
                """
            )
        with st.expander("⚡ Memory-Hard Key Derivation (Scrypt KDF vs Fast Hashes)"):
            st.markdown(
                """
                - **Standards Compliance**: RFC 7914 (Password-Based Key Derivation).
                - **Attack Mitigation**: Defeats massive GPU and ASIC-accelerated rainbow-table and parallel dictionary brute-force attacks.
                - **Configuration**: Uses $N=16384$, $r=8$, $p=1$ with fresh 128-bit cryptographic salts per operation.
                """
            )
        with st.expander("✍️ Non-Repudiation & Signature Security (RSA-PSS vs PKCS#1 v1.5)"):
            st.markdown(
                """
                - **Standards Compliance**: FIPS 186-4 & PKCS#1 v2.2.
                - **Attack Mitigation**: Provably immune to Bleichenbacher chosen-ciphertext attacks and existential forgery.
                - **Design**: Probabilistic Signature Scheme (PSS) injects randomized salt during signing, ensuring distinct signatures for identical inputs.
                """
            )

    with arch_col2:
        st.markdown("### 📦 Encrypted Container Structure (`.insc`)")
        st.markdown(
            """
            Files encrypted by the platform adhere to a standardized binary container layout:
            ```text
            +----------------------------------+
            | Magic Bytes: "INSC" (4 Bytes)   |
            +----------------------------------+
            | Format Version: 0x01 (1 Byte)   |
            +----------------------------------+
            | Scrypt Salt: (16 Bytes)          |
            +----------------------------------+
            | AES-GCM Nonce: (12 Bytes)        |
            +----------------------------------+
            | Filename Length: uint16 (2 Bytes)|
            +----------------------------------+
            | Original Filename (UTF-8 Bytes)  |
            +----------------------------------+
            | Ciphertext + GCM Tag (16 Bytes)  |
            +----------------------------------+
            ```
            > **Tamper Proofing**: The header fields are bound to the AES-GCM Associated Data stream. Any external alteration causes instant decryption failure.
            """
        )

    st.markdown(
        """
        <div class="disclaimer-box">
            <strong>🛡️ High-Assurance Operational Posture:</strong>
            Cryptographic primitives execute locally utilizing libcrypto-backed C implementations via pyca/cryptography.
            Strict zero-retention policy enforced: raw keys, passphrases, and decrypted plaintexts remain in volatile memory and are never persisted to disk or logs.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ======================================================================
# MODULE A: File Encryption and Decryption (AES-256-GCM + Scrypt)
# ======================================================================
elif menu_choice == "Module A: File Encryption (AES-GCM)":
    st.subheader("🔒 Module A — File Encryption & Decryption (AES-256-GCM)")
    st.caption("Authenticated Encryption with Associated Data (AEAD) + Salted Scrypt Key Derivation")

    # Check RBAC
    is_admin = st.session_state.current_role == ROLE_ADMIN
    is_analyst = st.session_state.current_role == ROLE_ANALYST

    enc_tab, dec_tab = st.tabs(["🔐 Encrypt File / Document", "🔓 Decrypt Workbench File"])

    # --- TAB 1: ENCRYPT ---
    with enc_tab:
        can_enc, enc_reason = check_permission(st.session_state.current_role, ACTION_ENCRYPT_FILE)
        if not can_enc:
            st.warning(f"🚫 {enc_reason}")
            st.info("💡 Switch active role to **Admin** in the sidebar to test file encryption.")
        else:
            st.markdown("Upload any document or file to encrypt it into a secure, tamper-evident `.insc` container.")

            col_up, col_param = st.columns([1.2, 0.8])
            with col_up:
                uploaded_file = st.file_uploader(
                    "Choose file to encrypt:",
                    type=None,
                    key="enc_uploader",
                    help="Accepts any file format (PDF, TXT, DOCX, PNG, CSV, etc.)",
                )
                quick_text = st.text_area(
                    "Or write sample confidential text directly:",
                    value="Confidential INS Project Data: AES-GCM guarantees privacy and authenticity.",
                    height=80,
                    key="enc_quick_text",
                )

            with col_param:
                enc_password = st.text_input(
                    "Encryption Password:",
                    type="password",
                    placeholder="Enter secret passphrase",
                    key="enc_pwd",
                )
                st.caption("🔒 Key will be derived using **Scrypt** with a fresh 16-byte random salt.")
                st.caption("⚡ Nonce: Fresh 12-byte random cryptographic vector per run.")

            if st.button("🔒 Encrypt and Authenticate", type="primary", use_container_width=True):
                if not enc_password:
                    st.error("Please enter a valid encryption password.")
                else:
                    if uploaded_file is not None:
                        plaintext_bytes = uploaded_file.getvalue()
                        original_name = uploaded_file.name
                    else:
                        plaintext_bytes = quick_text.encode("utf-8")
                        original_name = "secret_notes.txt"

                    try:
                        encrypted_payload = encrypt_file_data(plaintext_bytes, enc_password, original_name)
                        orig_hash = compute_sha256(plaintext_bytes)
                        enc_hash = compute_sha256(encrypted_payload)

                        log_event(
                            EVENT_ENCRYPT,
                            STATUS_SUCCESS,
                            f"File '{original_name}' encrypted successfully",
                            f"Plaintext size: {len(plaintext_bytes)}B, Ciphertext: {len(encrypted_payload)}B, SHA-256: {orig_hash[:16]}...",
                        )

                        st.success(f"✅ Successfully encrypted `{original_name}` with AES-256-GCM!")

                        res_c1, res_c2, res_c3 = st.columns(3)
                        res_c1.metric("Original Size", f"{len(plaintext_bytes)} bytes")
                        res_c2.metric("Encrypted Size", f"{len(encrypted_payload)} bytes")
                        res_c3.metric("Authentication Tag", "16 Bytes (GCM)")

                        st.code(
                            f"Original SHA-256 Digest : {orig_hash}\nEncrypted SHA-256 Digest: {enc_hash}",
                            language="text",
                        )

                        download_name = f"{original_name}.insc"
                        st.download_button(
                            label=f"⬇️ Download Encrypted File ({download_name})",
                            data=encrypted_payload,
                            file_name=download_name,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except Exception as e:
                        log_event(EVENT_ENCRYPT, STATUS_ERROR, f"Encryption failed for {original_name}", str(e))
                        st.error(f"Encryption failed: {str(e)}")

    # --- TAB 2: DECRYPT ---
    with dec_tab:
        can_dec, dec_reason = check_permission(st.session_state.current_role, ACTION_DECRYPT_FILE)
        if not can_dec:
            st.warning(f"🚫 {dec_reason}")
            st.info("💡 Switch active role to **Admin** or **Analyst** in the sidebar to test file decryption.")
        else:
            st.markdown("Upload a `.insc` encrypted container and provide the passphrase.")

            dec_file = st.file_uploader(
                "Upload encrypted `.insc` file:",
                type=["insc", "enc", "bin"],
                key="dec_uploader",
            )
            dec_password = st.text_input(
                "Enter Decryption Password:",
                type="password",
                placeholder="Enter passphrase used during encryption",
                key="dec_pwd",
            )

            if st.button("🔓 Decrypt & Verify Integrity", type="primary", use_container_width=True):
                if not dec_file:
                    st.error("Please upload an encrypted file first.")
                elif not dec_password:
                    st.error("Please enter the decryption password.")
                else:
                    payload_bytes = dec_file.getvalue()
                    try:
                        recovered_filename, decrypted_bytes = decrypt_file_data(payload_bytes, dec_password)
                        dec_hash = compute_sha256(decrypted_bytes)

                        log_event(
                            EVENT_DECRYPT,
                            STATUS_SUCCESS,
                            f"File '{recovered_filename}' decrypted successfully",
                            f"Integrity confirmed. Decrypted {len(decrypted_bytes)} bytes. SHA-256: {dec_hash[:16]}...",
                        )

                        st.success(f"✅ Decryption and Authenticity Check Succeeded for `{recovered_filename}`!")

                        d_c1, d_c2 = st.columns(2)
                        d_c1.metric("Recovered Filename", recovered_filename)
                        d_c2.metric("Decrypted Size", f"{len(decrypted_bytes)} bytes")
                        st.code(f"Decrypted SHA-256 Digest: {dec_hash}", language="text")

                        # Text preview if applicable
                        try:
                            text_preview = decrypted_bytes.decode("utf-8")
                            st.markdown("**Decrypted Plaintext Preview:**")
                            st.text_area("Decrypted Content", value=text_preview, height=120, disabled=True)
                        except UnicodeDecodeError:
                            st.info("Binary payload decrypted successfully. Ready for download.")

                        st.download_button(
                            label=f"⬇️ Download Decrypted File ({recovered_filename})",
                            data=decrypted_bytes,
                            file_name=recovered_filename,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except DecryptionError as de:
                        log_event(
                            EVENT_DECRYPT,
                            STATUS_ERROR,
                            f"Decryption failed for {dec_file.name}",
                            str(de),
                        )
                        st.error(f"❌ {str(de)}")
                        st.caption(
                            "🛡️ Security Note: AES-GCM tags reject any wrong password or modified ciphertext bit without revealing plaintext."
                        )


# ======================================================================
# MODULE B: Digital Signatures (RSA-2048 PSS + SHA-256)
# ======================================================================
elif menu_choice == "Module B: Digital Signatures (RSA-PSS)":
    st.subheader("✍️ Module B — Asymmetric Cryptography & Digital Signatures")
    st.caption("RSA-2048 Key Pairs, PSS (Probabilistic Signature Scheme) Padding, and SHA-256 Message Digests")

    sig_tab1, sig_tab2, sig_tab3 = st.tabs(
        ["🔑 Master Key Management", "🖋️ Sign File or Message", "🔍 Verify Digital Signature"]
    )

    # --- TAB 1: KEYS ---
    with sig_tab1:
        st.markdown("### Active RSA-2048 Public Key")
        st.caption("Public keys can be freely distributed to verify digital signatures.")

        st.text_area("RSA Public Key (PEM Format)", value=st.session_state.rsa_public_pem, height=180, disabled=True)

        k_col1, k_col2 = st.columns(2)
        with k_col1:
            st.download_button(
                label="⬇️ Download Public Key (`public_key.pem`)",
                data=st.session_state.rsa_public_pem,
                file_name="public_key.pem",
                mime="application/x-pem-file",
                use_container_width=True,
            )
        with k_col2:
            can_keygen, keygen_reason = check_permission(st.session_state.current_role, ACTION_GENERATE_KEYS)
            if st.button("🔄 Generate Fresh RSA-2048 Key Pair", use_container_width=True, disabled=not can_keygen):
                priv, pub = generate_rsa_key_pair(2048)
                st.session_state.rsa_key_pair = (priv, pub)
                st.session_state.rsa_public_pem = serialize_public_key(pub)
                log_event(
                    EVENT_KEYGEN,
                    STATUS_SUCCESS,
                    "New RSA-2048 Master Key Pair Generated",
                    "Public exponent: 65537, Key size: 2048 bits.",
                )
                st.success("New RSA-2048 key pair generated successfully!")
                st.rerun()
            if not can_keygen:
                st.caption(f"🔒 {keygen_reason}")

        st.info("🛡️ Security Policy: The private signing key is stored in volatile session memory and is never logged.")

    # --- TAB 2: SIGN ---
    with sig_tab2:
        can_sign, sign_reason = check_permission(st.session_state.current_role, ACTION_SIGN_FILE)
        if not can_sign:
            st.warning(f"🚫 {sign_reason}")
            st.info("💡 Switch active role to **Admin** in the sidebar to generate digital signatures.")
        else:
            st.markdown("Sign any document using the session RSA-2048 private key with RSA-PSS padding.")

            sign_file = st.file_uploader("Upload file to sign:", type=None, key="sign_uploader")
            sign_text = st.text_area(
                "Or sign direct message text:",
                value="AUTHENTICATED TRANSACTION DISPATCH #94820-SECURE-PAYLOAD. TIMESTAMP: 2026-10-20. INTEGRITY: VERIFIED.",
                height=70,
                key="sign_text",
            )

            if st.button("🖋️ Generate RSA-PSS Signature", type="primary", use_container_width=True):
                if sign_file is not None:
                    data_to_sign = sign_file.getvalue()
                    target_name = sign_file.name
                else:
                    data_to_sign = sign_text.encode("utf-8")
                    target_name = "statement.txt"

                privkey, _ = st.session_state.rsa_key_pair
                signature_bytes = sign_data(privkey, data_to_sign)
                digest = compute_sha256(data_to_sign)

                st.session_state.last_signature = signature_bytes
                st.session_state.last_signed_data = data_to_sign

                log_event(
                    EVENT_SIGN,
                    STATUS_SUCCESS,
                    f"Digital signature generated for '{target_name}'",
                    f"Payload size: {len(data_to_sign)}B, Signature: {len(signature_bytes)}B, SHA-256: {digest[:16]}...",
                )

                st.success(f"✅ Digital signature generated for `{target_name}`!")

                s_c1, s_c2 = st.columns(2)
                s_c1.metric("Signature Length", f"{len(signature_bytes)} bytes (2048 bits)")
                s_c2.metric("Padding Scheme", "RSA-PSS (Salt: Max)")

                st.code(
                    f"Message SHA-256 Digest: {digest}\nSignature (Hex Preview): {signature_bytes.hex()[:128]}...",
                    language="text",
                )

                st.download_button(
                    label=f"⬇️ Download Signature File (`{target_name}.sig`)",
                    data=signature_bytes,
                    file_name=f"{target_name}.sig",
                    mime="application/octet-stream",
                    use_container_width=True,
                )

    # --- TAB 3: VERIFY ---
    with sig_tab3:
        can_verify, verify_reason = check_permission(st.session_state.current_role, ACTION_VERIFY_SIGNATURE)
        if not can_verify:
            st.warning(f"🚫 {verify_reason}")
        else:
            st.markdown("Validate a digital signature against the original data and the signer's public key.")

            v_col1, v_col2 = st.columns(2)
            with v_col1:
                v_data_file = st.file_uploader("Upload original document:", type=None, key="verify_data_uploader")
                v_text_fallback = st.text_input(
                    "Or verify recent session payload:",
                    value="AUTHENTICATED TRANSACTION DISPATCH #94820-SECURE-PAYLOAD. TIMESTAMP: 2026-10-20. INTEGRITY: VERIFIED."
                    if st.session_state.last_signed_data
                    else "",
                )
            with v_col2:
                v_sig_file = st.file_uploader("Upload `.sig` signature file:", type=["sig", "bin"], key="verify_sig_uploader")
                use_session_sig = st.checkbox(
                    "Use signature generated in active session",
                    value=st.session_state.last_signature is not None,
                )

            custom_pub_key = st.text_area(
                "Signer's Public Key PEM (Leave blank to use session key):",
                value="",
                placeholder="-----BEGIN PUBLIC KEY-----\n...",
                height=100,
            )

            # Interactive Tamper Demonstration Button
            st.markdown("#### 🧪 Test Signature Verification")
            b_col1, b_col2 = st.columns(2)
            run_verify = b_col1.button("🔍 Verify Signature Authenticity", type="primary", use_container_width=True)
            run_tamper_test = b_col2.button("💥 Test Tampering Attack (Simulate 1-byte alteration)", use_container_width=True)

            if run_verify or run_tamper_test:
                # Resolve data
                if v_data_file is not None:
                    doc_bytes = v_data_file.getvalue()
                elif v_text_fallback:
                    doc_bytes = v_text_fallback.encode("utf-8")
                elif st.session_state.last_signed_data is not None:
                    doc_bytes = st.session_state.last_signed_data
                else:
                    st.error("Please supply the original document or text.")
                    doc_bytes = None

                # Resolve signature
                if v_sig_file is not None:
                    sig_bytes = v_sig_file.getvalue()
                elif use_session_sig and st.session_state.last_signature:
                    sig_bytes = st.session_state.last_signature
                else:
                    st.error("Please upload or generate a signature.")
                    sig_bytes = None

                # If tamper attack test is requested:
                if run_tamper_test and doc_bytes is not None:
                    # Alter 1 byte
                    doc_bytes = bytearray(doc_bytes)
                    if len(doc_bytes) > 0:
                        doc_bytes[0] ^= 0x01
                    doc_bytes = bytes(doc_bytes)
                    st.warning("⚠️ SIMULATED TAMPERING: Modified 1 byte of the original document payload before verification.")

                if doc_bytes is not None and sig_bytes is not None:
                    try:
                        if custom_pub_key.strip():
                            pubkey = load_public_key(custom_pub_key)
                        else:
                            _, pubkey = st.session_state.rsa_key_pair

                        is_valid = verify_signature(pubkey, sig_bytes, doc_bytes)

                        if is_valid:
                            log_event(
                                EVENT_VERIFY,
                                STATUS_SUCCESS,
                                "Signature Verification Passed",
                                f"RSA-PSS SHA-256 signature matched document hash {compute_sha256(doc_bytes)[:16]}...",
                            )
                            st.success("✅ VALID SIGNATURE: Document is authentic and unmodified (Non-Repudiation Confirmed).")
                        else:
                            log_event(
                                EVENT_VERIFY,
                                STATUS_WARNING,
                                "Signature Verification Failed",
                                "Document has been modified or signature was forged.",
                            )
                            st.error(
                                "❌ INVALID SIGNATURE: Cryptographic verification failed! The document has been tampered with or signed with an incompatible key."
                            )
                    except Exception as e:
                        log_event(EVENT_VERIFY, STATUS_ERROR, "Verification error", str(e))
                        st.error(f"Verification error: {str(e)}")


# ======================================================================
# MODULE C: Privacy Protection & Data Masking (CSV)
# ======================================================================
elif menu_choice == "Module C: Privacy Protection (CSV)":
    st.subheader("🕵️ Module C — Privacy Protection & PII Data Masking")
    st.caption("Data Minimization, Pseudonymization, and Redaction on Structured CSV Datasets")

    can_mask, mask_reason = check_permission(st.session_state.current_role, ACTION_MASK_DATA)
    if not can_mask:
        st.warning(f"🚫 {mask_reason}")
        st.info("💡 Switch active role to **Admin** or **Analyst** in the sidebar to run data privacy operations.")
    else:
        st.markdown(
            "Upload any CSV file or load our built-in sample PII dataset to demonstrate real-time column-level masking."
        )

        c_up1, c_up2 = st.columns([1.2, 0.8])
        with c_up1:
            uploaded_csv = st.file_uploader("Upload CSV file for sanitization:", type=["csv"], key="csv_uploader")
        with c_up2:
            st.markdown("<br/>", unsafe_allow_html=True)
            use_sample = st.button("📋 Load Sample PII Dataset", use_container_width=True)

        if "active_df" not in st.session_state or use_sample:
            if use_sample or "active_df" not in st.session_state:
                st.session_state.active_df = get_sample_pii_dataset()
                st.session_state.active_df_name = "sample_pii_records.csv"

        if uploaded_csv is not None:
            try:
                st.session_state.active_df = pd.read_csv(uploaded_csv)
                st.session_state.active_df_name = uploaded_csv.name
            except Exception as e:
                st.error(f"Failed to read CSV: {e}")

        current_df = st.session_state.get("active_df", None)

        if current_df is not None:
            st.markdown(f"**Dataset Preview:** `{st.session_state.get('active_df_name', 'Dataset')}` ({len(current_df)} rows, {len(current_df.columns)} columns)")
            st.dataframe(current_df, use_container_width=True)

            st.markdown("### 🛠️ Configure Column Masking Rules")
            detected = detect_pii_columns(current_df)

            rules = {}
            col_splits = st.columns(min(len(current_df.columns), 4))
            for idx, col in enumerate(current_df.columns):
                with col_splits[idx % len(col_splits)]:
                    default_type = detected.get(col, "None")
                    options = ["None", "Name", "Email", "Phone", "ID/Card"]
                    chosen = st.selectbox(
                        f"Column: {col}",
                        options=options,
                        index=options.index(default_type) if default_type in options else 0,
                        key=f"mask_rule_{col}",
                    )
                    rules[col] = chosen

            if st.button("🛡️ Apply Privacy Masking", type="primary", use_container_width=True):
                sanitized_df = apply_masking(current_df, rules)
                st.session_state.sanitized_df = sanitized_df

                masked_cols = [c for c, r in rules.items() if r != "None"]
                log_event(
                    EVENT_MASK,
                    STATUS_SUCCESS,
                    f"Dataset '{st.session_state.get('active_df_name')}' Sanitized",
                    f"Masked {len(masked_cols)} columns: {', '.join(masked_cols)} across {len(current_df)} rows.",
                )
                st.success("✅ Privacy masking applied successfully!")

            if "sanitized_df" in st.session_state:
                st.markdown("### 👁️ Sanitized Output Preview")
                st.dataframe(st.session_state.sanitized_df, use_container_width=True)

                can_export, exp_reason = check_permission(st.session_state.current_role, ACTION_EXPORT_SANITIZED)
                if can_export:
                    csv_buffer = io.StringIO()
                    st.session_state.sanitized_df.to_csv(csv_buffer, index=False)
                    st.download_button(
                        label="⬇️ Download Sanitized CSV",
                        data=csv_buffer.getvalue(),
                        file_name="sanitized_dataset.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )
                else:
                    st.caption(f"🔒 Export restricted: {exp_reason}")


# ======================================================================
# MODULE D: Role-Based Access Control (RBAC) Demonstration
# ======================================================================
elif menu_choice == "Module D: Access Control (RBAC)":
    st.subheader("👥 Module D — Role-Based Access Control (RBAC) Engine")
    st.caption("Least Privilege Enforcement, Policy Evaluation, and Permission Matrices")

    st.markdown(
        """
        <div style="background-color: #1e293b; padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155;">
            <strong>🛡️ Enterprise Access Enforcement (NIST RBAC):</strong>
            This engine evaluates Subject-Action-Object authorization policies in real time, enforcing the Principle of Least Privilege (PoLP) and preventing unauthorized privilege escalation.
        </div>
        """,
        unsafe_allow_html=True,
    )

    r_col1, r_col2 = st.columns([1, 1.4])

    with r_col1:
        st.markdown("### 🎛️ Interactive Policy Evaluation")
        test_role = st.selectbox("Select Subject Role to Evaluate:", AVAILABLE_ROLES, key="test_rbac_role")
        test_action = st.selectbox(
            "Select Requested Action:",
            list(ACTION_METADATA.keys()),
            format_func=lambda x: f"{ACTION_METADATA[x]['title']} ({x})",
            key="test_rbac_action",
        )

        if st.button("⚖️ Evaluate Authorization Decision", type="primary", use_container_width=True):
            is_allowed, explanation = check_permission(test_role, test_action)
            status = STATUS_SUCCESS if is_allowed else STATUS_DENIED

            log_event(
                EVENT_RBAC,
                status,
                f"RBAC Policy Decision for {test_role}",
                f"Action: {test_action} -> {'Permitted' if is_allowed else 'Denied'}",
            )

            if is_allowed:
                st.markdown(
                    f"""
                    <div style="background-color: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 8px; padding: 16px; margin-top: 14px;">
                        <span class="badge-success">DECISION: PERMITTED</span>
                        <h4 style="color: #34d399; margin: 8px 0 4px 0;">Access Granted</h4>
                        <p style="color: #cbd5e1; font-size: 0.85rem; margin: 0;">{explanation}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div style="background-color: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 16px; margin-top: 14px;">
                        <span class="badge-danger">DECISION: DENIED</span>
                        <h4 style="color: #f87171; margin: 8px 0 4px 0;">Access Denied (403 Forbidden)</h4>
                        <p style="color: #cbd5e1; font-size: 0.85rem; margin: 0;">{explanation}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    with r_col2:
        st.markdown("### 📋 Complete Permission Matrix")

        matrix_rows = []
        for action, meta in ACTION_METADATA.items():
            matrix_rows.append(
                {
                    "Action ID": action,
                    "Action Description": meta["title"],
                    "Admin": "✅ Yes" if action in PERMISSIONS_MATRIX[ROLE_ADMIN] else "❌ No",
                    "Analyst": "✅ Yes" if action in PERMISSIONS_MATRIX[ROLE_ANALYST] else "❌ No",
                    "Viewer": "✅ Yes" if action in PERMISSIONS_MATRIX[ROLE_VIEWER] else "❌ No",
                }
            )

        st.dataframe(pd.DataFrame(matrix_rows), use_container_width=True, hide_index=True)


# ======================================================================
# MODULE E: Security Event Log
# ======================================================================
elif menu_choice == "Module E: Security Event Log":
    st.subheader("📜 Module E — Security Event & Audit Log")
    st.caption("Active Session Security Log with Safe Filtering and Event Auditing")

    st.markdown(
        """
        <div style="background-color: #1e293b; padding: 10px 16px; border-radius: 8px; font-size: 0.8rem; color: #94a3b8; border: 1px solid #334155; margin-bottom: 16px;">
            <strong>🔒 Safe Logging Assurance:</strong> This log maintains an audit trail of security-relevant events.
            To adhere to cybersecurity compliance (OWASP/NIST), <strong>passwords, secret keys, or sensitive raw contents are never logged.</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    df_logs = logs_to_dataframe(st.session_state.audit_logs)

    # Filter Toolbar
    f_col1, f_col2, f_col3 = st.columns([1, 1, 1])
    with f_col1:
        role_filter = st.selectbox("Filter by Role:", ["All"] + AVAILABLE_ROLES + ["System"])
    with f_col2:
        status_filter = st.selectbox(
            "Filter by Outcome Status:",
            ["All", STATUS_SUCCESS, STATUS_WARNING, STATUS_DENIED, STATUS_ERROR, STATUS_INFO],
        )
    with f_col3:
        st.metric("Total Events Logged", len(df_logs))

    # Apply filters
    filtered_df = df_logs.copy()
    if role_filter != "All":
        filtered_df = filtered_df[filtered_df["Role"] == role_filter]
    if status_filter != "All":
        filtered_df = filtered_df[filtered_df["Status"] == status_filter]

    st.dataframe(
        filtered_df.iloc[::-1],  # Show latest first
        use_container_width=True,
        hide_index=True,
    )

    act_col1, act_col2 = st.columns(2)
    with act_col1:
        # Export CSV
        csv_log = df_logs.to_csv(index=False)
        st.download_button(
            label="⬇️ Export Audit Trail as CSV",
            data=csv_log,
            file_name=f"security_audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with act_col2:
        can_clear, clear_reason = check_permission(st.session_state.current_role, ACTION_CLEAR_LOGS)
        if st.button("🗑️ Clear Active Session Logs", use_container_width=True, disabled=not can_clear):
            st.session_state.audit_logs = [
                create_log_entry(
                    EVENT_SYSTEM,
                    STATUS_INFO,
                    st.session_state.current_role,
                    "Session Audit Log Purged",
                    "Administrative log clearance executed.",
                )
            ]
            st.success("Session logs purged.")
            st.rerun()
        if not can_clear:
            st.caption(f"🔒 {clear_reason}")

# ----------------------------------------------------------------------
# Footer
# ----------------------------------------------------------------------
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: #64748b; font-size: 0.8rem; padding: 10px 0;">
        <strong>Integrated Cryptography, Network Security & Privacy Suite</strong><br/>
        Engineered by <strong>Mukul Kumbhar</strong> | Repository: <a href="https://github.com/MukulKumbhar/All-auth" target="_blank" style="color: #38bdf8; text-decoration: none;">MukulKumbhar/All-auth</a><br/>
        Built with Streamlit, pyca/cryptography, and Pandas | NIST SP 800 & FIPS 186 Compliant Primitives
    </div>
    """,
    unsafe_allow_html=True,
)
