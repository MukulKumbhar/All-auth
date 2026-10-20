# Integrated Cryptography, Network Security & Privacy Suite

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/framework-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/crypto-pyca%2Fcryptography-10B981.svg)](https://cryptography.io/)
[![Security Standards](https://img.shields.io/badge/compliance-NIST%20SP%20800--38D%20%7C%20FIPS%20186--4-0284C7.svg)](#standards-compliance)
[![Tests](https://img.shields.io/badge/tests-12%20passing-brightgreen.svg)](#testing--verification)
[![License](https://img.shields.io/badge/license-MIT-64748B.svg)](LICENSE)

An enterprise-grade, high-assurance cybersecurity platform providing authenticated data encryption, asymmetric digital signatures, automated PII sanitization, role-based access authorization, and real-time security telemetry.

**Lead Developer:** Mukul Kumbhar  
**Repository:** [https://github.com/MukulKumbhar/All-auth](https://github.com/MukulKumbhar/All-auth)  
**Technical Documentation:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)

---

## 🌟 Executive Overview

In modern data processing and distributed computing environments, transport-layer security alone is insufficient to protect sensitive records from insider threats, compromised storage layers, and data exfiltration.

The **Integrated Cryptography, Network Security & Privacy Suite** provides an end-to-end defense framework:
- **Authenticated Data at Rest**: Authenticated encryption via **AES-256-GCM** with **Scrypt** memory-hard key derivation.
- **Origin Authenticity & Non-Repudiation**: Asymmetric signing via **RSA-2048 PSS** and **SHA-256** message digests.
- **Privacy Engineering & Minimization**: Dynamic tabular **PII Redaction** (Names, Emails, Phones, National IDs) compliant with modern privacy frameworks (DPDP, GDPR, HIPAA).
- **Zero-Trust Access Control**: Application-level **Role-Based Access Control (RBAC)** enforcing the Principle of Least Privilege (PoLP).
- **Forensic Audit & Telemetry**: Real-time **Security Event Stream** maintaining operational visibility while guaranteeing zero sensitive secret retention.

---

## 🧩 Subsystem Architecture

```text
                                  +-----------------------+
                                  |   Streamlit Web UI    |
                                  |  (Dark Ops Dashboard) |
                                  +-----------+-----------+
                                              |
      +------------------------+--------------+--------------+------------------------+
      |                        |                             |                        |
+-----+--------------+  +------+---------------+      +------+--------------+  +------+---------------+
| Authenticated      |  | Asymmetric           |      | Privacy Engineering |  | Access & Telemetry   |
| Storage Engine     |  | Identity & Signing   |      | & Sanitization      |  | Management           |
|                    |  |                      |      |                     |  |                      |
| • AES-256-GCM      |  | • RSA-2048 Key Pairs |      | • Automated PII Det.|  | • RBAC Policy Engine |
| • Scrypt KDF       |  | • RSA-PSS Padding    |      | • Schema Protection |  | • Sanitized Logging  |
| • Versioned .insc  |  | • SHA-256 Digests    |      | • CSV Export        |  | • Forensic Metrics   |
+--------------------+  +----------------------+      +---------------------+  +----------------------+
```

| Subsystem | Underlying Technology | Security Objective | Cryptographic Specification |
| :--- | :--- | :--- | :--- |
| **Module A: Authenticated Storage** | `AES-256-GCM` + `Scrypt` | Confidentiality & Integrity | 256-bit key, 96-bit nonce, 128-bit GCM tag, associated data binding |
| **Module B: Identity & Signing** | `RSA-2048` + `SHA-256` | Authenticity & Non-Repudiation | PSS randomized salt padding, MGF1 mask generation |
| **Module C: Privacy Engineering** | Regex / `Pandas` | Data Minimization | Pattern-matching redaction for names, emails, phones, and IDs |
| **Module D: Authorization Engine** | RBAC Policy Matrix | Least Privilege Enforcement | Multi-tier permissions (Admin, Analyst, Viewer) |
| **Module E: Security Telemetry** | In-Memory Audit Trail | Traceability & Forensics | Real-time event tracking with zero secret exposure |

---

## 📦 Container Specification (`.insc`)

Encrypted files are packaged into a binary container that cryptographically binds envelope metadata with the ciphertext:

```text
+--------------------------------------------------------------+
| Offset  | Length   | Field Name        | Description         |
+---------+----------+-------------------+---------------------+
| 0       | 4 Bytes  | Magic Header      | ASCII "INSC"        |
| 4       | 1 Byte   | Version           | 0x01                |
| 5       | 16 Bytes | Scrypt Salt       | Cryptographic Salt  |
| 21      | 12 Bytes | AES-GCM Nonce     | Cryptographic Nonce |
| 33      | 2 Bytes  | Filename Length   | uint16 big-endian   |
| 35      | N Bytes  | Original Filename | UTF-8 Encoded       |
| 35 + N  | Variable | Ciphertext + Tag  | AES-256-GCM Payload |
+--------------------------------------------------------------+
```

> **Tamper Proofing**: The header fields are bound to the AES-GCM Associated Data stream. Any unauthorized bit modification to the header or ciphertext triggers immediate decryption failure (`InvalidTag`).

---

## 🚀 Quickstart & Execution

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/MukulKumbhar/All-auth.git
cd All-auth

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the Application
```bash
streamlit run app.py
```
Open your web browser and navigate to: **`http://localhost:8501`**

---

## 🧪 Testing & Verification

A comprehensive automated test suite validates all cryptographic operations, edge cases, and attack surfaces:

```bash
pytest tests/test_crypto.py -v
```

### Test Suite Coverage
- **Encryption / Decryption Round-Trip**: Verifies byte-level integrity across data types.
- **Wrong Password Defense**: Validates authentication failure upon incorrect passphrase entry.
- **Ciphertext Tampering Detection**: Simulates bit-flipping attacks on ciphertext bytes.
- **Header Modification Detection**: Confirms Associated Data tamper-proofing on metadata.
- **Malformed Input Rejection**: Rejects truncated files and non-workbench structures.
- **RSA-PSS Signature Validity**: Confirms signing and constant-time public-key verification.
- **Signature Anti-Tampering**: Confirms signature invalidation upon 1-bit payload alteration.
- **PII Redaction Accuracy**: Verifies regex masking across names, emails, and phone numbers.
- **RBAC Policy Boundaries**: Confirms strict permission enforcement across roles.

---

## 🛡️ Standards Compliance

- **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation (Galois/Counter Mode).
- **RFC 7914**: The scrypt Password-Based Key Derivation Function.
- **FIPS 186-4**: Digital Signature Standard (DSS) — RSA-PSS with SHA-256.
- **NIST SP 800-92**: Guide to Computer Security Log Management (Zero Sensitive Data Retention).

---

## 📚 Technical Documentation

For an in-depth technical analysis covering the problem statement, cryptographic theory, threat modeling (STRIDE), and architectural diagrams, refer to the developer documentation:

👉 **[Read the Developer & Architecture Guide](docs/DEVELOPER_GUIDE.md)**

---

## 👤 Author & Maintainer

* **Developer:** Mukul Kumbhar
* **GitHub:** [@MukulKumbhar](https://github.com/MukulKumbhar)
* **Project Repository:** [https://github.com/MukulKumbhar/All-auth](https://github.com/MukulKumbhar/All-auth)
