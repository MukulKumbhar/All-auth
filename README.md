# Integrated Cryptography, Network Security and Privacy System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/frontend-Streamlit-red.svg)](https://streamlit.io/)
[![Cryptography](https://img.shields.io/badge/security-pyca%2Fcryptography-green.svg)](https://cryptography.io/)
[![Tests](https://img.shields.io/badge/tests-12%20passing-brightgreen.svg)](#running-automated-tests)

An educational cybersecurity workbench demonstrating authenticated symmetric encryption, digital signatures, privacy-preserving data masking, role-based authorization, and security event auditing in one unified interactive application.

**Author:** Mukul Kumbhar  
**Repository:** [https://github.com/MukulKumbhar/All-auth](https://github.com/MukulKumbhar/All-auth)  
**Academic Subject:** Information and Network Security (INS) Micro-Project  

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Module Architecture](#module-architecture)
3. [Binary Container Format (.insc)](#binary-container-format-insc)
4. [Quickstart & Execution](#quickstart--execution)
5. [Running Automated Tests](#running-automated-tests)
6. [Security & Limitations](#security--limitations)
7. [INS Viva Q&A Guide](#ins-viva-qa-guide)

---

## 🌟 Project Overview

This micro-project provides an intuitive, high-visibility cybersecurity platform to demonstrate core Information and Network Security (INS) tenets:
- **Confidentiality & Integrity**: AES-256 in Galois/Counter Mode (GCM) with Scrypt salted key derivation.
- **Authenticity & Non-Repudiation**: RSA-2048 with Probabilistic Signature Scheme (PSS) padding and SHA-256 message digests.
- **Privacy & Data Minimization**: Column-level PII masking (names, emails, phones, IDs) for compliance with privacy frameworks (DPDP, GDPR, HIPAA).
- **Authorization & Access Control**: Educational Role-Based Access Control (RBAC) engine simulating Admin, Analyst, and Viewer permissions.
- **Auditing & Accountability**: In-memory security event audit buffer tracking security decisions while strictly excluding sensitive secrets.

---

## 🧩 Module Architecture

| Module | Core Algorithm / Library | Purpose | Security Guarantee |
| :--- | :--- | :--- | :--- |
| **Module A: File Encryption** | `AES-256-GCM` + `Scrypt` | Symmetric file encryption and decryption | Authenticated Encryption with Associated Data (AEAD); tamper-proof container |
| **Module B: Digital Signatures** | `RSA-2048 PSS` + `SHA-256` | Asymmetric signing & verification | Mathematical proof of origin and payload integrity |
| **Module C: Privacy Protection** | Regex / `Pandas` | Tabular PII masking | Redacts personal identifiers before data export |
| **Module D: Access Control** | RBAC Policy Matrix | Authorization enforcement | Enforces Principle of Least Privilege |
| **Module E: Security Event Log** | Sanitized Session Buffer | Security audit logging | Complete operational traceability with zero secret leakage |
| **Module F: Security Overview** | Interactive Dashboard | System health & Viva guide | Visual architecture, concept explanations, and disclaimers |

---

## 📦 Binary Container Format (`.insc`)

Files encrypted by the workbench are wrapped in a custom, versioned binary envelope that authenticates both metadata and ciphertext:

```text
+--------------------------------------------------------------+
| Field Name        | Offset | Length   | Description          |
+--------------------------------------------------------------+
| Magic Header      | 0      | 4 Bytes  | b"INSC"              |
| Format Version    | 4      | 1 Byte   | 0x01 (Version 1)     |
| Scrypt Salt       | 5      | 16 Bytes | Random per file      |
| AES-GCM Nonce     | 21     | 12 Bytes | Random per file      |
| Filename Length   | 33     | 2 Bytes  | uint16 big-endian    |
| Original Filename | 35     | N Bytes  | UTF-8 Encoded Name   |
| Ciphertext + Tag  | 35 + N | Variable | AES-GCM (16-byte tag)|
+--------------------------------------------------------------+
```

> **Tamper Resistance**: The entire header is passed as **Associated Data** to `AESGCM.encrypt()`. Any modification to the filename, version, salt, nonce, or ciphertext causes immediate decryption failure.

---

## 🚀 Quickstart & Execution

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Clone Repository & Install Dependencies
```bash
git clone https://github.com/MukulKumbhar/All-auth.git
cd All-auth

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
streamlit run app.py
```
Open your browser to: **`http://localhost:8501`**

---

## 🧪 Running Automated Tests

Run the complete test suite verifying encryption round-trips, tampering detection, signature verification, and access controls:

```bash
pytest tests/test_crypto.py -v
```

**Expected output:**
```text
tests/test_crypto.py::test_encryption_decryption_roundtrip PASSED
tests/test_crypto.py::test_decryption_with_incorrect_password PASSED
tests/test_crypto.py::test_ciphertext_tampering_detection PASSED
tests/test_crypto.py::test_header_tampering_detection PASSED
tests/test_crypto.py::test_malformed_payload_rejection PASSED
tests/test_crypto.py::test_empty_password_rejection PASSED
tests/test_crypto.py::test_rsa_signature_generation_and_verification PASSED
tests/test_crypto.py::test_rsa_tampered_document_rejection PASSED
tests/test_crypto.py::test_rsa_key_serialization PASSED
tests/test_crypto.py::test_privacy_masking_functions PASSED
tests/test_crypto.py::test_dataframe_masking_integration PASSED
tests/test_crypto.py::test_rbac_permission_enforcement PASSED

============================= 12 passed in 1.00s ==============================
```

---

## ⚠️ Security & Limitations

- **Educational Scope**: Designed for classroom demonstration and laboratory examination. It does not replace enterprise Key Management Systems (AWS KMS, Azure Key Vault, HSMs) or enterprise SIEM log aggregators.
- **In-Memory Volatility**: Generated master private keys and session logs are held in memory during the active session and are not persisted to non-volatile disks.
- **Zero Secrets Logging**: In accordance with NIST SP 800-92 guidelines, plaintexts, passwords, and private key materials are strictly excluded from logging facilities.

---

## 🎓 INS Viva Q&A Guide

### Q1: Why AES-GCM over traditional AES-CBC?
**Answer**: AES-CBC provides confidentiality but no authenticity or integrity. An attacker can tamper with ciphertext blocks (bit-flipping attacks) or exploit padding oracle vulnerabilities. AES-GCM is an Authenticated Encryption with Associated Data (AEAD) algorithm that computes a Galois authentication tag concurrently with encryption, guaranteeing both secrecy and tamper detection.

### Q2: Why use Scrypt instead of standard SHA-256 for passwords?
**Answer**: SHA-256 is designed for fast file integrity verification. A standard GPU can compute millions of SHA-256 hashes per second, making dictionary attacks easy. Scrypt is a memory-hard password-based key derivation function (KDF) that requires substantial RAM and computation time, rendering ASIC/GPU brute-force attacks infeasible.

### Q3: Why is RSA-PSS preferred over PKCS#1 v1.5?
**Answer**: PKCS#1 v1.5 padding is deterministic and susceptible to chosen-ciphertext attacks (e.g., Bleichenbacher attacks). RSA-PSS (Probabilistic Signature Scheme) includes a randomized salt during signature generation, providing provable security against existential forgery.

### Q4: What is the difference between Authentication and Authorization in RBAC?
**Answer**: Authentication verifies *who* an entity is (e.g., via passwords or digital certificates). Authorization verifies *what* an authenticated entity is permitted to do based on assigned roles and least-privilege matrices.

---

## 📄 License
Educational Open-Source — Academic and Research Use.
