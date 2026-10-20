# Engineering & Architecture Guide: Integrated Cryptography, Network Security and Privacy Suite

**Repository:** [https://github.com/MukulKumbhar/All-auth](https://github.com/MukulKumbhar/All-auth)  
**Lead Developer:** Mukul Kumbhar  
**Document Classification:** Technical Architecture & Engineering Specification  

---

## 1. Executive Introduction

In an increasingly perimeterless digital ecosystem, data protection mechanisms cannot rely solely on transport-layer encryption (TLS) or perimeter firewalls. Critical enterprise data is vulnerable to insider threats, untrusted storage brokers, database exfiltration, and identity spoofing. 

The **Integrated Cryptography, Network Security and Privacy Suite** is a unified, defense-in-depth security engineering platform designed to guarantee data security across all three lifecycle states:
- **Data at Rest**: Authenticated, tamper-evident symmetric encryption using **AES-256-GCM** with **Scrypt** memory-hard key derivation.
- **Data in Transit / Origin Validation**: Cryptographic authenticity and non-repudiation using **RSA-2048 PSS** digital signatures with **SHA-256**.
- **Data in Use / Processing**: Privacy engineering via automated **Personally Identifiable Information (PII) masking** and redaction pipelines compliant with DPDP, GDPR, and HIPAA frameworks.
- **Access Authorization**: Strict enforcement of the **Principle of Least Privilege (PoLP)** through a granular **Role-Based Access Control (RBAC)** policy engine.
- **Traceability & Forensics**: Sanitized **centralized security telemetry** capturing operational events without persisting secrets or plaintexts.

---

## 2. Problem Statement

Modern enterprise software systems routinely face five critical security vulnerabilities:

1. **Unauthenticated Encryption (Bit-Flipping & Oracle Attacks)**:  
   Legacy systems frequently deploy unauthenticated ciphers such as AES-CBC or AES-ECB. These modes provide confidentiality but lack built-in integrity verification, leaving payloads susceptible to bit-flipping attacks, chosen-ciphertext attacks, and padding oracle vulnerabilities.
2. **Weak Password Derivation (GPU/ASIC Brute-Force)**:  
   Standard cryptographic hash functions (such as MD5, SHA-1, or plain SHA-256) are computationally optimized for rapid evaluation. Modern GPU clusters can compute billions of SHA-256 hashes per second, making offline dictionary attacks trivial against user-selected passphrases.
3. **Malleable Digital Signatures & Forgery**:  
   Deterministic signature padding schemes (such as PKCS#1 v1.5) are historically susceptible to Bleichenbacher chosen-ciphertext attacks and existential forgery under chosen-message scenarios.
4. **PII Data Exposure in Downstream Environments**:  
   Development, staging, and analytics pipelines frequently ingest production database dumps containing unmasked sensitive customer data (names, email addresses, phone numbers, identifiers), violating data minimization mandates.
5. **Privilege Creep & Opaque Security Decisions**:  
   Monolithic access rights without fine-grained role matrices lead to excessive operator permissions, creating attack vectors for insider threats and privilege escalation.

---

## 3. Proposed Solution

The proposed platform mitigates these challenges through a modular, high-assurance architecture:

```
+-----------------------------------------------------------------------------------+
|                           Streamlit Web Presentation                              |
|           (Dark-Themed Command Dashboard, Telemetry & Interactive Ops)            |
+-----------------------------------------------------------------------------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
+--------------+              +---------------+              +---------------+
|   Module A   |              |   Module B    |              |   Module C    |
| Authenticated|              |  Asymmetric   |              |  Data Privacy |
|  Encryption  |              |  Signatures   |              |   & Masking   |
| (AES-256-GCM |              |  (RSA-2048    |              |  (PII Engine, |
|   + Scrypt)  |              |  PSS/SHA-256) |              | Regex/Pandas) |
+--------------+              +---------------+              +---------------+
       \                              |                              /
        +-----------------------------+-----------------------------+
                                      |
                     +---------------------------------+
                     |            Module D             |
                     | Role-Based Access Control (RBAC)|
                     |   (Admin, Analyst, Viewer PoLP) |
                     +---------------------------------+
                                      |
                     +---------------------------------+
                     |            Module E             |
                     |  Sanitized Event Audit Trail    |
                     |  (Zero Secret Exposure Logger)  |
                     +---------------------------------+
```

---

## 4. Cryptographic Methodology & Applied Standards

### 4.1. Authenticated Encryption with Associated Data (AEAD)
* **Standard**: NIST SP 800-38D (Galois/Counter Mode).
* **Key Size**: 256 bits (32 bytes).
* **Nonce Vector**: 96 bits (12 bytes), cryptographically random (`os.urandom(12)`) per encryption event.
* **Authentication Tag**: 128 bits (16 bytes), generated via Galois field multiplication.
* **Associated Data Binding**: The container header (magic bytes, version, salt, nonce, filename length, filename) is authenticated alongside the ciphertext. Any unauthorized modification to either the header or ciphertext triggers immediate authentication failure (`InvalidTag`).

### 4.2. Password-Based Key Derivation Function (KDF)
* **Standard**: RFC 7914 (The scrypt Password-Based Key Derivation Function).
* **Cost Parameters**:
  * $N = 16384$ ($2^{14}$ CPU/memory cost parameter)
  * $r = 8$ (Block size parameter, 1024 bytes)
  * $p = 1$ (Parallelization parameter)
  * Salt Length: 128 bits (16 bytes), cryptographically random per file.
* **Rationale**: Scrypt mandates significant working RAM per evaluation, preventing parallel computation on FPGA, ASIC, and GPU hardware.

### 4.3. Digital Signatures & Public Key Cryptography
* **Standards**: FIPS 186-4 (Digital Signature Standard) and PKCS#1 v2.2.
* **Key Generation**: RSA 2048-bit modulus with public exponent $e = 65537$.
* **Padding Scheme**: PSS (Probabilistic Signature Scheme) utilizing Mask Generation Function 1 (MGF1) backed by SHA-256.
* **Salt Length**: `PSS.MAX_LENGTH` to maximize entropy.
* **Rationale**: PSS padding introduces non-deterministic random salt into the signing operation, providing a formal reduction proof to the RSA problem.

### 4.4. Privacy Engineering & Data Sanitization
* **Technique**: Format-Preserving Masking & Pseudonymization.
* **Coverage**: Full Names, Corporate Emails, International Phone Numbers, National Identifiers.
* **Properties**: Irreversible one-way redaction preserving semantic structure for analytical schema compatibility without re-identification risk.

---

## 5. System Architecture & Binary Container Specification

### 5.1. The `.insc` Binary Container Format

Every file processed through the platform is packaged in a deterministic, tamper-evident binary envelope:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: "INSC"                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver (0x01)   |                                               |
+-+-+-+-+-+-+-+-+           Scrypt Salt (16 Bytes)              +
|                                                               |
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+           AES-GCM Nonce (12 Bytes)            +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |     Filename Length (uint16)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Original Filename (UTF-8 Encoded, N Bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|        AES-256-GCM Ciphertext Payload (Variable Length)       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               AES-GCM Authentication Tag (16 Bytes)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.2. Component Interaction & Encryption Flow

```
[User Input: File + Passphrase]
            │
            ├──────► Generate Random 16-byte Salt
            ├──────► Generate Random 12-byte Nonce
            │
    [Scrypt KDF Engine]
            │ (Salt + Passphrase)
            ▼
    [256-bit AES Key]
            │
    [Construct Container Header]
            │
            ▼
   [AES-256-GCM Engine] ◄─── (Plaintext + Header as Associated Data)
            │
            ▼
   [Ciphertext + 16-byte GCM Tag]
            │
            ▼
   [Assemble `.insc` Container] ──► [Download Package / Persistent Storage]
```

---

## 6. Detailed Module Specifications

### Module A: Authenticated Encryption (`crypto_utils.py`)
- `encrypt_file_data(plaintext_bytes: bytes, password: str, original_filename: str) -> bytes`:
  Derives key, formats container header, binds header as associated data, and encrypts payload.
- `decrypt_file_data(encrypted_payload: bytes, password: str) -> Tuple[str, bytes]`:
  Parses binary header, validates magic bytes and version, derives key with extracted salt, and authenticates ciphertext and header. Raises `DecryptionError` upon tag mismatch or corruption.

### Module B: Asymmetric Signatures (`crypto_utils.py`)
- `generate_rsa_key_pair(key_size: int = 2048) -> Tuple[RSAPrivateKey, RSAPublicKey]`:
  Generates high-entropy RSA key pair with $e=65537$.
- `sign_data(private_key: RSAPrivateKey, data_bytes: bytes) -> bytes`:
  Produces 256-byte RSA-PSS signature using SHA-256 digest and MGF1.
- `verify_signature(public_key: RSAPublicKey, signature: bytes, data_bytes: bytes) -> bool`:
  Performs constant-time signature verification. Returns boolean status.

### Module C: Privacy Sanitization Engine (`masking_utils.py`)
- `detect_pii_columns(df: pd.DataFrame) -> dict`:
  Heuristic inspection detecting names, email patterns, phone numbers, and identifier columns.
- `apply_masking(df: pd.DataFrame, column_rules: dict) -> pd.DataFrame`:
  Vectorized sanitization preserving string boundaries and structural syntax.

### Module D: Role-Based Authorization (`rbac_utils.py`)
- Matrix enforcement mapping roles (`Admin`, `Analyst`, `Viewer`) to granular actions.
- Enforces strict separation between cryptographic signing authorities and analytical data consumers.

### Module E: Centralized Security Telemetry (`audit_utils.py`)
- Real-time logging of authentication, encryption, verification, and sanitization events.
- Strict compliance filter: passwords, secrets, and raw plaintexts are scrubbed prior to log generation.

---

## 7. Threat Modeling & Security Posture (STRIDE)

| Threat Category | Potential Attack Vector | Platform Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates document originator | RSA-2048 PSS digital signatures with asymmetric public-key verification. |
| **Tampering** | Attacker modifies ciphertext in transit | AES-256-GCM 128-bit authentication tag with associated data binding. |
| **Repudiation** | Originator denies authoring transmitted file | Cryptographic digital signature bound to private key held exclusively by sender. |
| **Information Disclosure** | Data breach of CSV dataset or storage leak | AES-256 encryption at rest + automated PII redaction pipeline. |
| **Denial of Service / Brute Force** | High-speed dictionary cracking of passphrases | Scrypt memory-hard KDF ($N=16384$) prevents GPU/ASIC acceleration. |
| **Elevation of Privilege** | Analyst attempts key generation or log purging | Application-level RBAC policy evaluation halts unauthorized actions. |

---

## 8. Verification & Test Suite

The test suite in `tests/test_crypto.py` runs under `pytest` and verifies:
1. Complete encryption/decryption round-trip fidelity.
2. Immediate rejection of invalid passwords.
3. Tamper detection on modified ciphertext payloads.
4. Tamper detection on modified container metadata headers.
5. Rejection of truncated or malformed file structures.
6. RSA-PSS signature validity and 1-bit tampering detection.
7. PII redaction accuracy across names, emails, and phone numbers.
8. RBAC privilege boundaries across Admin, Analyst, and Viewer roles.

To execute tests:
```bash
pytest tests/test_crypto.py -v
```

---

## 9. Developer Setup & Extension

### Installation
```bash
git clone https://github.com/MukulKumbhar/All-auth.git
cd All-auth
pip install -r requirements.txt
```

### Launching Platform
```bash
streamlit run app.py
```

### Adding a New Cryptographic Primitive
To introduce an alternative cipher (e.g., ChaCha20-Poly1305):
1. Add the cipher implementation into `crypto_utils.py` adhering to the AEAD interface.
2. Increment `FORMAT_VERSION` in the header specification to maintain backward compatibility.
3. Expose the algorithm selection in the Streamlit UI parameter panel.
4. Register corresponding permission actions in `rbac_utils.py`.
5. Add unit test coverage in `tests/test_crypto.py`.
