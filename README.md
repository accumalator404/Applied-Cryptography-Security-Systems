# Applied-Cryptography-Security-Systems
This project implements and analyzes various cryptographic primitives and their security properties, showcasing practical cryptanalysis skills and secure implementation techniques. The work demonstrates understanding of both the mathematical foundations of cryptography and real-world attack methodologies.


# Cryptographic Security Analysis

A university coursework project implementing and analyzing cryptographic systems, including AES encryption modes, cryptanalytic attacks, and hash function security.

## What I Built

### Task 1: Custom AES Encryption Mode
- Implemented a custom AES encryption/decryption system using cryptography.io
- Built a cipher mode that combines AES-ECB with XOR-based block chaining
- Handles hexadecimal keys, initialization vectors, and proper padding

```python
# Example usage
encrypted = Encrypt("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "Hello World")
decrypted = Decrypt(key, iv, encrypted)
```

### Task 2: Cryptanalytic Attack
- Developed a practical attack against the custom AES mode
- Exploits XOR chaining vulnerabilities to forge messages without knowing the key
- Successfully demonstrated by forging military communications

```python
# Attack demo: forge "attack orders" from "hold position" message
forged_ciphertext = attackAESMode(original_message, known_ciphertext, target_message)
```

### Task 3: Hash Function Analysis
- Created a custom hash function based on SHA-256 with iterative compression
- Built security analysis tools to detect vulnerabilities
- Implemented birthday attack and other cryptanalytic tests

```python
hash_output = myHash(data)
security_status = myAttack()  # Returns "YES" if secure, "NO" if vulnerable
```

## Key Skills Demonstrated

- **Cryptographic Programming**: AES implementation, secure key handling
- **Security Analysis**: Vulnerability assessment and attack development
- **Professional Libraries**: Using industry-standard cryptography.io
- **Problem Solving**: Breaking down complex security problems

## Technologies Used

- Python 3.8+
- cryptography.io library
- SHA-256 hashing
- NumPy for mathematical operations

## Academic Context

This was coursework for **SCC.363 Security and Risk** at Lancaster University, worth 30% of the module grade. The project demonstrates both defensive cryptographic implementation and offensive security analysis.

## Running the Code

```bash
pip install cryptography
python src/aes_implementation.py
python src/hash_analysis.py
```
