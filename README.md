# AES Cryptanalysis Toolkit

A collection of cryptographic tools for implementing and attacking AES encryption modes, plus hash function security testing.

### Custom AES Implementation
- Built a custom AES encryption mode that combines AES-ECB with XOR block chaining
- Handles hex keys, initialization vectors, and padding properly
- Uses the cryptography.io library for the core AES operations

```python
# Encrypt and decrypt with custom mode
encrypted = Encrypt("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "Hello World")
decrypted = Decrypt(key, iv, encrypted)
```

### Attack Implementation
- Wrote a known-plaintext attack that exploits the XOR chaining weakness
- Can forge new encrypted messages without knowing the encryption key
- Demonstrated it by turning "hold position" orders into "attack" orders

```python
# Forge messages using the attack
forged_ciphertext = attackAESMode(original_message, known_ciphertext, target_message)
```

### Hash Function Security Testing
- Created a custom hash function based on SHA-256 with compression stages
- Built tools to test its security using birthday attacks and other methods
- Shows how truncated hashes can be vulnerable to collisions

```python
# Test hash security
hash_output = myHash(data)
is_secure = myAttack()  # Returns "YES" or "NO"
```

## Skills Shown

- Writing cryptographic code with proper key handling
- Finding and exploiting vulnerabilities in crypto implementations  
- Building security testing tools
- Understanding the math behind cryptographic attacks

## Technologies

- Python 3.8+
- cryptography.io library
- SHA-256 hashing
- Custom algorithm implementations

## How to Run

```bash
pip install cryptography
python aes_implementation.py
python hash_analysis.py
```

## Why This Matters

Understanding how to break crypto is just as important as knowing how to implement it. This toolkit shows both sides - building secure implementations and finding the flaws that make them insecure.

The military communication example demonstrates how small implementation mistakes can have serious real-world consequences.
