# Cybersecurity Principles

This repository contains implementations of various core principles and techniques in cybersecurity. Each section demonstrates a different concept through code examples, aiming to provide educational value and practical applications of security concepts.

## Table of Contents
- [Asymmetric Cryptography](#asymmetric-cryptography)
- [Future Sections](#future-sections)

---

### Asymmetric Cryptography

Asymmetric cryptography, also known as public-key cryptography, is a method where a pair of keys is used: a public key for encryption and a private key for decryption. This ensures that even if the public key is widely known, only the private key holder can decrypt the encrypted message.

**Demo Overview:**
In the provided demo, a client and server exchange encrypted messages using RSA. The client encrypts a message with the server's public key, ensuring that only the server (with its private key) can decrypt and read the message.

- **Classes:**
  - `PseudoServer`: Represents a server that holds its own RSA key pair and can decrypt messages sent to it.
  - `Client`: Represents a client that holds its own RSA key pair and encrypts messages using the server's public key.
  - `CryptoTools`: Utility class to handle key generation, encryption, and decryption.
  - `Demo`: Demonstrates secure message exchange between the client and server using RSA.

- **Key Concepts:**
  - Key pair generation (public/private keys)
  - Encrypting messages with a recipient's public key
  - Decrypting messages with the recipient's private key

### Future Sections

- **Digital Signatures**: Coming soon
- **Two-Factor Authentication**: Coming soon