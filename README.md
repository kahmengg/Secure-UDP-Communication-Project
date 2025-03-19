# Secure UDP Communication Project

This project implements a secure communication channel over UDP between two parties, "Alice" (Host) and "Bob" (Client), using a shared password and cryptographic techniques. It follows a key exchange protocol based on Diffie-Hellman and secures messages with RC4 encryption and SHA-1 hashing for integrity.

## Features
- UDP-based network communication
- Diffie-Hellman key exchange for session key establishment
- RC4 stream cipher for encryption
- SHA-1 hashing for data integrity
- Nonce-based authentication

## Directory Structure
- `Alice/`: Contains the Host script (`host.py`) and configuration files (e.g., Diffie-Hellman parameters and hashed password).
- `Bob/`: Contains the Client script (`client.py`).

## Prerequisites
- Python 3.x
- Required libraries:
  - `pycryptodome` (for RC4 and SHA-1)
  - `socket` (built-in, for UDP)
  - `os` and `random` (built-in, for nonce generation and file handling)

Install dependencies:
```bash
pip install pycryptodome