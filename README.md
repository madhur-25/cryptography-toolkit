# cryptography-toolkit
Multi-Cipher Cryptography Toolkit

A Streamlit-based application that demonstrates both classical and modern cryptographic techniques through an interactive and user-friendly interface.
This project integrates multiple encryption, decryption, and hashing methods along with RSA key generation, making it suitable for learning, experimentation, and academic project work.

📌 Features
🟦 Classical Cryptography

Caesar Cipher – Shift-based substitution

Vigenère Cipher – Polyalphabetic encryption using keyword

Playfair Cipher – 5x5 matrix bigram encryption

Rail Fence Cipher – Zig-zag transposition cipher

🟩 Modern Cryptography

AES (CBC Mode) – Secure symmetric encryption using password-derived key

DES (CBC Mode) – Classic block cipher encryption

RSA (OAEP Padding)

Generate 2048-bit public/private key pairs

Encrypt with public key

Decrypt with private key

SHA-256 Hashing – One-way cryptographic hash function

🎯 Project Objectives

Provide a practical learning tool for classical and modern cipher algorithms

Demonstrate symmetric and asymmetric encryption schemes

Allow secure RSA key management and base64 export

Show real-time encryption/decryption results

Promote hands-on understanding of data confidentiality and integrity

🏗 Application Architecture
1. Front-End

Built using Streamlit

Three functional modes:

Classical Ciphers

Modern Cryptography

About & Help

Supports live encryption, decryption, and hashing

Downloadable results & keys

2. Cryptography Engine

Implemented in Python using:

PyCryptodome for AES, DES, RSA

Hashlib for SHA-256

Custom algorithms for Vigenère, Caesar, Playfair, Rail Fence

AES & DES implemented with:

CBC mode

PKCS7 padding

SHA-256 derived keys

3. Storage

Session-based history tracking

No local file storage required

RSA keys downloadable as files

▶️ How to Run Locally
1. Install Dependencies
pip install streamlit pycryptodome

2. Run the App
streamlit run app.py

3. Open in Browser

Streamlit will automatically launch at:

http://localhost:8501



📚 Algorithms Included
Technique	Type	Description
Caesar	Classical	Shift every letter by a fixed number
Vigenère	Classical	Polyalphabetic cipher using keyword
Playfair	Classical	5×5 matrix bigram encryption
Rail Fence	Classical	Zig-zag transposition pattern
AES-CBC	Modern	Strong symmetric encryption with password
DES-CBC	Modern	Block cipher with 8-byte key
RSA	Modern	Asymmetric encryption using key pairs
SHA-256	Hashing	One-way cryptographic hash


