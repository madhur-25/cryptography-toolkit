import streamlit as st
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# ================================
# Utility functions (padding / base64 helpers)
# ================================
BLOCK_SIZE_AES = 16
BLOCK_SIZE_DES = 8

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def from_b64(data: str) -> bytes:
    return base64.b64decode(data.encode())

# ================================
# Classical Cipher Algorithms
# ================================

# Vigenère
def encryption_vigenere(plain_text, key):
    main = string.ascii_lowercase
    index = 0
    cipher_text = ""
    plain_text = plain_text.lower()
    key = key.lower()
    for c in plain_text:
        if c in main:
            off = ord(key[index]) - ord('a')
            encrypt_num = (ord(c) - ord('a') + off) % 26
            encrypt = chr(encrypt_num + ord('a'))
            cipher_text += encrypt
            index = (index + 1) % len(key)
        else:
            cipher_text += c
    return cipher_text

def decryption_vigenere(cipher_text, key):
    main = string.ascii_lowercase
    index = 0
    plain_text = ""
    cipher_text = cipher_text.lower()
    key = key.lower()
    for c in cipher_text:
        if c in main:
            off = ord(key[index]) - ord('a')
            positive_off = 26 - off
            decrypt = chr((ord(c) - ord('a') + positive_off) % 26 + ord('a'))
            plain_text += decrypt
            index = (index + 1) % len(key)
        else:
            plain_text += c
    return plain_text

# Caesar
def encrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 + shift) % 26 + 65) if 'A' <= i <= 'Z' else chr((ord(i) - 97 + shift) % 26 + 97) for i in text])

def decrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 - shift) % 26 + 65) if 'A' <= i <= 'Z' else chr((ord(i) - 97 - shift) % 26 + 97) for i in text])

# Playfair
def key_generation_playfair(key):
    main = string.ascii_lowercase.replace('j', '.')
    key = key.lower()
    key_matrix = ['' for i in range(5)]
    i = 0
    j = 0
    for c in key:
        if c in main:
            key_matrix[i] += c
            main = main.replace(c, '.')
            j += 1
            if j > 4:
                i += 1
                j = 0
    for c in main:
        if c != '.':
            key_matrix[i] += c
            j += 1
            if j > 4:
                i += 1
                j = 0
    return key_matrix

def conversion_enc_playfair(key_matrix, plain_text):
    plain_text_pairs = []
    cipher_text_pairs = []
    plain_text = plain_text.replace(" ", "").lower()
    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        b = 'x' if (i + 1) == len(plain_text) else plain_text[i + 1]
        if a != b:
            plain_text_pairs.append(a + b)
            i += 2
        else:
            plain_text_pairs.append(a + 'x')
            i += 1
    for pair in plain_text_pairs:
        flag = False
        for row in key_matrix:
            if pair[0] in row and pair[1] in row:
                j0 = row.find(pair[0])
                j1 = row.find(pair[1])
                cipher_text_pair = row[(j0 + 1) % 5] + row[(j1 + 1) % 5]
                cipher_text_pairs.append(cipher_text_pair)
                flag = True
                break
        if flag:
            continue
        for j in range(5):
            col = "".join([key_matrix[i][j] for i in range(5)])
            if pair[0] in col and pair[1] in col:
                i0 = col.find(pair[0])
                i1 = col.find(pair[1])
                cipher_text_pair = col[(i0 + 1) % 5] + col[(i1 + 1) % 5]
                cipher_text_pairs.append(cipher_text_pair)
                flag = True
                break
        if flag:
            continue
    return "".join(cipher_text_pairs)

def conversion_dec_playfair(key_matrix, cipher_text):
    cipher_text_pairs = []
    plain_text_pairs = []
    cipher_text = cipher_text.lower()
    i = 0
    while i < len(cipher_text):
        a = cipher_text[i]
        b = cipher_text[i + 1]
        cipher_text_pairs.append(a + b)
        i += 2
    for pair in cipher_text_pairs:
        flag = False
        for row in key_matrix:
            if pair[0] in row and pair[1] in row:
                j0 = row.find(pair[0])
                j1 = row.find(pair[1])
                plain_text_pair = row[(j0 + 4) % 5] + row[(j1 + 4) % 5]
                plain_text_pairs.append(plain_text_pair)
                flag = True
                break
        if flag:
            continue
        for j in range(5):
            col = "".join([key_matrix[i][j] for i in range(5)])
            if pair[0] in col and pair[1] in col:
                i0 = col.find(pair[0])
                i1 = col.find(pair[1])
                plain_text_pair = col[(i0 + 4) % 5] + col[(i1 + 4) % 5]
                plain_text_pairs.append(plain_text_pair)
                flag = True
                break
        if flag:
            continue
    return "".join(plain_text_pairs)

def encrypt_playfair(key, plain_text):
    key_matrix = key_generation_playfair(key)
    return conversion_enc_playfair(key_matrix, plain_text)

def decrypt_playfair(key, cipher_text):
    key_matrix = key_generation_playfair(key)
    return conversion_dec_playfair(key_matrix, cipher_text)

# Rail Fence
def encrypt_railfence(text, key):
    rail = [['
' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        row = row + 1 if dir_down else row - 1
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '
':
                result.append(rail[i][j])
    return "".join(result)

def decrypt_railfence(cipher, key):
    rail = [['
' for i in range(len(cipher))] for j in range(key)]
    dir_down = None
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row = row + 1 if dir_down else row - 1
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
        col += 1
        row = row + 1 if dir_down else row - 1
    return "".join(result)

# ================================
# Modern Crypto: RSA, AES, DES, SHA-256
# ================================

# RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(message.encode())
    return to_b64(encrypted)

def rsa_decrypt(private_key, encrypted_text):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher.decrypt(from_b64(encrypted_text))
    return decrypted.decode()

# AES (CBC with PKCS7)
def aes_derive_key(password: str, length=16) -> bytes:
    # derive key from password using SHA-256, truncated to required length
    return hashlib.sha256(password.encode()).digest()[:length]

def aes_encrypt(password, plaintext):
    key = aes_derive_key(password, 16)  # AES-128 by default
    iv = get_random_bytes(BLOCK_SIZE_AES)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE_AES)
    ct = cipher.encrypt(data)
    return to_b64(iv + ct)

def aes_decrypt(password, b64_cipher):
    key = aes_derive_key(password, 16)
    raw = from_b64(b64_cipher)
    iv = raw[:BLOCK_SIZE_AES]
    ct = raw[BLOCK_SIZE_AES:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt).decode()

# DES (CBC with PKCS7)
def des_derive_key(password: str) -> bytes:
    # DES key must be 8 bytes; derive via sha256 and truncate
    return hashlib.sha256(password.encode()).digest()[:8]

def des_encrypt(password, plaintext):
    key = des_derive_key(password)
    iv = get_random_bytes(BLOCK_SIZE_DES)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE_DES)
    ct = cipher.encrypt(data)
    return to_b64(iv + ct)

def des_decrypt(password, b64_cipher):
    key = des_derive_key(password)
    raw = from_b64(b64_cipher)
    iv = raw[:BLOCK_SIZE_DES]
    ct = raw[BLOCK_SIZE_DES:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pkcs7_unpad(pt).decode()

# SHA-256
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

# ================================
# Streamlit UI
# ================================

st.set_page_config(page_title="Cryptography Toolkit", page_icon="🔐", layout="wide")
st.title("🔐 Multi-Cipher Encryption-Decryption App")
st.write("Explore classical and modern cryptography algorithms interactively.")

mode = st.sidebar.radio("Mode", ["Classical Ciphers", "Modern Cryptography", "About & Help"])

if 'history' not in st.session_state:
    st.session_state.history = []

# About explanations
explanations = {
    "Vigenère": "A polyalphabetic substitution cipher that uses a keyword to shift letters.",
    "Caesar": "A substitution cipher that shifts letters by a fixed number.",
    "Playfair": "Uses a 5x5 letter matrix to encrypt pairs of letters.",
    "Rail Fence": "A transposition cipher that writes text in a zig-zag pattern across rails.",
    "RSA": "A modern asymmetric cipher using public and private keys for secure encryption.",
    "AES": "Advanced Encryption Standard (AES) - a symmetric block cipher widely used in secure systems.",
    "DES": "Data Encryption Standard (DES) - an older symmetric cipher (8-byte key).",
    "SHA-256": "SHA-256 is a cryptographic hash function producing a 256-bit digest; it is one-way and not reversible."
}

if mode == "Classical Ciphers":
    st.header("Classical Ciphers")
    cipher_type = st.selectbox("Select Classical Cipher", ["Vigenère", "Caesar", "Playfair", "Rail Fence"])
    operation_type = st.selectbox("Operation", ["Encryption", "Decryption"]) 

    result = ""
    text = ""

    if cipher_type == "Vigenère":
        key = st.text_input("Enter Key", "")
        text = st.text_area("Enter Text", "")
        if not key.isalpha() and key != "":
            st.warning("Key must contain only letters.")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if key and text:
                    result = encryption_vigenere(text, key)
                    st.success("Encrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide key and text.")
        else:
            if st.button("Start Decryption"):
                if key and text:
                    result = decryption_vigenere(text, key)
                    st.success("Decrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide key and text.")

    elif cipher_type == "Caesar":
        key = st.number_input("Enter Shift Value", min_value=1, max_value=25, value=3)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if text:
                    result = encrypt_caesar(text, key)
                    st.success("Encrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start Decryption"):
                if text:
                    result = decrypt_caesar(text, key)
                    st.success("Decrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide text.")

    elif cipher_type == "Playfair":
        key = st.text_input("Enter Key", "")
        text = st.text_area("Enter Text", "")
        if not key.isalpha() and key != "":
            st.warning("Key must contain only letters.")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if key and text:
                    result = encrypt_playfair(key, text)
                    st.success("Encrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide key and text.")
        else:
            if st.button("Start Decryption"):
                if key and text:
                    result = decrypt_playfair(key, text)
                    st.success("Decrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide key and text.")

    elif cipher_type == "Rail Fence":
        key = st.number_input("Enter Number of Rails", min_value=2, value=3)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if text:
                    result = encrypt_railfence(text, key)
                    st.success("Encrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start Decryption"):
                if text:
                    result = decrypt_railfence(text, key)
                    st.success("Decrypted Text shown below")
                    st.code(result)
                else:
                    st.error("Please provide text.")

    if result:
        st.download_button("📥 Download Result", result)
        st.session_state.history.append(("Classical", cipher_type, operation_type, text, result))

elif mode == "Modern Cryptography":
    st.header("Modern Cryptography")
    cipher_type = st.selectbox("Select Modern Technique", ["RSA", "AES", "DES", "SHA-256"]) 
    operation_type = st.selectbox("Operation", ["Encryption", "Decryption"])

    result = ""
    text = ""

    if cipher_type == "RSA":
        st.subheader("RSA Key Generation")
        if st.button("Generate RSA Keys"):
            private_key, public_key = generate_rsa_keys()
            st.session_state['rsa_private'] = private_key
            st.session_state['rsa_public'] = public_key
            st.download_button("Download Public Key", public_key)
            st.download_button("Download Private Key", private_key)

        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start RSA Encryption"):
                if 'rsa_public' in st.session_state:
                    result = rsa_encrypt(st.session_state['rsa_public'], text)
                    st.success("Encrypted Text (base64) shown below")
                    st.code(result)
                else:
                    st.warning("Generate keys first.")
        else:
            if st.button("Start RSA Decryption"):
                if 'rsa_private' in st.session_state:
                    try:
                        result = rsa_decrypt(st.session_state['rsa_private'], text)
                        st.success("Decrypted Text shown below")
                        st.code(result)
                    except Exception as e:
                        st.error("Decryption failed: invalid key/cipher text")
                else:
                    st.warning("Generate keys first.")

    elif cipher_type == "AES":
        st.subheader("AES (CBC) - Symmetric Encryption")
        password = st.text_input("Enter a password to derive AES key (or leave blank to auto-generate)", type="password")
        if st.button("Generate Random AES Password"):
            password = to_b64(get_random_bytes(8))
            st.success("Random password generated (base64) - copy it to use for decryption")
            st.code(password)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start AES Encryption"):
                if text:
                    if not password:
                        st.warning("Please provide a password or generate one.")
                    else:
                        try:
                            result = aes_encrypt(password, text)
                            st.success("Encrypted Text (base64) shown below")
                            st.code(result)
                        except Exception as e:
                            st.error(f"AES encryption failed: {e}")
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start AES Decryption"):
                if text:
                    if not password:
                        st.warning("Please provide the password used during encryption.")
                    else:
                        try:
                            result = aes_decrypt(password, text)
                            st.success("Decrypted Text shown below")
                            st.code(result)
                        except Exception as e:
                            st.error("AES decryption failed: invalid password or ciphertext")

    elif cipher_type == "DES":
        st.subheader("DES (CBC) - Symmetric Encryption")
        password = st.text_input("Enter a password to derive DES key (or leave blank to auto-generate)", type="password", key="des_pwd")
        if st.button("Generate Random DES Password"):
            password = to_b64(get_random_bytes(6))
            st.success("Random password generated (base64) - copy it to use for decryption")
            st.code(password)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start DES Encryption"):
                if text:
                    if not password:
                        st.warning("Please provide a password or generate one.")
                    else:
                        try:
                            result = des_encrypt(password, text)
                            st.success("Encrypted Text (base64) shown below")
                            st.code(result)
                        except Exception as e:
                            st.error(f"DES encryption failed: {e}")
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start DES Decryption"):
                if text:
                    if not password:
                        st.warning("Please provide the password used during encryption.")
                    else:
                        try:
                            result = des_decrypt(password, text)
                            st.success("Decrypted Text shown below")
                            st.code(result)
                        except Exception as e:
                            st.error("DES decryption failed: invalid password or ciphertext")

    elif cipher_type == "SHA-256":
        st.subheader("SHA-256 Hashing (one-way)")
        text = st.text_area("Enter Text", "")
        if st.button("Compute SHA-256 Hash"):
            if text:
                result = sha256_hash(text)
                st.success("SHA-256 Digest (hex) shown below")
                st.code(result)
            else:
                st.error("Please provide text.")

    if result:
        st.download_button("📥 Download Result", result)
        st.session_state.history.append(("Modern", cipher_type, operation_type, text, result))

else:
    st.header("About & Help")
    st.write("This application demonstrates multiple classical and modern cryptography techniques. Use the side menu to switch between Classical and Modern cryptography modes.")
    st.write("Notes:")
    st.write("- SHA-256 is a one-way hash; it cannot be decrypted.")
    st.write("- AES and DES use a password to derive a symmetric key. Keep the password safe for decryption.")
    st.write("- RSA requires you to generate keys first and then use the public key for encryption and the private key for decryption.")

# Finally show recent history
if st.sidebar.checkbox("Show Recent Operations"):
    st.sidebar.write("Recent operations (most recent last):")
    if st.session_state.history:
        st.sidebar.dataframe(st.session_state.history[-10:], width=400)
    else:
        st.sidebar.write("No operations yet.")
