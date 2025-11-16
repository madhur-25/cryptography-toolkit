import streamlit as st
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# ================================
# Utility Helpers
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
# Classical Ciphers
# ================================
# -------- Vigenere --------
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
            cipher_text += chr(encrypt_num + ord('a'))
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
            decrypt = chr((ord(c) - ord('a') + (26 - off)) % 26 + ord('a'))
            plain_text += decrypt
            index = (index + 1) % len(key)
        else:
            plain_text += c
    return plain_text


# -------- Caesar --------
def encrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 + shift) % 26 + 65) if 'A' <= i <= 'Z'
                    else chr((ord(i) - 97 + shift) % 26 + 97) for i in text])


def decrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 - shift) % 26 + 65) if 'A' <= i <= 'Z'
                    else chr((ord(i) - 97 - shift) % 26 + 97) for i in text])


# -------- Playfair --------
def key_generation_playfair(key):
    main = string.ascii_lowercase.replace('j', '.')
    key = key.lower()
    key_matrix = ['' for _ in range(5)]
    i = j = 0

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
    plain_text = plain_text.replace(" ", "").lower()
    plain_text_pairs = []
    cipher_text_pairs = []

    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        b = plain_text[i + 1] if (i + 1) < len(plain_text) else 'x'
        if a == b:
            plain_text_pairs.append(a + 'x')
            i += 1
        else:
            plain_text_pairs.append(a + b)
            i += 2

    for pair in plain_text_pairs:
        # Same row
        for row in key_matrix:
            if pair[0] in row and pair[1] in row:
                j0 = row.find(pair[0])
                j1 = row.find(pair[1])
                cipher_text_pairs.append(row[(j0 + 1) % 5] + row[(j1 + 1) % 5])
                break
        else:
            # Same column
            for col_index in range(5):
                col = ''.join([key_matrix[r][col_index] for r in range(5)])
                if pair[0] in col and pair[1] in col:
                    i0 = col.find(pair[0])
                    i1 = col.find(pair[1])
                    cipher_text_pairs.append(col[(i0 + 1) % 5] + col[(i1 + 1) % 5])
                    break

    return "".join(cipher_text_pairs)


def conversion_dec_playfair(key_matrix, cipher_text):
    cipher_text = cipher_text.lower()
    pairs = [cipher_text[i:i+2] for i in range(0, len(cipher_text), 2)]
    result = []

    for pair in pairs:
        # Same row
        for row in key_matrix:
            if pair[0] in row and pair[1] in row:
                j0 = row.find(pair[0])
                j1 = row.find(pair[1])
                result.append(row[(j0 - 1) % 5] + row[(j1 - 1) % 5])
                break
        else:
            # Same column
            for col_index in range(5):
                col = ''.join([key_matrix[r][col_index] for r in range(5)])
                if pair[0] in col and pair[1] in col:
                    i0 = col.find(pair[0])
                    i1 = col.find(pair[1])
                    result.append(col[(i0 - 1) % 5] + col[(i1 - 1) % 5])
                    break

    return "".join(result)


def encrypt_playfair(key, pt):
    return conversion_enc_playfair(key_generation_playfair(key), pt)


def decrypt_playfair(key, ct):
    return conversion_dec_playfair(key_generation_playfair(key), ct)


# -------- Rail Fence (FIXED) --------
def encrypt_railfence(text, key):
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row = col = 0

    for i in range(len(text)):
        if row == 0 or row == key - 1:
            dir_down = not dir_down

        rail[row][col] = text[i]
        col += 1
        row = row + 1 if dir_down else row - 1

    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])

    return "".join(result)


def decrypt_railfence(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    dir_down = None
    row = col = 0

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
    row = col = 0
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
# Modern Crypto
# ================================
# ---- RSA ----
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(pub, message):
    key = RSA.import_key(pub)
    cipher = PKCS1_OAEP.new(key)
    return to_b64(cipher.encrypt(message.encode()))

def rsa_decrypt(priv, message):
    key = RSA.import_key(priv)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(from_b64(message)).decode()

# ---- AES ----
def aes_derive_key(password: str, length=16):
    return hashlib.sha256(password.encode()).digest()[:length]

def aes_encrypt(password, plaintext):
    key = aes_derive_key(password)
    iv = get_random_bytes(BLOCK_SIZE_AES)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE_AES)
    return to_b64(iv + cipher.encrypt(data))

def aes_decrypt(password, b64):
    key = aes_derive_key(password)
    raw = from_b64(b64)
    iv = raw[:BLOCK_SIZE_AES]
    ct = raw[BLOCK_SIZE_AES:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ct)).decode()

# ---- DES ----
def des_derive_key(password: str):
    return hashlib.sha256(password.encode()).digest()[:8]

def des_encrypt(password, plaintext):
    key = des_derive_key(password)
    iv = get_random_bytes(BLOCK_SIZE_DES)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    data = pkcs7_pad(plaintext.encode(), BLOCK_SIZE_DES)
    return to_b64(iv + cipher.encrypt(data))

def des_decrypt(password, b64):
    key = des_derive_key(password)
    raw = from_b64(b64)
    iv = raw[:BLOCK_SIZE_DES]
    ct = raw[BLOCK_SIZE_DES:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return pkcs7_unpad(cipher.decrypt(ct)).decode()

# ---- SHA256 ----
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ================================
# Streamlit UI
# ================================
st.set_page_config(page_title="Cryptography Toolkit", page_icon="🔐", layout="wide")
st.title("🔐 Multi-Cipher Encryption-Decryption App")

mode = st.sidebar.radio("Mode", ["Classical Ciphers", "Modern Cryptography", "About & Help"])

if 'history' not in st.session_state:
    st.session_state.history = []


# ================================
# CLASSICAL
# ================================
if mode == "Classical Ciphers":
    st.header("Classical Ciphers")
    cipher = st.selectbox("Select Cipher", ["Vigenère", "Caesar", "Playfair", "Rail Fence"])
    op = st.selectbox("Operation", ["Encryption", "Decryption"])
    text = ""
    result = ""

    if cipher == "Vigenère":
        key = st.text_input("Key")
        text = st.text_area("Text")
        if op == "Encryption" and st.button("Encrypt"):
            result = encryption_vigenere(text, key)
        if op == "Decryption" and st.button("Decrypt"):
            result = decryption_vigenere(text, key)

    elif cipher == "Caesar":
        shift = st.number_input("Shift", min_value=1, max_value=25, value=3)
        text = st.text_area("Text")
        if op == "Encryption" and st.button("Encrypt"):
            result = encrypt_caesar(text, shift)
        if op == "Decryption" and st.button("Decrypt"):
            result = decrypt_caesar(text, shift)

    elif cipher == "Playfair":
        key = st.text_input("Key")
        text = st.text_area("Text")
        if op == "Encryption" and st.button("Encrypt"):
            result = encrypt_playfair(key, text)
        if op == "Decryption" and st.button("Decrypt"):
            result = decrypt_playfair(key, text)

    elif cipher == "Rail Fence":
        rails = st.number_input("Rails", min_value=2, value=3)
        text = st.text_area("Text")
        if op == "Encryption" and st.button("Encrypt"):
            result = encrypt_railfence(text, rails)
        if op == "Decryption" and st.button("Decrypt"):
            result = decrypt_railfence(text, rails)

    if result:
        st.success("Result:")
        st.code(result)


# ================================
# MODERN
# ================================
elif mode == "Modern Cryptography":
    st.header("Modern Cryptography")
    cipher = st.selectbox("Select Technique", ["RSA", "AES", "DES", "SHA-256"])
    op = st.selectbox("Operation", ["Encryption", "Decryption"])

    text = ""
    result = ""

    # ---------- RSA ----------
    if cipher == "RSA":
        if st.button("Generate Keys"):
            priv, pub = generate_rsa_keys()
            st.session_state['priv'] = priv
            st.session_state['pub'] = pub
            st.success("Keys Generated!")

        text = st.text_area("Text")

        if op == "Encryption" and st.button("Encrypt"):
            if 'pub' in st.session_state:
                result = rsa_encrypt(st.session_state['pub'], text)
            else:
                st.error("Generate keys first!")
        if op == "Decryption" and st.button("Decrypt"):
            if 'priv' in st.session_state:
                result = rsa_decrypt(st.session_state['priv'], text)
            else:
                st.error("Generate keys first!")

    # ---------- AES ----------
    elif cipher == "AES":
        password = st.text_input("Password", type="password")
        text = st.text_area("Text")

        if op == "Encryption" and st.button("Encrypt"):
            result = aes_encrypt(password, text)
        if op == "Decryption" and st.button("Decrypt"):
            try:
                result = aes_decrypt(password, text)
            except:
                st.error("Wrong password or ciphertext.")

    # ---------- DES ----------
    elif cipher == "DES":
        password = st.text_input("Password", type="password")
        text = st.text_area("Text")

        if op == "Encryption" and st.button("Encrypt"):
            result = des_encrypt(password, text)
        if op == "Decryption" and st.button("Decrypt"):
            try:
                result = des_decrypt(password, text)
            except:
                st.error("Wrong password or ciphertext.")

    # ---------- SHA256 ----------
    elif cipher == "SHA-256":
        text = st.text_area("Text")
        if st.button("Hash"):
            result = sha256_hash(text)

    # Show output
    if result:
        st.success("Result:")
        st.code(result)


# ================================
# ABOUT
# ================================
else:
    st.header("Help")
    st.info("AES, DES = Symmetric\nRSA = Asymmetric\nSHA256 = One-way hash")

