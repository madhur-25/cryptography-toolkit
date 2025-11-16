import streamlit as st
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# ================================
# Cipher Algorithms
# ================================

# ---------------- Vigenère Cipher ----------------
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

# ---------------- Caesar Cipher ----------------
def encrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 + shift) % 26 + 65) if 'A' <= i <= 'Z' else chr((ord(i) - 97 + shift) % 26 + 97) for i in text])

def decrypt_caesar(text, shift):
    return ''.join([chr((ord(i) - 65 - shift) % 26 + 65) if 'A' <= i <= 'Z' else chr((ord(i) - 97 - shift) % 26 + 97) for i in text])

# ---------------- Playfair Cipher ----------------
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

# ---------------- Rail Fence Cipher ----------------
def encrypt_railfence(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
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
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def decrypt_railfence(cipher, key):
    rail = [['\n' for i in range(len(cipher))] for j in range(key)]
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

# ---------------- RSA Cipher ----------------
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(private_key, encrypted_text):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted.decode()

# ================================
# Streamlit UI
# ================================

st.set_page_config(page_title="Cryptography Toolkit", page_icon="🔐", layout="wide")
st.title("🔐 Multi-Cipher Encryption-Decryption App")
st.write("Explore classical and modern cryptography algorithms interactively.")

cipher_type = st.sidebar.selectbox("Select Cipher", ["Vigenère", "Caesar", "Playfair", "Rail Fence", "RSA"])
operation_type = st.sidebar.selectbox("Select Operation", ["Encryption", "Decryption"])

st.sidebar.info("Choose your cipher type and operation mode.")

# Cipher info tabs
tab1, tab2 = st.tabs(["Encrypt / Decrypt", "About Cipher"])

with tab2:
    explanations = {
        "Vigenère": "A polyalphabetic substitution cipher that uses a keyword to shift letters.",
        "Caesar": "A substitution cipher that shifts letters by a fixed number.",
        "Playfair": "Uses a 5x5 letter matrix to encrypt pairs of letters.",
        "Rail Fence": "A transposition cipher that writes text in a zig-zag pattern across rails.",
        "RSA": "A modern asymmetric cipher using public and private keys for secure encryption."
    }
    st.markdown(f"### {cipher_type} Cipher Explanation")
    st.info(explanations[cipher_type])

with tab1:
    result = ""

    if cipher_type == "Vigenère":
        key = st.text_input("Enter Key", "")
        text = st.text_area("Enter Text", "")
        if not key.isalpha() and key != "":
            st.warning("Key must contain only letters.")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if key and text:
                    result = encryption_vigenere(text, key)
                    st.success(f"Encrypted Text: {result}")
                else:
                    st.error("Please provide key and text.")
        else:
            if st.button("Start Decryption"):
                if key and text:
                    result = decryption_vigenere(text, key)
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.error("Please provide key and text.")

    elif cipher_type == "Caesar":
        key = st.number_input("Enter Shift Value", min_value=1, max_value=25, value=3)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if text:
                    result = encrypt_caesar(text, key)
                    st.success(f"Encrypted Text: {result}")
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start Decryption"):
                if text:
                    result = decrypt_caesar(text, key)
                    st.success(f"Decrypted Text: {result}")
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
                    st.success(f"Encrypted Text: {result}")
                else:
                    st.error("Please provide key and text.")
        else:
            if st.button("Start Decryption"):
                if key and text:
                    result = decrypt_playfair(key, text)
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.error("Please provide key and text.")

    elif cipher_type == "Rail Fence":
        key = st.number_input("Enter Number of Rails", min_value=2, value=3)
        text = st.text_area("Enter Text", "")
        if operation_type == "Encryption":
            if st.button("Start Encryption"):
                if text:
                    result = encrypt_railfence(text, key)
                    st.success(f"Encrypted Text: {result}")
                else:
                    st.error("Please provide text.")
        else:
            if st.button("Start Decryption"):
                if text:
                    result = decrypt_railfence(text, key)
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.error("Please provide text.")

    elif cipher_type == "RSA":
        st.subheader("RSA Key Generation")
        if st.button("Generate Keys"):
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
                    st.success(f"Encrypted Text: {result}")
                else:
                    st.warning("Generate keys first.")
        else:
            if st.button("Start RSA Decryption"):
                if 'rsa_private' in st.session_state:
                    result = rsa_decrypt(st.session_state['rsa_private'], text)
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.warning("Generate keys first.")

    if result:
        st.download_button("📥 Download Result", result)

        if 'history' not in st.session_state:
            st.session_state.history = []
        st.session_state.history.append((cipher_type, operation_type, text, result))
        st.write("### Recent Operations")
        st.dataframe(st.session_state.history[-5:])
