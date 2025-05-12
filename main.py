import streamlit as st
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# In-memory data storage
stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
failed_attempt = 0  # Track failed attempts globally

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to generate AES key
def generate_key():
    return os.urandom(16)  # AES key size is 16 bytes

# Function to encrypt data using AES
def encrypt_data(plaintext, passkey):
    key = hash_passkey(passkey)[:16].encode()  # Use the first 16 bytes of the hashed passkey as the key
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext.encode().ljust(16 * ((len(plaintext) + 15) // 16))  # PKCS7 padding
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()  # Combine IV and ciphertext

# Function to decrypt data using AES
def decrypt_data(encrypted_text, passkey):
    global failed_attempt  # Declare failed_attempt as global
    hashed_passkey = hash_passkey(passkey)

    key = hashed_passkey[:16].encode()  # Use the first 16 bytes of the hashed passkey as the key
    encrypted_data = base64.b64decode(encrypted_text.encode())
    iv = encrypted_data[:16]  # Extract the IV
    ciphertext = encrypted_data[16:]  # Get the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    plaintext = padded_plaintext.rstrip()
    
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempt = 0
            return plaintext.decode()

    failed_attempt += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data page
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

# Retrieve Data page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        global failed_attempts  # Declare failed_attempt as global for retrieval
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempt}")

                if failed_attempt >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

# Login page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo; replace with proper auth
            failed_attempt = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
