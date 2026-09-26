import streamlit as st
import database as db
import crypto_utils as crypto
from cryptography.exceptions import InvalidTag

st.set_page_config(page_title="SecureShare - Encrypted File Sharing", page_icon="🔐", layout="wide")
db.init_db()

# Session State for Authentication
if "user" not in st.session_state:
    st.session_state["user"] = None

def logout():
    st.session_state["user"] = None
    st.rerun()

# ----------------- AUTHENTICATION SCREEN -----------------
if not st.session_state["user"]:
    st.title("🔐 SecureShare Portal")
    st.write("Zero-Knowledge Authenticated File Sharing Platform")
    
    auth_mode = st.radio("Choose Mode", ["Login", "Register"], horizontal=True)
    col1, col2 = st.columns([1, 1])
    
    with col1:
        username = st.text_input("Username").strip()
        password = st.text_input("Password", type="password")
        
        if auth_mode == "Register":
            if st.button("Create Account"):
                if username and password:
                    if db.register_user(username, password):
                        st.success("Account registered successfully! Please log in.")
                    else:
                        st.error("Username already exists.")
                else:
                    st.warning("All fields are required.")
                    
        elif auth_mode == "Login":
            if st.button("Log In"):
                if db.verify_user(username, password):
                    st.session_state["user"] = username
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
    st.stop()

# ----------------- MAIN APP SCREEN -----------------
st.sidebar.title("🔐 SecureShare")
st.sidebar.markdown(f"**Logged in as:** `{st.session_state['user']}`")
if st.sidebar.button("Log Out"):
    logout()

st.sidebar.markdown("---")
view = st.sidebar.radio("Navigation", ["📤 Encrypt & Share", "📥 Receive & Decrypt", "📁 My Uploads", "🛡️ Security Specs"])

# View 1: Upload & Encrypt
if view == "📤 Encrypt & Share":
    st.header("📤 Encrypt & Generate Share Link")
    uploaded_file = st.file_uploader("Select file (PDF, DOCX, Images, TXT, ZIP)", type=None)
    enc_password = st.text_input("Set a Decryption Password for Recipient", type="password")
    
    if st.button("🔒 Encrypt and Store"):
        if not uploaded_file:
            st.error("Please upload a file first.")
        elif not enc_password:
            st.error("Please specify an encryption password.")
        else:
            file_bytes = uploaded_file.read()
            original_hash = crypto.compute_sha256(file_bytes)
            
            with st.spinner("Deriving Argon2id key and encrypting with AES-256-GCM..."):
                encrypted_payload = crypto.encrypt_file_data(file_bytes, enc_password)
                share_id = db.store_file_record(
                    filename=uploaded_file.name,
                    original_sha256=original_hash,
                    encrypted_bytes=encrypted_payload,
                    uploader=st.session_state["user"]
                )
                
            st.success("File encrypted and stored safely!")
            st.info(f"**Unique Share ID:** `{share_id}`")
            st.markdown(f"**SHA-256 Hash:** `{original_hash}`")
            st.caption("Send this Share ID and the password out-of-band to the recipient.")

# View 2: Receive & Decrypt
elif view == "📥 Receive & Decrypt":
    st.header("📥 Access & Decrypt Shared File")
    share_id = st.text_input("Enter 12-character Share ID").strip().upper()
    decrypt_pwd = st.text_input("Enter Decryption Password", type="password")
    
    if st.button("🔓 Decrypt File"):
        if not share_id or not decrypt_pwd:
            st.warning("Both Share ID and Password are required.")
        else:
            record = db.get_file_record(share_id)
            if not record:
                st.error("Share ID not found or expired.")
            else:
                filename, original_hash, filepath, uploader = record
                try:
                    with open(filepath, "rb") as f:
                        payload = f.read()
                        
                    decrypted_data = crypto.decrypt_file_data(payload, decrypt_pwd)
                    download_hash = crypto.compute_sha256(decrypted_data)
                    
                    st.success("Authentication tag verified! File decrypted successfully.")
                    
                    # File Integrity Comparison
                    colA, colB = st.columns(2)
                    colA.metric("Stored SHA-256", f"{original_hash[:10]}...")
                    colB.metric("Decrypted SHA-256", f"{download_hash[:10]}...")
                    
                    if original_hash == download_hash:
                        st.caption("✅ Integrity check passed: exact cryptographic match.")
                    
                    st.download_button(
                        label=f"⬇️ Download {filename}",
                        data=decrypted_data,
                        file_name=filename,
                        mime="application/octet-stream"
                    )
                except InvalidTag:
                    st.error("Decryption failed! Incorrect password or corrupted/tampered ciphertext.")
                except Exception as e:
                    st.error(f"Error reading file: {str(e)}")

# View 3: My Uploads
elif view == "📁 My Uploads":
    st.header("📁 Uploaded Files Directory")
    files = db.list_user_files(st.session_state["user"])
    if not files:
        st.write("No files shared yet.")
    else:
        st.table([{
            "Share ID": f[0],
            "File Name": f[1],
            "SHA-256": f"{f[2][:16]}...",
            "Uploaded At": f[3]
        } for f in files])

# View 4: Security Specs
elif view == "🛡️ Security Specs":
    st.header("🛡️ System Architecture & Threat Model")
    st.markdown("""
    * **Encryption Algorithm:** `AES-256-GCM` (Authenticated Encryption with Associated Data).
    * **Key Derivation Function:** `Argon2id` (64MB memory hardness, 2 iterations, 4 lanes).
    * **Integrity Guarantee:** The 16-byte Poly1305/GHASH authentication tag detects bit-flips or corruption before decoding plaintext.
    * **Zero-Knowledge Principle:** Plaintext file passwords are never saved in the database or server logs.
    """)