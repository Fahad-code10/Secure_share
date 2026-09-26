import streamlit as st
import database as db
import crypto_utils as crypto
from cryptography.exceptions import InvalidTag

st.set_page_config(
    page_title="SecureShare | Cryptographic Transfer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

db.init_db()

# Custom UI Accent CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=JetBrains+Mono:wght@600&display=swap');

    * {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }

    /* Top Banner */
    .top-banner {
        background: linear-gradient(135deg, #0e2038 0%, #08111e 100%);
        border: 1px solid #1e3a5f;
        border-radius: 12px;
        padding: 1.4rem 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Primary Container Cards */
    .vault-box {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 12px;
        padding: 1.8rem;
        margin-bottom: 1.2rem;
    }

    /* Visible Checksum/Hash Display */
    .checksum-badge {
        background-color: #030712;
        border: 1px solid #0284c7;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        font-family: 'JetBrains Mono', monospace;
        color: #38bdf8;
        font-size: 0.92rem;
        word-break: break-all;
    }

    /* Uploader Border Accent */
    [data-testid="stFileUploader"] {
        border: 2px dashed #0284c7 !important;
        border-radius: 10px !important;
        padding: 1rem !important;
    }
</style>
""", unsafe_allow_html=True)

# Authentication Session State
if "user" not in st.session_state:
    st.session_state["user"] = None

def logout():
    st.session_state["user"] = None
    st.rerun()

# ------------------- AUTHENTICATION SCREEN -------------------
if not st.session_state["user"]:
    st.markdown("""
        <div class="top-banner">
            <div>
                <h2 style="color: #38bdf8; margin: 0; font-weight: 800;">🛡️ SecureShare Vault</h2>
                <p style="color: #94a3b8; margin: 0.2rem 0 0 0; font-size: 0.95rem;">Zero-Knowledge Cryptographic Transfer Node</p>
            </div>
            <div style="font-size: 2.2rem;">🔒</div>
        </div>
    """, unsafe_allow_html=True)

    col1, _ = st.columns([1.1, 0.9])
    with col1:
        st.markdown('<div class="vault-box">', unsafe_allow_html=True)
        auth_mode = st.radio("Choose Mode", ["Log In", "Register"], horizontal=True)
        st.write("")

        username = st.text_input("Username").strip()
        password = st.text_input("Password", type="password")
        st.write("")

        if auth_mode == "Register":
            if st.button("Create Account", use_container_width=True, type="primary"):
                if username and password:
                    if db.register_user(username, password):
                        st.success("Account created successfully. You can now log in.")
                    else:
                        st.error("Username already registered.")
                else:
                    st.warning("Both username and password are required.")
        else:
            if st.button("Unlock Dashboard", use_container_width=True, type="primary"):
                if db.verify_user(username, password):
                    st.session_state["user"] = username
                    st.rerun()
                else:
                    st.error("Invalid username or password.")
        st.markdown('</div>', unsafe_allow_html=True)
    st.stop()

# ------------------- MAIN INTERFACE -------------------
st.markdown(f"""
    <div class="top-banner">
        <div>
            <h2 style="color: #38bdf8; margin: 0; font-weight: 800;">🛡️ SecureShare Console</h2>
            <p style="color: #cbd5e1; margin: 0.2rem 0 0 0; font-size: 0.95rem;">Logged in as: <strong style="color: #38bdf8;">{st.session_state['user']}</strong></p>
        </div>
        <div style="background: rgba(2, 132, 199, 0.15); border: 1px solid #0284c7; color: #38bdf8; padding: 0.4rem 0.8rem; border-radius: 6px; font-weight: 700; font-size: 0.85rem;">
            AES-256-GCM Active
        </div>
    </div>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.markdown(f"### 👤 User: `{st.session_state['user']}`")
view = st.sidebar.radio(
    "Navigation Menu",
    ["📤 Encrypt & Share", "📥 Receive & Decrypt", "📁 My Files", "🛡️ Technical Specs"]
)

st.sidebar.markdown("---")
if st.sidebar.button("🚪 Disconnect Session", use_container_width=True):
    logout()

# ------------------- VIEW 1: ENCRYPT & SHARE -------------------
if view == "📤 Encrypt & Share":
    st.markdown('<div class="vault-box">', unsafe_allow_html=True)
    st.subheader("📤 Encrypt New Payload")
    st.caption("Upload a file. A 256-bit AES key is derived via PBKDF2 (600,000 iterations).")

    uploaded_file = st.file_uploader("Select file", type=None)
    enc_password = st.text_input("Set a One-Time Transfer Password", type="password", help="The recipient must use this password to decrypt.")

    if st.button("🔒 Encrypt and Seal File", use_container_width=True, type="primary"):
        if not uploaded_file:
            st.error("Please choose a file to encrypt.")
        elif not enc_password:
            st.error("Please provide an encryption password.")
        else:
            file_bytes = uploaded_file.read()
            original_hash = crypto.compute_sha256(file_bytes)

            with st.spinner("Deriving PBKDF2 key and encrypting..."):
                encrypted_payload = crypto.encrypt_file_data(file_bytes, enc_password)
                share_id = db.store_file_record(
                    filename=uploaded_file.name,
                    original_sha256=original_hash,
                    encrypted_bytes=encrypted_payload,
                    uploader=st.session_state["user"]
                )

            st.success("File sealed and encrypted!")

            col_id, col_hash = st.columns([1, 2])
            with col_id:
                st.metric("Unique Share ID", share_id)
            with col_hash:
                st.markdown("**SHA-256 Digest**")
                st.markdown(f'<div class="checksum-badge">{original_hash}</div>', unsafe_allow_html=True)

            st.info("💡 Share the **Share ID** and the **password** with your intended recipient.")
    st.markdown('</div>', unsafe_allow_html=True)

# ------------------- VIEW 2: RECEIVE & DECRYPT -------------------
elif view == "📥 Receive & Decrypt":
    st.markdown('<div class="vault-box">', unsafe_allow_html=True)
    st.subheader("📥 Retrieve & Decrypt Payload")
    st.caption("Enter the reference ID and shared secret to verify the authentication tag and decrypt.")

    col1, col2 = st.columns(2)
    with col1:
        share_id = st.text_input("12-Character Share ID").strip().upper()
    with col2:
        decrypt_pwd = st.text_input("Decryption Password", type="password")

    if st.button("🔓 Verify Authenticity & Decrypt", use_container_width=True, type="primary"):
        if not share_id or not decrypt_pwd:
            st.warning("Please provide both the Share ID and password.")
        else:
            record = db.get_file_record(share_id)
            if not record:
                st.error("Share ID not found in system.")
            else:
                filename, original_hash, filepath, uploader = record
                try:
                    with open(filepath, "rb") as f:
                        payload = f.read()

                    decrypted_data = crypto.decrypt_file_data(payload, decrypt_pwd)
                    download_hash = crypto.compute_sha256(decrypted_data)

                    st.success("✅ Authentication Tag Verified! File integrity intact.")

                    col_m1, col_m2 = st.columns(2)
                    col_m1.metric("Original SHA-256", f"{original_hash[:16]}...")
                    col_m2.metric("Decrypted SHA-256", f"{download_hash[:16]}...")

                    st.download_button(
                        label=f"⬇️ Download {filename}",
                        data=decrypted_data,
                        file_name=filename,
                        mime="application/octet-stream",
                        use_container_width=True
                    )
                except InvalidTag:
                    st.error("🚨 Decryption Failed! Invalid password or modified ciphertext.")
                except Exception as e:
                    st.error(f"Error reading file: {str(e)}")
    st.markdown('</div>', unsafe_allow_html=True)

# ------------------- VIEW 3: MY FILES -------------------
elif view == "📁 My Files":
    st.markdown('<div class="vault-box">', unsafe_allow_html=True)
    st.subheader("📁 Uploaded Files Inventory")
    files = db.list_user_files(st.session_state["user"])

    if not files:
        st.info("No files stored under this account.")
    else:
        table_rows = [{
            "Share ID": f[0],
            "File Name": f[1],
            "SHA-256 (Prefix)": f"{f[2][:24]}...",
            "Timestamp": f[3]
        } for f in files]
        st.dataframe(table_rows, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ------------------- VIEW 4: TECHNICAL SPECS -------------------
elif view == "🛡️ Technical Specs":
    st.markdown('<div class="vault-box">', unsafe_allow_html=True)
    st.subheader("🛡️ Cryptographic Architecture")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""
        **Symmetric Encryption**
        * **AES-256-GCM**
        * 128-bit authentication tag
        * 96-bit unique IV generated per run via OS CSPRNG
        """)
    with c2:
        st.markdown("""
        **Key Derivation & Hashing**
        * **PBKDF2-HMAC-SHA256**
        * 600,000 iterations (OWASP standard)
        * 128-bit cryptographically secure random salt
        """)
    st.markdown('</div>', unsafe_allow_html=True)
