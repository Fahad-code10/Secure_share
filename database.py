import sqlite3
import os
import hashlib
import uuid

DB_NAME = "secureshare.db"
UPLOAD_DIR = "encrypted_store"

def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    
    # User accounts table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    
    # Shared files metadata table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            share_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            original_sha256 TEXT NOT NULL,
            stored_filepath TEXT NOT NULL,
            uploader TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def hash_user_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if not salt:
        salt = os.urandom(16)
    pwd_hash = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return pwd_hash, salt.hex()

def register_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    try:
        pwd_hash, salt_hex = hash_user_password(password)
        cur.execute("INSERT INTO users VALUES (?, ?, ?)", (username, pwd_hash, salt_hex))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return False
    stored_hash, salt_hex = row
    check_hash, _ = hash_user_password(password, bytes.fromhex(salt_hex))
    return check_hash == stored_hash

def store_file_record(filename: str, original_sha256: str, encrypted_bytes: bytes, uploader: str) -> str:
    share_id = uuid.uuid4().hex[:12].upper()
    stored_filename = f"{share_id}.enc"
    full_path = os.path.join(UPLOAD_DIR, stored_filename)
    
    with open(full_path, "wb") as f:
        f.write(encrypted_bytes)
        
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO shared_files VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (share_id, filename, original_sha256, full_path, uploader)
    )
    conn.commit()
    conn.close()
    return share_id

def get_file_record(share_id: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT filename, original_sha256, stored_filepath, uploader FROM shared_files WHERE share_id = ?", (share_id,))
    row = cur.fetchone()
    conn.close()
    return row

def list_user_files(uploader: str):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT share_id, filename, original_sha256, created_at FROM shared_files WHERE uploader = ?", (uploader,))
    rows = cur.fetchall()
    conn.close()
    return rows