"""
Core Module: Authentication Manager (SQLite Engine)
---------------------------------------------------
Handles user authentication, password hashing, role management, and storage in SQLite database (database/users.db).
Roles: 'guest', 'registered', 'admin'
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from typing import Optional, Dict, Any, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(PROJECT_ROOT, "database")
DB_FILE = os.path.join(DB_DIR, "users.db")

def _get_db_connection():
    """Returns a SQLite connection to database/users.db."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    """Initializes the users SQLite table and default admin account with extended profile fields."""
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'registered',
                email TEXT,
                full_name TEXT,
                phone TEXT,
                organization TEXT,
                designation TEXT,
                auth_provider TEXT DEFAULT 'local',
                created_at TEXT NOT NULL
            )
        """)
        
        # Add column migrations for existing databases
        for col in ["full_name", "phone", "organization", "designation", "auth_provider", "google_sub", "picture"]:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
            except Exception:
                pass
        
        # Check if default admin exists
        cursor.execute("SELECT username FROM users WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_hash, admin_salt = _hash_password("admin123")
            now_iso = datetime.now().isoformat()
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, role, email, full_name, designation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("admin", admin_hash, admin_salt, "admin", "admin@compliance.local", "System Administrator", "Chief Information Security Officer", now_iso)
            )
        conn.commit()

def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hashes password with SHA256 and salt."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashed, salt

# Ensure table exists at module load
_init_db()

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticates username and password against SQLite users table."""
    username_clean = username.strip().lower()
    if not username_clean:
        return None
        
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username_clean,))
        row = cursor.fetchone()
        if not row:
            return None
            
        check_hash, _ = _hash_password(password, row["salt"])
        if check_hash == row["password_hash"]:
            return {
                "username": row["username"],
                "role": row["role"],
                "email": row["email"] or "",
                "full_name": row["full_name"] or row["username"],
                "phone": row["phone"] or "",
                "organization": row["organization"] or "",
                "designation": row["designation"] or ""
            }
    return None

def register_user(
    username: str,
    password: str,
    email: str = "",
    full_name: str = "",
    phone: str = "",
    organization: str = "",
    designation: str = "",
    role: str = "registered",
    auth_provider: str = "local"
) -> tuple[bool, str]:
    """Registers a new user account in SQLite database with extended profile metadata."""
    username_clean = username.strip().lower()
    if not username_clean:
        return False, "Username cannot be empty."
    if len(password) < 4 and auth_provider == "local":
        return False, "Password must be at least 4 characters long."
        
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE LOWER(username) = ?", (username_clean,))
        if cursor.fetchone():
            return False, "Username already exists. Please choose another."

        if email and email.strip():
            cursor.execute("SELECT username FROM users WHERE LOWER(email) = ?", (email.strip().lower(),))
            if cursor.fetchone():
                return False, "An account with this email address is already registered. Please sign in or use another email."

        pwd_hash, salt = _hash_password(password if password else secrets.token_hex(12))
        now_iso = datetime.now().isoformat()
        try:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, email, full_name, phone, organization, designation, auth_provider, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username.strip(),
                    pwd_hash,
                    salt,
                    role,
                    email.strip(),
                    full_name.strip(),
                    phone.strip(),
                    organization.strip(),
                    designation.strip(),
                    auth_provider,
                    now_iso
                )
            )
            conn.commit()
            return True, "Registration successful!"
        except Exception as exc:
            return False, f"Database error: {exc}"

def get_user_role(username: str) -> str:
    """Returns the role of a given username from SQLite ('guest', 'registered', 'admin')."""
    if not username or username == "guest":
        return "guest"
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE LOWER(username) = ?", (username.strip().lower(),))
        row = cursor.fetchone()
        return row["role"] if row else "guest"

def list_all_users() -> List[Dict[str, Any]]:
    """Lists summary of all registered users from SQLite with session statistics."""
    session_db = os.path.join(DB_DIR, "compliance_sessions.db")
    session_counts = {}
    msg_counts = {}
    if os.path.exists(session_db):
        try:
            with sqlite3.connect(session_db) as s_conn:
                s_cursor = s_conn.cursor()
                s_cursor.execute("SELECT username, COUNT(*), SUM(message_count) FROM chat_sessions GROUP BY username")
                for u, c_cnt, m_cnt in s_cursor.fetchall():
                    u_key = (u or "guest").lower()
                    session_counts[u_key] = c_cnt
                    msg_counts[u_key] = m_cnt or 0
        except Exception:
            pass

    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, email, created_at FROM users ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [
            {
                "username": r["username"],
                "role": r["role"],
                "email": r["email"] or "",
                "created_at": r["created_at"],
                "sessions_count": session_counts.get(r["username"].lower(), 0),
                "messages_count": msg_counts.get(r["username"].lower(), 0),
            }
            for r in rows
        ]

def update_user_role(username: str, new_role: str) -> tuple[bool, str]:
    """Updates the role of a user in SQLite database."""
    username_clean = username.strip().lower()
    if username_clean == "admin" and new_role != "admin":
        return False, "Cannot change the role of the primary admin account."
    if new_role not in ["guest", "registered", "admin"]:
        return False, "Invalid role specified."

    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET role = ? WHERE LOWER(username) = ?", (new_role, username_clean))
        conn.commit()
        if cursor.rowcount > 0:
            return True, f"Role for user '{username}' updated to '{new_role}'."
        return False, f"User '{username}' not found."

def delete_user_account(username: str) -> tuple[bool, str]:
    """Deletes a user account and associated chat sessions."""
    username_clean = username.strip().lower()
    if username_clean == "admin":
        return False, "Primary admin account cannot be deleted."

    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE LOWER(username) = ?", (username_clean,))
        conn.commit()
        if cursor.rowcount == 0:
            return False, f"User '{username}' not found."

    # Also clean up chat sessions for deleted user
    session_db = os.path.join(DB_DIR, "compliance_sessions.db")
    if os.path.exists(session_db):
        try:
            with sqlite3.connect(session_db) as s_conn:
                s_cursor = s_conn.cursor()
                s_cursor.execute("DELETE FROM chat_sessions WHERE LOWER(username) = ?", (username_clean,))
                s_conn.commit()
        except Exception:
            pass

    return True, f"User account '{username}' and associated audit data deleted successfully."

def get_user_profile(username: str) -> Optional[Dict[str, Any]]:
    """Fetches comprehensive profile details for a specific username."""
    if not username or username == "guest":
        return None
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username.strip().lower(),))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "username": row["username"],
            "role": row["role"],
            "email": row["email"] or "",
            "full_name": row["full_name"] or row["username"].capitalize(),
            "phone": row["phone"] or "",
            "organization": row["organization"] or "",
            "designation": row["designation"] or "",
            "picture": row["picture"] or "",
            "auth_provider": row["auth_provider"] or "local",
            "created_at": row["created_at"] or ""
        }

def update_user_profile(
    username: str,
    full_name: str,
    email: str,
    phone: str = "",
    organization: str = "",
    designation: str = "",
    picture: str = ""
) -> tuple[bool, str]:
    """Updates user profile information in SQLite database."""
    username_clean = username.strip().lower()
    if not username_clean:
        return False, "Invalid username."
        
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        # Verify user exists
        cursor.execute("SELECT username FROM users WHERE LOWER(username) = ?", (username_clean,))
        if not cursor.fetchone():
            return False, f"User '{username}' not found."
            
        # Check email conflict with another user
        if email and email.strip():
            cursor.execute("SELECT username FROM users WHERE LOWER(email) = ? AND LOWER(username) != ?", (email.strip().lower(), username_clean))
            if cursor.fetchone():
                return False, "This email is already in use by another account."
                
        cursor.execute(
            """
            UPDATE users 
            SET full_name = ?, email = ?, phone = ?, organization = ?, designation = ?, picture = ?
            WHERE LOWER(username) = ?
            """,
            (
                full_name.strip(),
                email.strip(),
                phone.strip(),
                organization.strip(),
                designation.strip(),
                picture.strip(),
                username_clean
            )
        )
        conn.commit()
        return True, "Profile updated successfully!"

def update_user_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    """Validates current password and sets a new password for the user."""
    username_clean = username.strip().lower()
    if len(new_password) < 4:
        return False, "New password must be at least 4 characters long."
        
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username_clean,))
        row = cursor.fetchone()
        if not row:
            return False, f"User '{username}' not found."
            
        # Validate old password (unless admin override or google auth)
        if old_password:
            curr_hash, _ = _hash_password(old_password, row["salt"])
            if curr_hash != row["password_hash"]:
                return False, "Current password is incorrect."
                
        new_hash, new_salt = _hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE LOWER(username) = ?", (new_hash, new_salt, username_clean))
        conn.commit()
        return True, "Password changed successfully!"

def authenticate_or_register_google_user(
    email: str,
    full_name: str = "",
    picture: str = "",
    google_sub: str = ""
) -> Dict[str, Any]:
    """Authenticates or provisions a user account based on verified Google OAuth profile metadata."""
    email_clean = email.strip().lower()
    username = email_clean.split("@")[0] if "@" in email_clean else email_clean
    
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (email_clean, username))
        row = cursor.fetchone()
        
        if row:
            cursor.execute(
                "UPDATE users SET full_name = COALESCE(NULLIF(?, ''), full_name), auth_provider = 'google', google_sub = COALESCE(NULLIF(?, ''), google_sub), picture = COALESCE(NULLIF(?, ''), picture) WHERE username = ?",
                (full_name, google_sub, picture, row["username"])
            )
            conn.commit()
            return {
                "username": row["username"],
                "role": row["role"],
                "email": row["email"] or email_clean,
                "full_name": full_name or row["full_name"] or row["username"],
                "picture": picture or row["picture"] or "",
                "auth_provider": "google"
            }
        else:
            pwd_hash, salt = _hash_password(secrets.token_hex(16))
            now_iso = datetime.now().isoformat()
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt, role, email, full_name, auth_provider, google_sub, picture, created_at)
                VALUES (?, ?, ?, 'registered', ?, ?, 'google', ?, ?, ?)
                """,
                (username, pwd_hash, salt, email_clean, full_name or username.capitalize(), google_sub, picture, now_iso)
            )
            conn.commit()
            return {
                "username": username,
                "role": "registered",
                "email": email_clean,
                "full_name": full_name or username.capitalize(),
                "picture": picture,
                "auth_provider": "google"
            }

# In-memory temporary store for active OTP codes: {email_or_username: otp_code}
_OTP_STORE: Dict[str, str] = {}

def generate_email_otp(identifier: str) -> tuple[bool, str, str]:
    """Generates a dynamic 6-digit OTP code for sign-in via Email Address or Username."""
    clean_id = identifier.strip().lower()
    if not clean_id:
        return False, "Please enter your registered Email Address or Username.", ""
        
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (clean_id, clean_id))
        row = cursor.fetchone()
        
        # Security Enforcement: OTP can ONLY be generated for existing accounts
        if not row:
            return False, f"No account registered with '{identifier}'. Please register an account first.", ""
            
        user_email = row["email"] or clean_id
                
    # Generate 6-digit random OTP
    otp_code = str(secrets.randbelow(900000) + 100000)
    _OTP_STORE[clean_id] = otp_code
    
    # Dispatch OTP via SMTP Email Service
    try:
        import core.email_dispatcher as edispatch
        edispatch.send_otp_email(recipient_email=user_email, otp_code=otp_code, username=row["username"])
    except Exception as e:
        print(f"[SECURITY AUDIT LOG] OTP for user '{clean_id}' ({user_email}): {otp_code} (Error: {e})", flush=True)
    
    return True, f"Verification OTP sent to owner of '{user_email}'. Please check your inbox.", otp_code

def verify_email_otp(identifier: str, input_otp: str) -> tuple[bool, Optional[Dict[str, Any]], str]:
    """Verifies the 6-digit OTP code and returns authenticated user details."""
    clean_id = identifier.strip().lower()
    clean_otp = input_otp.strip()
    
    if not clean_id or not clean_otp:
        return False, None, "Identifier and OTP code are required."
        
    stored_otp = _OTP_STORE.get(clean_id)
    if not stored_otp or stored_otp != clean_otp:
        return False, None, "Invalid or expired OTP code. Please request a new code."
        
    # Clear used OTP
    _OTP_STORE.pop(clean_id, None)
    
    with _get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(username) = ?", (clean_id, clean_id))
        row = cursor.fetchone()
        if row:
            return True, {
                "username": row["username"],
                "role": row["role"],
                "email": row["email"] or ""
            }, "Authentication successful!"
            
    return False, None, "User account not found."
