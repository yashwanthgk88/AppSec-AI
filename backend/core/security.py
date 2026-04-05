from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from jose import JWTError, jwt
import bcrypt
import hashlib
import secrets
import sqlite3
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from models.database import get_db
from models.models import User
import os
import time
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password: str) -> str:
    """Hash password"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()

    # Use time.time() to get the correct UTC timestamp
    if expires_delta:
        expire = int(time.time()) + int(expires_delta.total_seconds())
    else:
        expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> dict:
    """Decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if payload is None:
        raise credentials_exception

    user_id_str: str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# ---------------------------------------------------------------------------
# API Key Authentication (for external integrations)
# ---------------------------------------------------------------------------
def _get_db_path():
    persistent_path = "/app/data/appsec.db"
    if os.path.exists("/app/data"):
        return persistent_path
    return "appsec.db"


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, key_hash, key_prefix)."""
    raw_key = f"apsk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]
    return raw_key, key_hash, key_prefix


def verify_api_key(raw_key: str) -> Optional[dict]:
    """Verify an API key and return its metadata if valid."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
        (key_hash,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    row_dict = dict(row)

    # Check expiry
    if row_dict.get("expires_at"):
        from datetime import datetime as dt
        try:
            exp = dt.fromisoformat(row_dict["expires_at"])
            if exp < dt.utcnow():
                conn.close()
                return None
        except Exception:
            pass

    # Update last_used_at
    cursor.execute(
        "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
        (row_dict["id"],),
    )
    conn.commit()
    conn.close()
    return row_dict


def get_api_key_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Extract API key from X-API-Key header and return the owning user."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None

    key_data = verify_api_key(api_key)
    if not key_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    user = db.query(User).filter(User.id == key_data["created_by_user_id"]).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key owner account is inactive",
        )

    # Attach key metadata to request state for scope checking
    request.state.api_key_scopes = key_data.get("scopes", '["threat_intel"]')
    return user


def get_current_user_or_api_key(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Authenticate via JWT token OR API key (X-API-Key header).

    Use this dependency on endpoints that should be accessible to external systems.
    """
    # Try API key first (doesn't require Authorization header)
    api_key = request.headers.get("X-API-Key")
    if api_key:
        user = get_api_key_user(request, db)
        if user:
            return user

    # Fall back to JWT
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        try:
            payload = decode_token(token)
            if payload:
                user_id_str = payload.get("sub")
                if user_id_str:
                    user = db.query(User).filter(User.id == int(user_id_str)).first()
                    if user and user.is_active:
                        return user
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Provide a valid JWT token (Authorization: Bearer <token>) or API key (X-API-Key header)",
    )
