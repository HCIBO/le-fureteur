from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import get_config
from .models import AuditLog, SessionToken, User

_ph = PasswordHasher()
SESSION_COOKIE = "scakit_session"
CSRF_COOKIE = "scakit_csrf"
MIN_PASSWORD = 10


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(hashed: str, pw: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except (VerificationError, InvalidHashError):
        return False


def password_problem(pw: str) -> str | None:
    if len(pw) < MIN_PASSWORD:
        return f"Parola en az {MIN_PASSWORD} karakter olmalı"
    if pw.isdigit() or pw.isalpha():
        return "Parola harf ve rakam / sembol içermeli"
    return None


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, ip: str, user_agent: str = "", method: str = "password") -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(SessionToken(token_hash=_token_hash(token), user_id=user.id, ip=ip, user_agent=user_agent[:400],
                        method=method, last_seen_at=now, last_ip=ip,
                        expires_at=now + timedelta(hours=get_config().session_hours)))
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    return token


def user_for_token(db: Session, token: str | None, ip: str = "") -> User | None:
    if not token:
        return None
    st = db.query(SessionToken).filter_by(token_hash=_token_hash(token)).first()
    if st is None:
        return None
    now = datetime.now(timezone.utc)
    exp = st.expires_at if st.expires_at.tzinfo else st.expires_at.replace(tzinfo=timezone.utc)
    if exp < now or not st.user.active:
        db.delete(st)
        db.commit()
        return None
    seen = st.last_seen_at.replace(tzinfo=st.last_seen_at.tzinfo or timezone.utc) if st.last_seen_at else None
    if seen is None or (now - seen).total_seconds() > 60 or (ip and ip != st.last_ip):
        st.last_seen_at, st.last_ip = now, ip or st.last_ip
        db.commit()
    st.user.session_id = st.id
    return st.user


def end_session(db: Session, token: str | None) -> None:
    if token:
        db.query(SessionToken).filter_by(token_hash=_token_hash(token)).delete()
        db.commit()


def end_user_sessions(db: Session, user_id: int) -> None:
    db.query(SessionToken).filter_by(user_id=user_id).delete()
    db.commit()


def new_csrf() -> str:
    return secrets.token_urlsafe(24)


def csrf_ok(cookie: str | None, header: str | None) -> bool:
    return bool(cookie and header and hmac.compare_digest(cookie, header))


_attempts: dict[str, deque] = defaultdict(deque)
WINDOW, LIMIT = 15 * 60, 10


def throttled(key: str, limit: int = LIMIT, window: int = WINDOW) -> bool:
    q = _attempts[key]
    now = time.time()
    while q and now - q[0] > window:
        q.popleft()
    return len(q) >= max(1, limit)


def record_failure(key: str) -> None:
    _attempts[key].append(time.time())


def clear_failures(key: str) -> None:
    _attempts.pop(key, None)


def _fernet() -> Fernet:
    key = hashlib.sha256(("scakit-settings:" + get_config().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return ""


def audit(db: Session, user: User | None, action: str, obj_type: str = "", obj_id="", detail: str = "",
          ip: str = "") -> None:
    db.add(AuditLog(user_id=user.id if user else None, user_email=user.email if user else "", action=action,
                    object_type=obj_type, object_id=str(obj_id), detail=detail[:2000], ip=ip))
    db.commit()
