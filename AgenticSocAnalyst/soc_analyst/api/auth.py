"""
JWT authentication module for the HallucinatingCrusaders API.

Provides token creation, verification, and a FastAPI dependency that
extracts the current user from the ``Authorization: Bearer <token>`` header.

Password hashing uses bcrypt directly.  Token signing uses python-jose
with the HS256 algorithm.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

from soc_analyst.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OAuth2 scheme (points to the token endpoint)
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class Token(BaseModel):
    """Response body returned after successful authentication."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Claims embedded inside the JWT payload."""

    username: Optional[str] = None


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compare a plain-text password against its bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def get_password_hash(password: str) -> str:
    """Return the bcrypt hash of *password*."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a signed JWT.

    Parameters
    ----------
    data:
        Claims to embed (at minimum ``{"sub": "<username>"}``).
    expires_delta:
        Custom expiry duration.  Falls back to the configured default.

    Returns
    -------
    str
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.auth.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(
        to_encode,
        settings.auth.secret_key,
        algorithm=settings.auth.algorithm,
    )
    return encoded_jwt


def verify_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT.

    Parameters
    ----------
    token:
        The raw JWT string.

    Returns
    -------
    dict
        The decoded payload.

    Raises
    ------
    HTTPException
        If the token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload: Dict[str, Any] = jwt.decode(
            token,
            settings.auth.secret_key,
            algorithms=[settings.auth.algorithm],
        )
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


from fastapi import Request


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
) -> Dict[str, Any]:
    """FastAPI dependency that resolves the authenticated user from the JWT.

    First checks the Authorization header (via oauth2_scheme). If not present,
    falls back to checking the 'access_token' cookie.

    Usage::

        @router.get("/protected")
        async def protected(user: dict = Depends(get_current_user)):
            ...

    Returns
    -------
    dict
        Decoded JWT payload (contains at least ``sub`` with the username).
    """
    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(token)


async def get_current_user_cookie(request: Request) -> Dict[str, Any]:
    """FastAPI dependency that resolves the authenticated user from the JWT.

    It checks:
    1. The 'Authorization' header for a Bearer token.
    2. The 'access_token' cookie.

    If neither is present or is invalid, raises 401.
    """
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(token)


# ---------------------------------------------------------------------------
# Token endpoint logic
# ---------------------------------------------------------------------------

# Pre-hash the default dev password at module load so we never store the
# plain-text value in memory longer than necessary.
_default_password_hash: str = get_password_hash(settings.auth.default_password)


def authenticate_user(username: str, password: str) -> Optional[str]:
    """Validate credentials and return the username on success.

    For development, this checks against the single admin account defined
    in ``settings.auth``.  A production deployment should replace this with
    a proper user store (PostgreSQL table, LDAP, etc.).

    Returns
    -------
    str or None
        The authenticated username, or ``None`` if authentication failed.
    """
    if username == settings.auth.default_username:
        if verify_password(password, _default_password_hash):
            return username
    logger.warning("Failed login attempt for user '%s'.", username)
    return None


async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm,
) -> Token:
    """Validate credentials and issue a JWT.

    This function is wired to ``POST /auth/token`` in the main application.

    Raises
    ------
    HTTPException
        401 if the credentials are invalid.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user})
    logger.info("Issued token for user '%s'.", user)
    return Token(access_token=access_token)


__all__ = [
    "Token",
    "TokenData",
    "create_access_token",
    "verify_token",
    "get_current_user",
    "get_current_user_cookie",
    "authenticate_user",
    "login_for_access_token",
    "get_password_hash",
    "verify_password",
    "oauth2_scheme",
]
