"""
auth.py — JWT + bcrypt para autenticación multi-cliente.

A2 (2026-05-18): el token vive ahora en una cookie HttpOnly + Secure +
SameSite=Lax (`consultor_token`). Para protección CSRF se emite además una
cookie pública (no HttpOnly) `consultor_csrf` con un valor aleatorio que el
frontend debe reenviar como header `X-CSRF-Token` en cada petición que
cambie estado (POST/PUT/PATCH/DELETE). La validación double-submit se hace
en el middleware en `app.main`.

Compatibilidad: `require_user`/`require_admin` aceptan también el header
`Authorization: Bearer <jwt>` para que clientes ya autenticados antes del
despliegue (sessionStorage residual) sigan funcionando hasta su próximo login.
Esta vía se eliminará una vez todos los clientes hayan rotado.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

# auto_error=False: queremos poder caer en la cookie si no hay header.
_bearer = HTTPBearer(auto_error=False)


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# Hash dummy precomputado al import del módulo. Sirve para que verify_password_ct
# tarde el mismo tiempo cuando el email no existe que cuando existe con password
# mal — elimina el side-channel de timing para enumerar usuarios.
_DUMMY_HASH = bcrypt.hashpw(b"\x00" * 32, bcrypt.gensalt(rounds=12)).decode()


def verify_password_ct(plain: str, hashed: str | None) -> bool:
    """verify_password constant-time vs enumeración.
    Si `hashed` es None, ejecuta bcrypt contra un hash dummy y devuelve False —
    así el caller no puede medir si el email existe por el tiempo de respuesta.
    """
    target = hashed if hashed is not None else _DUMMY_HASH
    ok = bcrypt.checkpw(plain.encode(), target.encode())
    return ok if hashed is not None else False


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(user_id: int, rol: str) -> str:
    """Genera un JWT con user_id (sub) + rol + jti único."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "rol": rol,
        "iat": now,
        "exp": now + timedelta(hours=settings.jwt_expire_hours),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def _decode_token(token: str) -> dict:
    """Devuelve el payload decodificado o lanza HTTPException 401."""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado. Vuelve a iniciar sesión.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Cookies de sesión + CSRF (A2) ─────────────────────────────────────────────

def set_auth_cookies(response: Response, user_id: int, rol: str) -> str:
    """Emite cookie JWT HttpOnly + cookie CSRF pública. Devuelve el token JWT
    para que el endpoint pueda también incluirlo en el JSON (compatibilidad
    con clientes que aún esperan `access_token`)."""
    token = create_access_token(user_id, rol)
    csrf = secrets.token_urlsafe(32)
    max_age = settings.jwt_expire_hours * 3600
    samesite = settings.cookie_samesite if settings.cookie_samesite in (
        "lax", "strict", "none") else "lax"
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=samesite,
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf,
        max_age=max_age,
        httponly=False,  # lo lee el JS y lo reenvía en X-CSRF-Token
        secure=settings.cookie_secure,
        samesite=samesite,
        path="/",
    )
    return token


def clear_auth_cookies(response: Response) -> None:
    """Limpia las cookies de sesión en /auth/logout y en 401."""
    for name in (settings.auth_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(name, path="/")


def _extract_token(request: Request,
                   credentials: HTTPAuthorizationCredentials | None) -> str:
    """Devuelve el JWT desde la cookie de sesión o desde Authorization: Bearer.
    La cookie tiene prioridad — si está presente la usamos aunque venga también
    el header (típicamente no pasa)."""
    token = request.cookies.get(settings.auth_cookie_name)
    if token:
        return token
    if credentials is not None and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Dependencias FastAPI ──────────────────────────────────────────────────────

def require_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Cualquier usuario autenticado. Devuelve {id: int, rol: str}.
    Acepta cookie HttpOnly (preferido) o Authorization: Bearer."""
    token = _extract_token(request, credentials)
    payload = _decode_token(token)
    try:
        return {"id": int(payload["sub"]), "rol": payload.get("rol", "cliente")}
    except (KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Token sin sub válido.")


def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Solo administradores."""
    user = require_user(request, credentials)
    if user["rol"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren permisos de administrador.",
        )
    return user
