"""
main.py — Punto de entrada de la API FastAPI.

Arranca con:
    uvicorn app.main:app --reload

Docs automáticas disponibles en:
    http://localhost:8000/docs       (Swagger UI)
    http://localhost:8000/redoc      (ReDoc)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.database import close_pool, get_pool
from app.limits import limiter
from app.routes import router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Lifecycle (startup / shutdown) ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Iniciando API de Auditoría…")
    await get_pool()          # precalienta el pool de conexiones
    logger.info("Pool PostgreSQL listo  →  %s", settings.db_dsn.split("@")[-1])
    yield
    logger.info("Cerrando pool PostgreSQL…")
    await close_pool()


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ConsultorIA — API de Auditoría de Seguridad",
    version="1.0.0",
    description=(
        "API para registrar solicitudes de auditoría de seguridad. "
        "Persiste datos en PostgreSQL y archivos en MinIO (S3-compatible)."
    ),
    lifespan=lifespan,
    docs_url="/api/docs" if settings.enable_docs else None,
    redoc_url="/api/redoc" if settings.enable_docs else None,
    openapi_url="/api/openapi.json" if settings.enable_docs else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Nota: el header `Server: uvicorn` se quita pasando --no-server-header al CLI
# de uvicorn (en el Dockerfile). El middleware ASGI no puede tocarlo porque
# uvicorn lo añade DESPUÉS, al serializar la respuesta HTTP.


# ── CSRF middleware (A2) ──────────────────────────────────────────────────────
# Double-submit cookie: si la request lleva cookie de sesión y el método cambia
# estado (POST/PUT/PATCH/DELETE), exigimos que el header `X-CSRF-Token` coincida
# con la cookie `consultor_csrf`. Endpoints anónimos (sin auth cookie) NO se ven
# afectados — el formulario público y los logins siguen funcionando.
_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Rutas exentas (login/signup aún no tienen cookie cuando se llaman):
_CSRF_EXEMPT_PATHS = {
    "/api/auth/login",
    "/api/auth/signup",
    "/api/admin/login",
    "/api/audit-request",  # formulario público anónimo
    "/api/btcpay/webhook",  # firma HMAC propia
}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in _CSRF_SAFE_METHODS:
            return await call_next(request)
        if request.url.path in _CSRF_EXEMPT_PATHS:
            return await call_next(request)
        if not request.cookies.get(settings.auth_cookie_name):
            # request anónima (formulario público p.ej.) — no exigimos CSRF
            return await call_next(request)
        cookie_csrf = request.cookies.get(settings.csrf_cookie_name)
        header_csrf = request.headers.get("X-CSRF-Token")
        if not cookie_csrf or not header_csrf or cookie_csrf != header_csrf:
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token inválido o ausente."},
            )
        return await call_next(request)


app.add_middleware(CSRFMiddleware)


# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(router)


# ── Health check (sin prefijo, para el HEALTHCHECK de Docker) ─────────────────
@app.get("/health", include_in_schema=False)
async def health_root():
    return {"status": "ok"}


# ── Dev entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
