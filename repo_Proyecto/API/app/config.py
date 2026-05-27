"""
config.py — Carga de variables de entorno con Pydantic Settings.
Todas las credenciales viven en .env (nunca en el código).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    db_host: str = Field("localhost", alias="DB_HOST")
    db_port: int = Field(5432, alias="DB_PORT")
    db_name: str = Field("auditoria_db", alias="DB_NAME")
    db_user: str = Field("postgres", alias="DB_USER")
    db_password: str = Field(..., alias="DB_PASSWORD")

    @property
    def db_dsn(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    # ── MinIO / S3 ────────────────────────────────────────────────────────────
    minio_endpoint: str = Field("localhost:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field("minioadmin", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field("minioadmin123", alias="MINIO_SECRET_KEY")
    minio_bucket: str = Field("audit-files", alias="MINIO_BUCKET")
    minio_secure: bool = Field(False, alias="MINIO_SECURE")

    # ── API ───────────────────────────────────────────────────────────────────
    api_host: str = Field("0.0.0.0", alias="API_HOST")
    api_port: int = Field(8000, alias="API_PORT")
    allowed_origins: str = Field(
        "http://localhost:5500,http://127.0.0.1:5500",
        alias="ALLOWED_ORIGINS",
    )

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    # ── Admin Auth ────────────────────────────────────────────────────────────
    # Genera el hash con:
    #   python3 -c "import bcrypt; print(bcrypt.hashpw(b'TU_PASSWORD', bcrypt.gensalt()).decode())"
    # Genera el secret con:
    #   python3 -c "import secrets; print(secrets.token_hex(32))"
    admin_username: str = Field("admin", alias="ADMIN_USERNAME")
    admin_password_hash: str = Field(..., alias="ADMIN_PASSWORD_HASH")
    # Email del usuario admin semilla en la tabla Usuario — usado por el endpoint
    # legacy /api/admin/login para resolver username='auditor' → email.
    admin_default_email: str = Field(
        "auditor@laconsultoria.cat", alias="ADMIN_DEFAULT_EMAIL"
    )
    jwt_secret: str = Field(..., alias="JWT_SECRET")
    jwt_expire_hours: int = Field(8, alias="JWT_EXPIRE_HOURS")

    # ── Cookies de sesión (A2) ────────────────────────────────────────────────
    # En prod: HTTPS obligatorio, SameSite=Lax (Strict rompería navegaciones
    # cross-tab desde links externos al panel). En dev local con http://, poner
    # COOKIE_SECURE=0 para que el navegador acepte la cookie.
    cookie_secure: bool = Field(True, alias="COOKIE_SECURE")
    cookie_samesite: str = Field("lax", alias="COOKIE_SAMESITE")
    auth_cookie_name: str = Field("consultor_token", alias="AUTH_COOKIE_NAME")
    csrf_cookie_name: str = Field("consultor_csrf", alias="CSRF_COOKIE_NAME")

    # ── Pricing ───────────────────────────────────────────────────────────────
    rate_base_eur_hour: float = Field(80.0, alias="RATE_BASE_EUR_HOUR")
    rate_enterprise_eur_hour: float = Field(150.0, alias="RATE_ENTERPRISE_EUR_HOUR")

    # ── BTCPay ────────────────────────────────────────────────────────────────
    btcpay_url: str = Field("https://pay.laconsultoria.cat", alias="BTCPAY_URL")
    btcpay_api_key: str = Field("", alias="BTCPAY_API_KEY")
    btcpay_store_id: str = Field("", alias="BTCPAY_STORE_ID")
    btcpay_webhook_secret: str = Field("", alias="BTCPAY_WEBHOOK_SECRET")

    # ── Cloudflare Turnstile (anti-bot signup) ────────────────────────────────
    # Vacío en producción = se RECHAZAN todos los signup/login (fail-close).
    # Para deshabilitar en dev local, usa CAPTCHA_DISABLED=1 explícito.
    turnstile_secret: str = Field("", alias="TURNSTILE_SECRET")
    captcha_disabled: bool = Field(False, alias="CAPTCHA_DISABLED")

    # ── Docs OpenAPI ──────────────────────────────────────────────────────────
    # Por defecto desactivadas (no exponer /api/docs ni /api/openapi.json en prod).
    # Para dev local: ENABLE_DOCS=1
    enable_docs: bool = Field(False, alias="ENABLE_DOCS")

    # ── Field-level DB encryption (pgcrypto pgp_sym) ─────────────────────────
    # Master key compartida con orchestrator/.env. Cifrado de columnas
    # no-buscables: acceso.notas, empresa.cif, contacto.{departamento,rol}.
    # Sin esta variable la app no arranca (fail-close).
    db_field_key: str = Field(..., alias="DB_FIELD_KEY")

    # ── Internal auth (bypass captcha para servicios propios) ────────────────
    # Token compartido entre API y servicios internos (auto_poller, etc.) que
    # llegan vía red privada y NO pueden resolver el captcha. Si la request
    # llega con header `X-Internal-Auth: <token>` y el token matchea, la
    # verificación Turnstile se considera satisfecha. Si está vacío, el bypass
    # se desactiva (modo estricto).
    internal_auth_token: str = Field("", alias="INTERNAL_AUTH_TOKEN")


settings = Settings()
