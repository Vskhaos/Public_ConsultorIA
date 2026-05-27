"""
schemas.py — Modelos Pydantic para validar el payload del formulario.

El frontend envía multipart/form-data (archivos + JSON en campo "data").
FastAPI lo deserializa y Pydantic valida cada campo con mensajes claros.
"""
from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

# Mapeo de los códigos de duración del select a días naturales (para
# calcular fecha_final por defecto). Las opciones de horas (1h/4h/8h y
# 'custom_<N>h' generadas por el frontend) ocupan el mismo día.
DURATION_DAYS: dict[str, int] = {
    "1h":  1,
    "4h":  1,
    "8h":  1,
    "1d":  1,
    "2-3d": 3,
    "1w":  7,
    "2w":  14,
    "1m":  30,
}


def _duration_days_for(duration: str | None) -> int | None:
    """Igual que el dict pero acepta 'custom_<N>h' (1 día, sea cual sea N)."""
    if not duration:
        return None
    if duration in DURATION_DAYS:
        return DURATION_DAYS[duration]
    if duration.startswith("custom_") and duration.endswith("h"):
        return 1
    return None


class AuditRequestSchema(BaseModel):
    """
    Payload principal que llega como campo JSON 'data' en el multipart.
    Refleja exactamente lo que construye el JS del formulario.
    """
    ref: str
    company: str
    sector: Optional[str] = None
    domain: Optional[str] = None

    contact: str
    role: str
    department: Optional[str] = None
    email: EmailStr
    phone: Optional[str] = None

    ips: list[str] = []
    scope: list[str]
    tunnel: Optional[str] = None      # "wireguard" | "ssh" | None
    scope_notes: Optional[str] = None

    audit_date: date
    duration: Optional[str] = None
    fecha_final: Optional[date] = None      # calculada automáticamente
    horario_preferido: Optional[str] = None  # ej: "09:00-18:00"
    priority: Optional[str] = "low"

    submitted_at: Optional[str] = None

    # ── Validaciones ──────────────────────────────────────────────────────────

    @field_validator("company", "contact", "role")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("El campo no puede estar vacío")
        return v.strip()

    @field_validator("scope")
    @classmethod
    def scope_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Debe seleccionarse al menos un tipo de auditoría")
        return v

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        ip_re = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        )
        for ip in v:
            if not ip_re.match(ip):
                raise ValueError(f"IP o CIDR inválido: {ip}")
        return v

    @field_validator("tunnel")
    @classmethod
    def validate_tunnel(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in ("wireguard", "ssh"):
            raise ValueError("tunnel debe ser 'wireguard' o 'ssh'")
        return v

    @field_validator("audit_date")
    @classmethod
    def date_not_past(cls, v: date) -> date:
        if v < date.today():
            raise ValueError("La fecha de inicio no puede ser pasada")
        return v

    @field_validator("priority")
    @classmethod
    def valid_priority(cls, v: Optional[str]) -> Optional[str]:
        allowed = {"low", "medium", "high", None}
        if v not in allowed:
            raise ValueError(f"priority debe ser uno de: {allowed - {None}}")
        return v

    @model_validator(mode="after")
    def compute_fecha_final(self) -> "AuditRequestSchema":
        """Calcula fecha_final a partir de audit_date + duration si no viene ya informada."""
        if self.fecha_final is None:
            days = _duration_days_for(self.duration)
            if days:
                self.fecha_final = self.audit_date + timedelta(days=days - 1)
        return self


class AuditResponseSchema(BaseModel):
    """Respuesta devuelta al frontend tras una solicitud exitosa."""
    ok: bool = True
    ref: str
    empresa_id: int
    contacto_id: int
    acceso_id: int
    uploaded_files: list[str] = []
    message: str = "Solicitud registrada correctamente"


class AdminLoginSchema(BaseModel):
    """Credenciales para el login del panel de administración."""
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)
    # Token Turnstile (widget invisible). Si TURNSTILE_SECRET vacío se ignora.
    turnstile_token: Optional[str] = Field(None, max_length=2048)


# ─────────────────────────────────────────────────────────────────────────────
# Auth multi-cliente (introducido en migración 002 — 1 Usuario : N Empresas)
# ─────────────────────────────────────────────────────────────────────────────


class EmpresaCreateSchema(BaseModel):
    """Empresa que el cliente asocia a su cuenta. Sin alcance técnico aquí —
    el alcance (dominio/ips/scope) va en cada Acceso (auditoría)."""
    nombre: str = Field(..., min_length=1, max_length=255)
    sectores: list[str] = Field(default_factory=list)
    cif: Optional[str] = Field(None, max_length=20)

    @field_validator("nombre")
    @classmethod
    def _trim_nombre(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("El nombre de la empresa no puede estar vacío")
        return v

    @field_validator("cif")
    @classmethod
    def _validate_cif(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().upper().replace(" ", "").replace("-", "")
        if not v:
            return None
        # CIF: letra + 7 dígitos + dígito/letra control. NIF: 8 dígitos + letra.
        # NIE: X/Y/Z + 7 dígitos + letra. Acepta cualquiera con regex laxo.
        if not re.match(r"^[A-Z]?\d{7,8}[A-Z0-9]$", v):
            raise ValueError("CIF/NIF/NIE inválido")
        return v


class EmpresaPatchSchema(BaseModel):
    """Body de PATCH /api/me/empresas/{id} — campos editables del perfil."""
    cif: Optional[str] = Field(None, max_length=20)

    @field_validator("cif")
    @classmethod
    def _validate_cif(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().upper().replace(" ", "").replace("-", "")
        if not v:
            return None
        if not re.match(r"^[A-Z]?\d{7,8}[A-Z0-9]$", v):
            raise ValueError("CIF/NIF/NIE inválido")
        return v


class DescargoEstadoSchema(BaseModel):
    """Estado del descargo de una auditoría concreta."""
    acceso_id: int
    ref: str
    estado: str            # 'pendiente_descargo' | 'pendiente' | ...
    descargo_id: Optional[int] = None
    signer_dn: Optional[str] = None
    signer_serial: Optional[str] = None
    firmado_at: Optional[str] = None
    verificado_at: Optional[str] = None
    valido: Optional[bool] = None


class PrecioPreviewSchema(BaseModel):
    """GET /api/me/audits/{ref}/precio — desglose del precio."""
    ref: str
    importe_eur: float
    rate_eur_hour: float
    horas: float
    mult_tipo: float
    mult_prio: float
    tier: str


class PagoCreateRequestSchema(BaseModel):
    """POST /api/me/audits/{ref}/pay — body."""
    codigo_promo: Optional[str] = Field(None, max_length=64)


class PagoResponseSchema(BaseModel):
    """Respuesta del endpoint /pay."""
    ok: bool
    paid: bool                 # true si quedó pagado en el momento (promo 100%)
    importe_eur: float         # bruto
    descuento_eur: float
    importe_final_eur: float
    pago_id: int
    metodo: str                # 'btcpay' | 'promo_bypass'
    codigo_aplicado: Optional[str] = None
    btcpay_url: Optional[str] = None
    btcpay_invoice_id: Optional[str] = None


class DescargoFirmaResponseSchema(BaseModel):
    """Respuesta de POST /api/me/audits/{ref}/descargo/firmar."""
    ok: bool
    valid: bool
    sha256: str
    descargo_id: Optional[int] = None
    signer_dn: Optional[str] = None
    signer_serial: Optional[str] = None
    firmado_at: Optional[str] = None
    estado_audit: Optional[str] = None
    error: Optional[str] = None


class UserSignupSchema(BaseModel):
    """Registro de un nuevo cliente. Las empresas iniciales son opcionales —
    también se pueden añadir luego desde el dashboard."""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    nombre: Optional[str] = Field(None, max_length=255)
    empresas: list[EmpresaCreateSchema] = Field(default_factory=list)
    # Token de Cloudflare Turnstile (widget invisible en el front).
    # Si la verificación está desactivada (TURNSTILE_SECRET vacío) se ignora.
    turnstile_token: Optional[str] = Field(None, max_length=2048)


class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., max_length=256)
    # Token Turnstile (widget invisible). Si TURNSTILE_SECRET vacío se ignora.
    turnstile_token: Optional[str] = Field(None, max_length=2048)


class UserMeSchema(BaseModel):
    """Respuesta de GET /api/auth/me — datos no sensibles del usuario logueado."""
    id: int
    email: EmailStr
    nombre: Optional[str] = None
    rol: str
    email_verified: bool
    empresas: list[dict] = Field(default_factory=list)  # [{id, nombre, sectores: [...]}]


class ChangePasswordSchema(BaseModel):
    old_password: str = Field(..., max_length=256)
    new_password: str = Field(..., min_length=8, max_length=128)


class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserMeSchema


class UploadResponseSchema(BaseModel):
    """Respuesta de POST /api/me/uploads — el cliente sube archivo y recibe
    su object_key + sha256 calculado server-side. Después referencia ese
    object_key al crear la petición de auditoría."""
    object_key: str
    sha256: str
    size: int
    filename: str
    kind: str  # 'wg_conf' | 'ssh_key'


# ─────────────────────────────────────────────────────────────────────────────
# Petición de auditoría desde el dashboard cliente (T3)
# ─────────────────────────────────────────────────────────────────────────────


class ClientAuditContactSchema(BaseModel):
    nombre: str = Field(..., min_length=1, max_length=255)
    rol: Optional[str] = Field(None, max_length=100)
    departamento: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None     # si null, usa el del Usuario logueado
    telefono: Optional[str] = Field(None, max_length=30)


class ClientAuditCreateSchema(BaseModel):
    """Body de POST /api/me/audits — el usuario autenticado pide una auditoría
    contra una de SUS empresas. La empresa ya existe; aquí solo se persisten
    el alcance técnico (Acceso) y el representante (Contacto)."""
    empresa_id: int
    ref: str = Field(..., min_length=4, max_length=50)
    dominio: Optional[str] = Field(None, max_length=255)
    dominios_extra: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    scope: list[str]
    audit_date: date
    duration: Optional[str] = None
    fecha_final: Optional[date] = None
    horario_preferido: Optional[str] = Field(None, max_length=20)
    priority: Optional[str] = "low"
    tunnel: Optional[str] = None    # 'wireguard' | 'ssh' | None
    # Object keys de archivos pre-subidos via POST /api/me/uploads (opcional).
    # El backend los copiará a su key final {ref}/wg_config.conf | ssh_key.pem.
    wg_object_key: Optional[str] = None
    ssh_object_key: Optional[str] = None
    scope_notes: Optional[str] = None
    contact: ClientAuditContactSchema
    # Solo aplica si el usuario es admin (rol=admin). Si True, salta el step
    # 'pendiente_descargo' y crea el audit directo en 'pendiente_pago'. El
    # backend ignora este flag silenciosamente para usuarios cliente.
    skip_descargo: Optional[bool] = False

    @field_validator("tunnel")
    @classmethod
    def _validate_tunnel(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in ("wireguard", "ssh"):
            raise ValueError("tunnel debe ser 'wireguard' o 'ssh'")
        return v

    @field_validator("scope")
    @classmethod
    def _scope_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Debe seleccionarse al menos un tipo de auditoría")
        return v

    @field_validator("ips")
    @classmethod
    def _validate_ips(cls, v: list[str]) -> list[str]:
        ip_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
        for ip in v:
            if not ip_re.match(ip):
                raise ValueError(f"IP o CIDR inválido: {ip}")
        return v

    @field_validator("audit_date")
    @classmethod
    def _date_not_past(cls, v: date) -> date:
        if v < date.today():
            raise ValueError("La fecha de inicio no puede ser pasada")
        return v

    @field_validator("priority")
    @classmethod
    def _valid_priority(cls, v: Optional[str]) -> Optional[str]:
        allowed = {"low", "medium", "high", None}
        if v not in allowed:
            raise ValueError(f"priority debe ser uno de: {allowed - {None}}")
        return v

    @model_validator(mode="after")
    def _compute_fecha_final(self) -> "ClientAuditCreateSchema":
        if self.fecha_final is None and self.duration in DURATION_DAYS:
            self.fecha_final = self.audit_date + timedelta(days=DURATION_DAYS[self.duration] - 1)
        return self
