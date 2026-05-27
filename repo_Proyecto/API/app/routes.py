"""
routes.py — Endpoints de la API de auditoría.

POST /api/audit-request     Recibe y persiste la solicitud del formulario
POST /api/admin/login       Autenticación del panel de administración (JWT)
GET  /api/admin/events      Eventos del calendario (requiere JWT válido)
GET  /api/health            Health check
"""
import hashlib
import json
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError

import asyncpg

from app.auth import (
    clear_auth_cookies,
    create_access_token,
    hash_password,
    require_admin,
    require_user,
    set_auth_cookies,
    verify_password,
    verify_password_ct,
)
from app.config import settings
from app.database import (
    cancel_audit,
    create_client_audit,
    get_acceso_basic,
    get_acceso_descargo_data,
    get_calendar_events,
    marcar_acceso_completada,
    get_descargo_estado,
    get_user_audits,
    get_user_by_email,
    get_user_by_id,
    get_user_empresas,
    get_user_password_hash,
    insert_descargo_intento,
    save_audit_request,
    signup_with_empresas,
    update_empresa_cif,
    update_last_login,
    update_password_hash,
    # T22 — pagos
    buscar_codigo_promo,
    confirmar_pago_btcpay,
    crear_pago,
    get_acceso_para_pago,
    get_public_stats,
)
from app.captcha import verify_turnstile, verify_captcha_or_internal, has_valid_internal_auth
from app.descargo import generar_pdf_descargo, validar_pdf_firmado
from app.pricing import (
    BTCPayError,
    calcular_precio,
    crear_invoice_btcpay,
    verify_btcpay_webhook_signature,
)
from app.limits import limiter
from app.schemas import (
    AdminLoginSchema,
    AuditRequestSchema,
    AuditResponseSchema,
    ChangePasswordSchema,
    ClientAuditCreateSchema,
    DescargoEstadoSchema,
    DescargoFirmaResponseSchema,
    EmpresaPatchSchema,
    PagoCreateRequestSchema,
    PagoResponseSchema,
    PrecioPreviewSchema,
    TokenResponseSchema,
    UploadResponseSchema,
    UserLoginSchema,
    UserMeSchema,
    UserSignupSchema,
)
from app.storage import copy_object, get_object_bytes, remove_object, upload_file

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Auditoría"])

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


# ── Formulario público ────────────────────────────────────────────────────────

@router.post(
    "/audit-request",
    response_model=AuditResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar solicitud de auditoría",
)
@limiter.limit("10/minute")
async def create_audit_request(
    request: Request,
    data: str = Form(..., description="JSON con el payload del formulario"),
    wg_conf: Optional[UploadFile] = File(None, description="Archivo WireGuard (.conf)"),
    ssh_key: Optional[UploadFile] = File(None, description="Clave privada SSH (.pem / .key)"),
):
    # ── 1. Parsear y validar ──────────────────────────────────────────────────
    try:
        raw = json.loads(data)
        payload = AuditRequestSchema.model_validate(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"El campo 'data' no es JSON válido: {exc}")
    except ValidationError as exc:
        errors = [
            {"field": ".".join(str(l) for l in e["loc"]), "msg": e["msg"]}
            for e in exc.errors()
        ]
        raise HTTPException(status_code=422, detail={"validation_errors": errors})

    ref = payload.ref

    # ── 2. Persistir en PostgreSQL ────────────────────────────────────────────
    try:
        db_ids = await save_audit_request(payload.model_dump())
    except Exception as exc:
        logger.exception("Error al insertar en PostgreSQL para ref=%s", ref)
        raise HTTPException(status_code=500, detail="Error al guardar los datos.") from exc

    # ── 3. Subir archivos a MinIO ─────────────────────────────────────────────
    uploaded: list[str] = []

    async def _upload(file: UploadFile, name: str) -> None:
        content = await file.read()
        if not content:
            return
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"El archivo '{name}' supera el límite de 5 MB.",
            )
        key = upload_file(
            ref=ref,
            filename=name,
            data=content,
            content_type=file.content_type or "application/octet-stream",
        )
        uploaded.append(key)
        logger.info("Archivo subido: %s (%d bytes)", key, len(content))

    try:
        if wg_conf and wg_conf.filename:
            await _upload(wg_conf, "wg_config.conf")
        if ssh_key and ssh_key.filename:
            ext = ssh_key.filename.rsplit(".", 1)[-1] if "." in ssh_key.filename else "pem"
            await _upload(ssh_key, f"ssh_key.{ext}")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error al subir archivos a MinIO para ref=%s: %s", ref, exc)
        return JSONResponse(
            status_code=207,
            content={
                "ok": True,
                "ref": ref,
                **db_ids,
                "uploaded_files": uploaded,
                "message": "Solicitud registrada, pero algunos archivos no pudieron subirse.",
            },
        )

    logger.info("Solicitud %s registrada | empresa_id=%d | archivos=%s", ref, db_ids["empresa_id"], uploaded)
    return AuditResponseSchema(ref=ref, uploaded_files=uploaded, **db_ids)


# ── Panel de administración ───────────────────────────────────────────────────

@router.post("/admin/login", summary="Login administrador (legacy, username)")
# A1 mitigación temporal: 2/min × 4 réplicas = 8/min efectivos. Sin REDIS_URL
# slowapi cuenta por proceso → el límite real se multiplica por número de réplicas.
# Fix definitivo post-defensa: añadir servicio Redis al stack y REDIS_URL al api.
@limiter.limit("2/minute")
async def admin_login(request: Request, response: Response, body: AdminLoginSchema = Body(...)):
    """Legacy: panel admin actual envía username='auditor'. Mapeamos al email del
    admin semilla si no es ya un email. Validación contra tabla Usuario.
    Rate limit: 5/min/IP."""
    remote_ip = request.client.host if request.client else None
    if not await verify_captcha_or_internal(request, body.turnstile_token, remote_ip):
        logger.warning("Login admin bloqueado por captcha desde %s user=%s", remote_ip, body.username)
        raise HTTPException(status_code=403, detail="Verificación anti-bot fallida.")
    email = body.username if "@" in body.username else settings.admin_default_email
    user = await get_user_by_email(email)
    hashed = user["password_hash"] if user else None
    if not verify_password_ct(body.password, hashed):
        logger.warning("Login admin fallido para '%s' desde %s", body.username, request.client)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas.")
    if user["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Se requieren permisos de administrador.")
    await update_last_login(user["id"])
    logger.info("Login admin OK uid=%d desde %s", user["id"], request.client)
    token = set_auth_cookies(response, user["id"], user["rol"])
    return {"access_token": token, "token_type": "bearer"}


@router.get("/admin/events", summary="Eventos para el calendario de administración")
async def admin_events(current_admin: dict = Depends(require_admin)):
    """Devuelve las auditorías como eventos de FullCalendar. Requiere JWT admin."""
    rows = await get_calendar_events()

    priority_color = {"high": "#e74c3c", "medium": "#f39c12", "low": "#0066cc"}
    events = []

    for r in rows:
        from datetime import timedelta as _td
        start = r["start_date"].isoformat() if r["start_date"] else None
        end = None
        if r["end_date"]:
            end = (r["end_date"] + _td(days=1)).isoformat()
        elif r["start_date"]:
            # FullCalendar end es exclusive: si solo tenemos start, dejamos
            # el evento como bloque de 1 día para que se renderice
            # correctamente (en vez de start==end → punto invisible).
            end = (r["start_date"] + _td(days=1)).isoformat()

        # Sufijo de duración legible en el título del evento
        dur = r.get("duration") or ""
        dur_label = ""
        if dur in ("1h", "4h", "8h"):
            dur_label = f" · {dur}"
        elif dur.startswith("custom_") and dur.endswith("h"):
            dur_label = f" · {dur[len('custom_'):-1]}h"
        elif dur in ("1d", "2-3d", "1w", "2w", "1m"):
            map_dur = {"1d": "1d", "2-3d": "2-3d", "1w": "1 sem", "2w": "2 sem", "1m": "1 mes"}
            dur_label = f" · {map_dur[dur]}"
        title = (r["company"] or "—") + dur_label

        events.append({
            "id":    str(r["acceso_id"]),
            "title": title,
            "start": start,
            "end":   end,
            "color": priority_color.get(r["priority"] or "low", "#0066cc"),
            "extendedProps": {
                "sector":   r["sector"],
                "email":    r["email"],
                "tunnel":   r["tunnel"],
                "schedule": r["schedule"],
                "duration": r["duration"],
                "priority": r["priority"],
                "dominio":  r["dominio"],
                "ips":      [str(ip) for ip in (r["ips"] or [])],
                "scope":    list(r["scope"] or []),
                "estado":   r.get("estado"),
                "ref":      r.get("ref"),
            },
        })

    return events


@router.post("/admin/audits/{ref}/uploaded",
             summary="(interno) Marcar auditoría como completada tras subir informes")
async def marcar_audit_uploaded(ref: str, request: Request):
    """Endpoint interno: lo llama el orchestrator (header X-Internal-Auth) cuando
    termina de subir los informes a MinIO. Marca el Acceso como 'completada' para
    que el panel muestre los botones de descarga. Idempotente — no expone JWT,
    solo acepta el token interno (servicio→servicio)."""
    if not has_valid_internal_auth(request):
        raise HTTPException(status_code=401, detail="No autorizado.")
    acceso = await get_acceso_basic(ref)
    if acceso is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
    actualizado = await marcar_acceso_completada(ref)
    logger.info("Audit %s marcada completada (interno) | actualizado=%s",
                ref, actualizado)
    return {"ref": ref, "estado": "completada", "actualizado": actualizado}


# ─────────────────────────────────────────────────────────────────────────────
#  Auth multi-cliente — /api/auth/*
# ─────────────────────────────────────────────────────────────────────────────


async def _build_user_me(user_id: int) -> UserMeSchema:
    user = await get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    empresas = await get_user_empresas(user_id)
    return UserMeSchema(
        id=user["id"],
        email=user["email"],
        nombre=user.get("nombre"),
        rol=user["rol"],
        email_verified=user["email_verified"],
        empresas=empresas,
    )


@router.post("/auth/signup", response_model=TokenResponseSchema,
             status_code=status.HTTP_201_CREATED, summary="Registrar nuevo cliente")
@limiter.limit("3/minute")
async def auth_signup(request: Request, response: Response, body: UserSignupSchema = Body(...)):
    remote_ip = request.client.host if request.client else None
    if not await verify_captcha_or_internal(request, body.turnstile_token, remote_ip):
        logger.warning("Signup bloqueado por captcha desde %s email=%s", remote_ip, body.email)
        raise HTTPException(status_code=403, detail="Verificación anti-bot fallida.")
    pwd_hash = hash_password(body.password)
    try:
        result = await signup_with_empresas(
            email=str(body.email),
            password_hash=pwd_hash,
            nombre=body.nombre,
            empresas=[e.model_dump() for e in body.empresas],
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="Ese email ya está registrado.")
    user_id = result["user_id"]
    token = set_auth_cookies(response, user_id, "cliente")
    me = await _build_user_me(user_id)
    logger.info("Signup OK uid=%d email=%s empresas=%d",
                user_id, body.email, len(result["empresa_ids"]))
    return TokenResponseSchema(access_token=token, user=me)


@router.post("/auth/login", response_model=TokenResponseSchema,
             summary="Login cliente o admin")
@limiter.limit("10/minute")
async def auth_login(request: Request, response: Response, body: UserLoginSchema = Body(...)):
    remote_ip = request.client.host if request.client else None
    if not await verify_captcha_or_internal(request, body.turnstile_token, remote_ip):
        logger.warning("Login bloqueado por captcha desde %s email=%s", remote_ip, body.email)
        raise HTTPException(status_code=403, detail="Verificación anti-bot fallida.")
    user = await get_user_by_email(str(body.email))
    # verify_password_ct corre bcrypt incluso si el user no existe → timing constante
    # frente a enumeración de cuentas.
    hashed = user["password_hash"] if user else None
    if not verify_password_ct(body.password, hashed):
        logger.warning("Login fallido email=%s desde %s", body.email, request.client)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas.")
    await update_last_login(user["id"])
    token = set_auth_cookies(response, user["id"], user["rol"])
    me = await _build_user_me(user["id"])
    logger.info("Login OK uid=%d email=%s rol=%s", user["id"], body.email, user["rol"])
    return TokenResponseSchema(access_token=token, user=me)


@router.post("/auth/logout", summary="Cerrar sesión (limpia cookies)")
async def auth_logout(response: Response):
    """Limpia la cookie HttpOnly + la CSRF. No exige auth — siempre OK."""
    clear_auth_cookies(response)
    return {"ok": True}


@router.get("/auth/me", response_model=UserMeSchema, summary="Perfil del usuario logueado")
async def auth_me(current: dict = Depends(require_user)):
    return await _build_user_me(current["id"])


@router.post("/auth/change-password", summary="Cambiar contraseña del usuario logueado")
@limiter.limit("5/minute")
async def auth_change_password(
    request: Request,
    body: ChangePasswordSchema = Body(...),
    current: dict = Depends(require_user),
):
    current_hash = await get_user_password_hash(current["id"])
    if current_hash is None or not verify_password(body.old_password, current_hash):
        raise HTTPException(status_code=401, detail="La contraseña actual no coincide.")
    await update_password_hash(current["id"], hash_password(body.new_password))
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Mis peticiones — /api/me/*
# ─────────────────────────────────────────────────────────────────────────────


@router.patch("/me/empresas/{empresa_id}", summary="Actualizar datos de una empresa propia")
async def patch_my_empresa(
    empresa_id: int,
    body: EmpresaPatchSchema = Body(...),
    current: dict = Depends(require_user),
):
    """Hoy permite actualizar el CIF/NIF (necesario para firmar el descargo).
    Ampliable a otros campos editables más adelante."""
    if body.cif is None:
        raise HTTPException(status_code=400, detail="Sin cambios.")
    ok = await update_empresa_cif(empresa_id, current["id"], body.cif)
    if not ok:
        raise HTTPException(status_code=404,
            detail="Empresa no encontrada o no es tuya.")
    return {"ok": True, "empresa_id": empresa_id, "cif": body.cif}


@router.get("/me/empresas", summary="Mis empresas")
async def my_empresas(current: dict = Depends(require_user)):
    return await get_user_empresas(current["id"])


@router.get("/me/audits", summary="Mis peticiones de auditoría")
async def my_audits(current: dict = Depends(require_user)):
    rows = await get_user_audits(current["id"])
    # Serializar tipos no-JSON (INET, date, datetime, ipaddress.IPv*).
    out = []
    for r in rows:
        d = dict(r)
        d["fecha_inicial"] = d["fecha_inicial"].isoformat() if d["fecha_inicial"] else None
        d["fecha_final"]   = d["fecha_final"].isoformat()   if d["fecha_final"]   else None
        d["cancelada_at"]  = d["cancelada_at"].isoformat()  if d["cancelada_at"]  else None
        d["ips"]           = [str(ip) for ip in (d["ips"] or [])]
        d["scope"]         = list(d["scope"] or [])
        out.append(d)
    return out


@router.post("/me/uploads", response_model=UploadResponseSchema,
              status_code=status.HTTP_201_CREATED,
              summary="Subir archivo de túnel (wg_conf | ssh_key) — devuelve sha256")
@limiter.limit("30/minute")
async def upload_my_file(
    request: Request,
    file: UploadFile = File(..., description="Archivo a subir"),
    kind: str = Form(..., description="'wg_conf' o 'ssh_key'"),
    current: dict = Depends(require_user),
):
    if kind not in ("wg_conf", "ssh_key"):
        raise HTTPException(status_code=400, detail="kind debe ser 'wg_conf' o 'ssh_key'")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Archivo vacío")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="El archivo supera el límite de 5 MB.")

    sha = hashlib.sha256(content).hexdigest()
    fname = (file.filename or "").rsplit("/", 1)[-1] or "upload.bin"
    # key temporal en pending/{user_id}/ — se mueve a su key final cuando se cree el Acceso
    object_key = f"pending/{current['id']}/{sha[:16]}-{kind}-{fname}"
    upload_file(ref=f"pending/{current['id']}",
                filename=f"{sha[:16]}-{kind}-{fname}",
                data=content,
                content_type=file.content_type or "application/octet-stream")
    logger.info("Upload uid=%d kind=%s sha=%s size=%d key=%s",
                current["id"], kind, sha[:12], len(content), object_key)
    return UploadResponseSchema(
        object_key=object_key, sha256=sha,
        size=len(content), filename=fname, kind=kind,
    )


@router.post("/me/audits", status_code=status.HTTP_201_CREATED,
              summary="Crear una nueva petición de auditoría (cliente autenticado)")
@limiter.limit("20/minute")
async def create_my_audit(
    request: Request,
    body: ClientAuditCreateSchema = Body(...),
    current: dict = Depends(require_user),
):
    result = await create_client_audit(
        current["id"], body.model_dump(),
        is_admin=(current.get("rol") == "admin"),
    )
    if not result["ok"]:
        if result["reason"] == "forbidden_empresa":
            raise HTTPException(status_code=403,
                detail="Esa empresa no está asociada a tu cuenta.")
        if result["reason"] == "duplicate_ref":
            # Idempotencia: cliente reintentó. El frontend maneja 409 con
            # code=duplicate_ref como éxito (sigue al step de firma/pago).
            raise HTTPException(status_code=409,
                detail={"code": "duplicate_ref",
                        "message": "Ya hay una petición con esa referencia."})
        raise HTTPException(status_code=400, detail=result["reason"])

    # Mover archivos pre-subidos (pending/{user_id}/...) a su key final {ref}/...
    moved: list[str] = []
    try:
        if body.wg_object_key:
            dst = f"{body.ref}/wg_config.conf"
            copy_object(body.wg_object_key, dst)
            remove_object(body.wg_object_key)
            moved.append(dst)
        if body.ssh_object_key:
            ext = body.ssh_object_key.rsplit(".", 1)[-1] if "." in body.ssh_object_key else "pem"
            if ext not in ("pem", "key"):
                ext = "pem"
            dst = f"{body.ref}/ssh_key.{ext}"
            copy_object(body.ssh_object_key, dst)
            remove_object(body.ssh_object_key)
            moved.append(dst)
    except Exception as exc:
        logger.error("Error moviendo archivos a {ref}/ ref=%s: %s", body.ref, exc)
        return JSONResponse(status_code=207, content={
            "ok": True, "ref": body.ref,
            "acceso_id": result["acceso_id"],
            "contacto_id": result["contacto_id"],
            "uploaded_files": moved,
            "message": "Petición creada, pero los archivos no pudieron moverse a su key final.",
        })

    logger.info("Petición creada uid=%d ref=%s acceso_id=%d files=%s",
                current["id"], body.ref, result["acceso_id"], moved)
    return {"ok": True, "ref": body.ref,
            "acceso_id": result["acceso_id"],
            "contacto_id": result["contacto_id"],
            "uploaded_files": moved}


@router.delete("/me/audits/{acceso_id}", summary="Cancelar una auditoría (cutoff 24h)")
async def cancel_my_audit(
    acceso_id: int,
    current: dict = Depends(require_user),
):
    result = await cancel_audit(acceso_id, current["id"])
    if result["ok"]:
        return result
    reason = result["reason"]
    if reason == "not_found":
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
    if reason == "forbidden":
        raise HTTPException(status_code=403, detail="No es tuya.")
    if reason == "cutoff_24h":
        raise HTTPException(status_code=409, detail={
            "code": "cutoff_24h",
            "message": "No se puede cancelar con menos de 24h de antelación.",
            "starts_at": result.get("starts_at"),
        })
    raise HTTPException(status_code=409, detail=reason)


# ── Descargo firmado (T4) ─────────────────────────────────────────────────────

@router.get("/me/audits/{ref}/descargo/pdf",
             summary="PDF del descargo a firmar (generado dinámico)")
async def descargo_pdf(ref: str, current: dict = Depends(require_user)):
    """Devuelve el PDF descargo con los datos de la auditoría rellenados.
    El cliente lo firma localmente con AutoFirma (PAdES) y lo sube en el
    siguiente endpoint."""
    data = await get_acceso_descargo_data(ref, current["id"])
    if data is None:
        raise HTTPException(status_code=404,
            detail="Auditoría no encontrada o no es tuya.")
    if not data.get("cif"):
        raise HTTPException(status_code=409,
            detail={"code": "missing_cif",
                    "message": "Antes de firmar el descargo añade el CIF/NIF de la empresa en tu perfil."})
    pdf_bytes = generar_pdf_descargo(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition":
                 f'inline; filename="descargo_{ref}.pdf"'},
    )


@router.post("/me/audits/{ref}/descargo/firmar",
              response_model=DescargoFirmaResponseSchema,
              summary="Sube el PDF firmado y valida la firma electrónica")
@limiter.limit("10/minute")
async def descargo_firmar(
    request: Request,
    ref: str,
    file: UploadFile = File(...),
    current: dict = Depends(require_user),
):
    if not file.content_type or "pdf" not in file.content_type.lower():
        raise HTTPException(status_code=415,
            detail="Esperaba un PDF (application/pdf).")
    data = await get_acceso_descargo_data(ref, current["id"])
    if data is None:
        raise HTTPException(status_code=404,
            detail="Auditoría no encontrada o no es tuya.")

    pdf_bytes = await file.read()
    if len(pdf_bytes) < 1000 or len(pdf_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413,
            detail=f"Tamaño de PDF inválido (1KB–{MAX_FILE_SIZE // 1024 // 1024}MB).")

    result = validar_pdf_firmado(pdf_bytes)

    # Guardamos el PDF en MinIO independientemente de la validez (auditoría
    # interna de intentos). El descargo válido lleva sufijo .firmado.pdf.
    suffix = "firmado" if result["valid"] else "intento"
    filename = f"descargo_{suffix}_{result['sha256'][:16]}.pdf"
    object_key = upload_file(
        ref=ref, filename=filename, data=pdf_bytes,
        content_type="application/pdf",
    )

    descargo_id = await insert_descargo_intento(
        usuario_id=current["id"],
        acceso_id=data["acceso_id"],
        pdf_object_key=object_key,
        sha256=result["sha256"],
        signer_dn=result.get("signer_dn") or "",
        signer_serial=result.get("signer_serial") or "",
        firmado_at=result.get("firmado_at"),
        valido=result["valid"],
    )
    nuevo_estado = "pendiente" if result["valid"] else data["estado"]

    logger.info(
        "Descargo ref=%s uid=%d valid=%s sha256=%s signer=%r",
        ref, current["id"], result["valid"], result["sha256"][:16],
        result.get("signer_dn"),
    )

    firmado_at = result.get("firmado_at")
    return DescargoFirmaResponseSchema(
        ok=True,
        valid=result["valid"],
        sha256=result["sha256"],
        descargo_id=descargo_id,
        signer_dn=result.get("signer_dn") or None,
        signer_serial=result.get("signer_serial") or None,
        firmado_at=firmado_at.isoformat() if firmado_at else None,
        estado_audit=nuevo_estado,
        error=result.get("error"),
    )


_INFORME_TIPO_FICHERO = {
    "tecnico":   "informe_tecnico.md",
    "ejecutivo": "informe_ejecutivo.md",
}


@router.get("/me/audits/{ref}/informe/{tipo}",
             summary="Descarga el informe (técnico o ejecutivo) de una auditoría")
async def descargar_informe(
    ref: str,
    tipo: str,
    format: str = "pdf",
    current: dict = Depends(require_user),
):
    """Devuelve el informe como descarga. Formato por defecto: PDF profesional
    generado on-the-fly (`?format=pdf`). El cliente puede pedir el .md crudo con
    `?format=md` si lo necesita técnico.
    Permisos: admin descarga cualquier audit; cliente solo los de sus empresas.
    El informe vive en MinIO bajo {ref}/informe_{tipo}.md (lo sube el orchestrator
    al terminar el engagement); el PDF se renderiza cada vez con la plantilla
    corporativa actual."""
    if tipo not in _INFORME_TIPO_FICHERO:
        raise HTTPException(status_code=400,
            detail=f"tipo inválido: {tipo} (use 'tecnico' o 'ejecutivo')")
    if format not in ("pdf", "md"):
        raise HTTPException(status_code=400,
            detail=f"format inválido: {format} (use 'pdf' o 'md')")
    acceso = await get_acceso_basic(ref)
    if acceso is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
    es_admin = current.get("rol") == "admin"
    if not es_admin and acceso["owner_user_id"] != current["id"]:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
    if acceso["estado"] != "completada":
        raise HTTPException(status_code=409,
            detail=f"Audit en estado '{acceso['estado']}', no hay informe disponible aún.")

    object_key = f"{ref}/{_INFORME_TIPO_FICHERO[tipo]}"
    data = get_object_bytes(object_key)
    if data is None:
        logger.warning("informe %s/%s no encontrado en MinIO (audit %s)", ref, tipo, ref)
        raise HTTPException(status_code=404,
            detail="El informe aún no está disponible. Inténtalo en unos minutos.")

    if format == "pdf":
        try:
            from app.informe_pdf import render_informe_pdf
            pdf_bytes = render_informe_pdf(
                md_text=data.decode("utf-8", errors="replace"),
                ref=ref,
                tipo=tipo,
                empresa_nombre=acceso["empresa_nombre"],
            )
        except ImportError as exc:
            logger.error("WeasyPrint/markdown no disponible: %s", exc)
            raise HTTPException(status_code=503,
                detail="Renderizado PDF temporalmente no disponible. Pruebe ?format=md.")
        except Exception as exc:
            logger.exception("Error generando PDF de informe %s/%s: %s", ref, tipo, exc)
            raise HTTPException(status_code=500,
                detail="No se pudo generar el PDF. Pruebe ?format=md.")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition":
                     f'attachment; filename="informe_{tipo}_{ref}.pdf"'},
        )

    download_name = f"informe_{tipo}_{ref}.md"
    return Response(
        content=data,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'},
    )


@router.get("/me/audits/{ref}/descargo",
             response_model=DescargoEstadoSchema,
             summary="Estado del descargo de una auditoría")
async def descargo_estado(ref: str, current: dict = Depends(require_user)):
    estado = await get_descargo_estado(ref, current["id"])
    if estado is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada.")
    firmado_at = estado.get("firmado_at")
    verificado_at = estado.get("verificado_at")
    return DescargoEstadoSchema(
        acceso_id=estado["acceso_id"],
        ref=estado["ref"],
        estado=estado["estado"],
        descargo_id=estado.get("descargo_id"),
        signer_dn=estado.get("signer_dn"),
        signer_serial=estado.get("signer_serial"),
        firmado_at=firmado_at.isoformat() if firmado_at else None,
        verificado_at=verificado_at.isoformat() if verificado_at else None,
        valido=estado.get("valido"),
    )


# ── Pago (T22) ────────────────────────────────────────────────────────────────

@router.get("/me/audits/{ref}/precio",
             response_model=PrecioPreviewSchema,
             summary="Calcula el precio de la auditoría (preview, sin crear pago)")
async def precio_preview(ref: str, current: dict = Depends(require_user)):
    audit = await get_acceso_para_pago(ref, current["id"])
    if audit is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada o no es tuya.")
    desglose = calcular_precio(
        scope=audit["scope"], duration=audit["duracion"],
        priority=audit["prioridad"], tier="standard",
    )
    return PrecioPreviewSchema(
        ref=ref,
        importe_eur=desglose["importe_eur"],
        rate_eur_hour=desglose["rate_eur_hour"],
        horas=desglose["horas"],
        mult_tipo=desglose["mult_tipo"],
        mult_prio=desglose["mult_prio"],
        tier=desglose["tier"],
    )


@router.post("/me/audits/{ref}/pay",
              response_model=PagoResponseSchema,
              summary="Inicia el pago de una auditoría (BTCPay o bypass por código)")
@limiter.limit("10/minute")
async def pagar_auditoria(
    request: Request,
    ref: str,
    body: PagoCreateRequestSchema = Body(default=None),
    current: dict = Depends(require_user),
):
    audit = await get_acceso_para_pago(ref, current["id"])
    if audit is None:
        raise HTTPException(status_code=404, detail="Auditoría no encontrada o no es tuya.")
    if audit["pago_id"] and audit["pagado_at"]:
        raise HTTPException(status_code=409,
            detail={"code": "already_paid", "message": "Esta auditoría ya está pagada."})

    desglose = calcular_precio(
        scope=audit["scope"], duration=audit["duracion"],
        priority=audit["prioridad"], tier="standard",
    )
    importe_cents = desglose["importe_eur_cents"]

    codigo_str = (body.codigo_promo if body else None) or None
    descuento_cents = 0
    codigo_id: int | None = None
    codigo_codigo: str | None = None
    if codigo_str:
        promo = await buscar_codigo_promo(codigo_str, current["id"])
        if promo is None:
            raise HTTPException(status_code=400,
                detail={"code": "invalid_promo", "message": "Código promocional inválido o no aplicable."})
        descuento_cents = int(importe_cents * float(promo["descuento_pct"]) / 100)
        descuento_cents = min(descuento_cents, importe_cents)
        codigo_id = promo["id"]
        codigo_codigo = promo["codigo"]

    final_cents = max(importe_cents - descuento_cents, 0)

    # Caso 1: descuento 100% → bypass de BTCPay, audit queda pagada
    if final_cents == 0:
        # asyncpg rechaza mezcla naive/aware. La columna Pago.pagado_at es
        # TIMESTAMP WITHOUT TIME ZONE → pasamos None y dejamos que la BD
        # ponga NOW() (UTC del server).
        pago_id = await crear_pago(
            acceso_id=audit["acceso_id"], usuario_id=current["id"],
            importe_eur_cents=importe_cents, descuento_cents=descuento_cents,
            final_eur_cents=0, codigo_promo_id=codigo_id,
            metodo="promo_bypass", estado="pagado",
            pagado_at=None,
        )
        logger.info("Pago bypass por código uid=%d ref=%s codigo=%s",
                    current["id"], ref, codigo_codigo)
        return PagoResponseSchema(
            ok=True, paid=True,
            importe_eur=importe_cents / 100.0,
            descuento_eur=descuento_cents / 100.0,
            importe_final_eur=0.0,
            pago_id=pago_id, metodo="promo_bypass",
            codigo_aplicado=codigo_codigo,
        )

    # Caso 2: pago real vía BTCPay
    try:
        invoice = await crear_invoice_btcpay(
            importe_eur_cents=final_cents,
            audit_ref=ref,
            user_email=audit["user_email"],
            metadata={"acceso_id": audit["acceso_id"],
                      "codigo_promo": codigo_codigo or ""},
        )
    except BTCPayError as exc:
        logger.error("BTCPay invoice falló ref=%s: %s", ref, exc)
        raise HTTPException(status_code=503,
            detail={"code": "btcpay_unavailable",
                    "message": "Pasarela de pago no disponible. Inténtalo más tarde."})

    pago_id = await crear_pago(
        acceso_id=audit["acceso_id"], usuario_id=current["id"],
        importe_eur_cents=importe_cents, descuento_cents=descuento_cents,
        final_eur_cents=final_cents, codigo_promo_id=codigo_id,
        btcpay_invoice_id=invoice.get("id"),
        metodo="btcpay", estado="pendiente",
    )
    return PagoResponseSchema(
        ok=True, paid=False,
        importe_eur=importe_cents / 100.0,
        descuento_eur=descuento_cents / 100.0,
        importe_final_eur=final_cents / 100.0,
        pago_id=pago_id, metodo="btcpay",
        codigo_aplicado=codigo_codigo,
        btcpay_url=invoice.get("checkoutLink"),
        btcpay_invoice_id=invoice.get("id"),
    )


@router.post("/btcpay/webhook",
              summary="Webhook de BTCPay (HMAC-SHA256 firmado con shared secret)")
async def btcpay_webhook(request: Request):
    raw = await request.body()
    sig = request.headers.get("BTCPay-Sig") or request.headers.get("BTCPAY-SIG")
    if not verify_btcpay_webhook_signature(raw, sig):
        logger.warning("BTCPay webhook con firma inválida (sig=%r)", sig)
        raise HTTPException(status_code=401, detail="Firma inválida")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Payload no es JSON")

    tipo = payload.get("type", "")
    invoice_id = payload.get("invoiceId") or payload.get("data", {}).get("invoiceId")
    if not invoice_id:
        return {"ok": True, "ignored": "missing invoiceId"}
    if tipo not in ("InvoiceSettled", "InvoiceProcessing", "InvoicePaymentSettled"):
        return {"ok": True, "ignored": tipo}

    result = await confirmar_pago_btcpay(invoice_id, payload)
    if result is None:
        return {"ok": True, "ignored": "invoice no enlazada con ningún Pago"}
    logger.info("BTCPay webhook ok invoice=%s pago=%d ref=%s already=%s",
                invoice_id, result["pago_id"], result["ref"], result.get("already_paid"))
    return {"ok": True, "pago_id": result["pago_id"], "ref": result["ref"]}


# ── Stats públicas (T5) ───────────────────────────────────────────────────────

@router.get("/public/stats",
             summary="Estadísticas anonimizadas para el dashboard /hitos")
@limiter.limit("60/minute")
async def public_stats(request: Request):
    """Devuelve agregados k≥3 anonimizados. Sin auth.
    Cacheable 60s en cliente."""
    stats = await get_public_stats(k_min=3)
    return JSONResponse(stats, headers={"Cache-Control": "public, max-age=60"})


# ── Health check ──────────────────────────────────────────────────────────────

@router.get("/health", summary="Health check")
async def health():
    return {"status": "ok"}
