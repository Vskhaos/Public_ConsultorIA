"""
database.py — Pool de conexiones PostgreSQL con asyncpg.
Expone get_pool() para obtener el pool global y funciones
de inserción transaccional para cada entidad del schema.
"""
from __future__ import annotations

import asyncpg
from asyncpg import Pool, Connection
from typing import Any

from app.config import settings

# Atajo: clave para pgp_sym_encrypt/decrypt en columnas no-buscables
# (acceso.notas, empresa.cif, contacto.{departamento,rol}).
_FK = settings.db_field_key

_pool: Pool | None = None


async def get_pool() -> Pool:
    """Devuelve el pool global, creándolo si no existe."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=settings.db_dsn,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


# ── Helpers de inserción ──────────────────────────────────────────────────────

async def insert_empresa(
    conn: Connection,
    *,
    nombre: str,
    sector: str | None,
    dominio: str | None,
    ips: list[str],
    scope: list[str],
    prioridad: str | None,
) -> int:
    """
    Inserta una fila en Empresa y devuelve su id.
    Las IPs se pasan como lista de strings; PostgreSQL las convierte a INET[].
    """
    row = await conn.fetchrow(
        """
        INSERT INTO Empresa (nombre, sector, dominio, ips, scope, prioridad)
        VALUES ($1, $2, $3, $4::inet[], $5, $6)
        RETURNING id
        """,
        nombre,
        sector or None,
        dominio or None,
        ips if ips else [],
        scope if scope else [],
        prioridad or None,
    )
    return row["id"]


async def insert_contacto(
    conn: Connection,
    *,
    empresa_id: int,
    nombre: str,
    rol: str | None,
    departamento: str | None,
    email: str,
    telefono: str | None,
) -> int:
    """Inserta un Contacto vinculado a una Empresa."""
    row = await conn.fetchrow(
        """
        INSERT INTO Contacto (empresa_id, nombre, rol_enc, departamento_enc, email)
        VALUES ($1, $2,
                CASE WHEN $3::text IS NULL THEN NULL
                     ELSE pgp_sym_encrypt($3, $6) END,
                CASE WHEN $4::text IS NULL THEN NULL
                     ELSE pgp_sym_encrypt($4, $6) END,
                $5)
        RETURNING id
        """,
        empresa_id,
        nombre,
        rol or None,
        departamento or None,
        email,
        _FK,
    )
    return row["id"]


async def insert_acceso(
    conn: Connection,
    *,
    empresa_id: int,
    metodo: str | None,
    notas: str | None,
    fecha_inicial: Any,          # date string "YYYY-MM-DD" o None
    fecha_final: Any,            # date string "YYYY-MM-DD" o None
    duracion: str | None,
    horario_preferido: str | None,
    ref: str | None = None,
    # Alcance técnico (migrado de Empresa en v002 — ahora vive en Acceso)
    dominio: str | None = None,
    ips: list[str] | None = None,
    scope: list[str] | None = None,
    prioridad: str | None = None,
    estado_inicial: str = "pendiente",
) -> int:
    """Inserta un registro de Acceso con alcance técnico embebido."""
    row = await conn.fetchrow(
        """
        INSERT INTO Acceso (
            empresa_id, metodo, notas_enc, fecha_inicial, fecha_final,
            duracion, horario_preferido, ref,
            dominio, ips, scope, prioridad, estado
        )
        VALUES ($1, $2,
                CASE WHEN $3::text IS NULL THEN NULL
                     ELSE pgp_sym_encrypt($3, $14) END,
                $4::date, $5::date, $6, $7, $8,
                $9, $10::inet[], $11, $12, $13)
        RETURNING id
        """,
        empresa_id,
        metodo or None,
        notas or None,
        fecha_inicial or None,
        fecha_final or None,
        duracion or None,
        horario_preferido or None,
        ref or None,
        dominio or None,
        ips if ips else [],
        scope if scope else [],
        prioridad or None,
        estado_inicial,
        _FK,
    )
    return row["id"]


async def get_calendar_events() -> list[dict]:
    """Eventos del calendario admin. COALESCE entre Acceso (nuevo) y Empresa
    (legacy) durante la transición. Una fila por auditoría: el JOIN con
    Contacto se hace via LATERAL LIMIT 1 para evitar el producto cartesiano
    cuando una empresa acumula varios contactos."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                a.id                                        AS acceso_id,
                e.nombre                                    AS company,
                e.sector,
                COALESCE(a.dominio,   e.dominio)            AS dominio,
                COALESCE(a.ips,       e.ips)                AS ips,
                COALESCE(a.scope,     e.scope)              AS scope,
                COALESCE(a.prioridad, e.prioridad)          AS priority,
                a.fecha_inicial                             AS start_date,
                a.fecha_final                               AS end_date,
                a.metodo                                    AS tunnel,
                a.horario_preferido                         AS schedule,
                a.duracion                                  AS duration,
                a.estado                                    AS estado,
                a.ref                                       AS ref,
                c.email
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            LEFT JOIN LATERAL (
                SELECT email FROM Contacto
                WHERE empresa_id = e.id
                ORDER BY id DESC
                LIMIT 1
            ) c ON TRUE
            WHERE a.fecha_inicial IS NOT NULL
            ORDER BY a.fecha_inicial
        """)
    return [dict(r) for r in rows]


async def save_audit_request(payload: dict[str, Any]) -> dict[str, int]:
    """
    Ejecuta las tres inserciones en una única transacción.
    Devuelve los IDs generados: { empresa_id, contacto_id, acceso_id }.
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        async with conn.transaction():
            empresa_id = await insert_empresa(
                conn,
                nombre=payload["company"],
                sector=payload.get("sector"),
                dominio=payload.get("domain"),
                ips=payload.get("ips", []),
                scope=payload.get("scope", []),
                prioridad=payload.get("priority"),
            )

            contacto_id = await insert_contacto(
                conn,
                empresa_id=empresa_id,
                nombre=payload["contact"],
                rol=payload.get("role"),
                departamento=payload.get("department"),
                email=payload["email"],
                telefono=payload.get("phone"),
            )

            acceso_id = await insert_acceso(
                conn,
                empresa_id=empresa_id,
                metodo=payload.get("tunnel"),
                notas=payload.get("scope_notes"),
                fecha_inicial=payload.get("audit_date"),
                fecha_final=payload.get("fecha_final"),
                duracion=payload.get("duration"),
                horario_preferido=payload.get("horario_preferido"),
                ref=payload.get("ref"),
                # Alcance técnico también en Acceso (sincronía con Empresa
                # durante la transición, hasta que init.sql v003 elimine
                # dominio/ips/scope/prioridad de Empresa).
                dominio=payload.get("domain"),
                ips=payload.get("ips", []),
                scope=payload.get("scope", []),
                prioridad=payload.get("priority"),
            )

    return {
        "empresa_id": empresa_id,
        "contacto_id": contacto_id,
        "acceso_id": acceso_id,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Usuario (auth multi-cliente — introducido en migración 002)
# ─────────────────────────────────────────────────────────────────────────────

async def get_user_by_email(email: str) -> dict | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, password_hash, nombre, rol, email_verified, "
            "created_at, last_login_at FROM Usuario WHERE email = $1",
            email,
        )
    return dict(row) if row else None


async def get_user_by_id(user_id: int) -> dict | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, nombre, rol, email_verified, created_at, "
            "last_login_at FROM Usuario WHERE id = $1",
            user_id,
        )
    return dict(row) if row else None


async def create_user(
    *, email: str, password_hash: str, nombre: str | None, rol: str = "cliente"
) -> int:
    """Crea un usuario nuevo. Lanza asyncpg.UniqueViolationError si email duplicado."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO Usuario (email, password_hash, nombre, rol) "
            "VALUES ($1, $2, $3, $4) RETURNING id",
            email, password_hash, nombre, rol,
        )
    return row["id"]


async def signup_with_empresas(
    *,
    email: str,
    password_hash: str,
    nombre: str | None,
    empresas: list[dict],
) -> dict:
    """Crea usuario + sus empresas + asocia sectores en una sola transacción."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            user_row = await conn.fetchrow(
                "INSERT INTO Usuario (email, password_hash, nombre, rol) "
                "VALUES ($1, $2, $3, 'cliente') RETURNING id",
                email, password_hash, nombre,
            )
            user_id = user_row["id"]
            empresa_ids: list[int] = []
            for emp in empresas:
                e_row = await conn.fetchrow(
                    "INSERT INTO Empresa (nombre, usuario_id, cif_enc) "
                    "VALUES ($1, $2, "
                    "  CASE WHEN $3::text IS NULL THEN NULL "
                    "       ELSE pgp_sym_encrypt($3, $4) END"
                    ") RETURNING id",
                    emp["nombre"], user_id, emp.get("cif"), _FK,
                )
                e_id = e_row["id"]
                empresa_ids.append(e_id)
                for sector_nombre in emp.get("sectores", []):
                    sector_nombre = sector_nombre.strip()
                    if not sector_nombre:
                        continue
                    s_row = await conn.fetchrow(
                        "INSERT INTO Sector (nombre) VALUES ($1) "
                        "ON CONFLICT (nombre) DO UPDATE SET nombre = EXCLUDED.nombre "
                        "RETURNING id",
                        sector_nombre,
                    )
                    await conn.execute(
                        "INSERT INTO EmpresaSector (empresa_id, sector_id) "
                        "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        e_id, s_row["id"],
                    )
    return {"user_id": user_id, "empresa_ids": empresa_ids}


async def update_last_login(user_id: int) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE Usuario SET last_login_at = NOW() WHERE id = $1", user_id)


async def update_password_hash(user_id: int, new_hash: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE Usuario SET password_hash = $1 WHERE id = $2",
            new_hash, user_id,
        )


async def get_user_password_hash(user_id: int) -> str | None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash FROM Usuario WHERE id = $1", user_id,
        )
    return row["password_hash"] if row else None


async def get_user_empresas(user_id: int) -> list[dict]:
    """Lista de empresas del usuario con sus sectores agregados."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT e.id, e.nombre,
                   CASE WHEN e.cif_enc IS NULL THEN NULL
                        ELSE pgp_sym_decrypt(e.cif_enc, $2) END AS cif,
                   COALESCE(
                       (SELECT array_agg(s.nombre ORDER BY s.nombre)
                        FROM EmpresaSector es
                        JOIN Sector s ON s.id = es.sector_id
                        WHERE es.empresa_id = e.id),
                       '{}'::text[]
                   ) AS sectores
            FROM Empresa e
            WHERE e.usuario_id = $1
            ORDER BY e.id
            """,
            user_id, _FK,
        )
    return [{"id": r["id"], "nombre": r["nombre"], "cif": r["cif"],
             "sectores": list(r["sectores"])}
            for r in rows]


async def get_user_audits(user_id: int) -> list[dict]:
    """Mis peticiones — todas las auditorías de empresas del usuario."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT a.id, a.ref, a.fecha_inicial, a.fecha_final, a.duracion,
                   a.horario_preferido, a.estado, a.cancelada_at, a.reagendada_de,
                   a.descargo_id,
                   COALESCE(a.dominio, e.dominio)         AS dominio,
                   COALESCE(a.ips, e.ips)                 AS ips,
                   COALESCE(a.scope, e.scope)             AS scope,
                   COALESCE(a.prioridad, e.prioridad)     AS prioridad,
                   e.id AS empresa_id, e.nombre AS empresa_nombre,
                   CASE WHEN e.cif_enc IS NULL THEN NULL
                        ELSE pgp_sym_decrypt(e.cif_enc, $2) END AS cif
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            WHERE e.usuario_id = $1
            ORDER BY a.fecha_inicial DESC, a.id DESC
            """,
            user_id, _FK,
        )
    return [dict(r) for r in rows]


async def update_empresa_cif(empresa_id: int, user_id: int, cif: str | None) -> bool:
    """Actualiza el CIF de una empresa del usuario. False si no es suya."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE Empresa
               SET cif_enc = CASE WHEN $1::text IS NULL THEN NULL
                                  ELSE pgp_sym_encrypt($1, $4) END
             WHERE id = $2 AND usuario_id = $3
            """,
            cif, empresa_id, user_id, _FK,
        )
        return result.endswith(" 1")


async def cancel_audit(acceso_id: int, user_id: int) -> dict:
    """Cancela una auditoría. Cutoff: si quedan menos de 24h hasta fecha_inicial,
    rechaza. Devuelve {ok, reason} o lanza ValueError si no es del usuario."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT a.id, a.estado, a.fecha_inicial, a.horario_preferido,
                       e.usuario_id
                FROM Acceso a JOIN Empresa e ON e.id = a.empresa_id
                WHERE a.id = $1
                FOR UPDATE
                """,
                acceso_id,
            )
            if row is None:
                return {"ok": False, "reason": "not_found"}
            if row["usuario_id"] != user_id:
                return {"ok": False, "reason": "forbidden"}
            if row["estado"] in ("cancelada", "completada"):
                return {"ok": False, "reason": f"already_{row['estado']}"}

            # Cutoff 24h: parsear horario "HH:MM-HH:MM" para tener inicio.
            from datetime import datetime, timedelta, timezone
            inicio = datetime.combine(row["fecha_inicial"], datetime.min.time(),
                                      tzinfo=timezone.utc)
            horario = (row["horario_preferido"] or "").strip()
            if "-" in horario:
                hh = horario.split("-")[0].strip()
                try:
                    h, m = [int(x) for x in hh.split(":")[:2]]
                    inicio = inicio.replace(hour=h, minute=m)
                except ValueError:
                    pass
            now = datetime.now(timezone.utc)
            if (inicio - now) < timedelta(hours=24):
                return {"ok": False, "reason": "cutoff_24h",
                        "starts_at": inicio.isoformat()}

            await conn.execute(
                "UPDATE Acceso SET estado='cancelada', cancelada_at=NOW() WHERE id=$1",
                acceso_id,
            )
            return {"ok": True, "acceso_id": acceso_id}


async def create_client_audit(user_id: int, payload: dict,
                                is_admin: bool = False) -> dict:
    """Crea una petición de auditoría desde el dashboard cliente. Valida que
    empresa_id pertenezca al usuario. Persiste Acceso (con alcance) + Contacto.
    Si `is_admin` y `payload.skip_descargo`, salta el paso de firma y la
    auditoría arranca directamente en `pendiente_pago`.
    Devuelve {ok, acceso_id, contacto_id} o {ok=False, reason}.
    `reason='duplicate_ref'` si la ref ya existía (UNIQUE en Acceso.ref)."""
    import asyncpg
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                empresa_row = await conn.fetchrow(
                    "SELECT id FROM Empresa WHERE id=$1 AND usuario_id=$2",
                    payload["empresa_id"], user_id,
                )
                if empresa_row is None:
                    return {"ok": False, "reason": "forbidden_empresa"}

                user_row = await conn.fetchrow(
                    "SELECT email, nombre FROM Usuario WHERE id=$1", user_id,
                )

                contact = payload["contact"]
                contact_email = contact.get("email") or (user_row["email"] if user_row else None)
                contacto_id = await insert_contacto(
                    conn,
                    empresa_id=payload["empresa_id"],
                    nombre=contact["nombre"],
                    rol=contact.get("rol"),
                    departamento=contact.get("departamento"),
                    email=contact_email,
                    telefono=contact.get("telefono"),
                )

                # Si hay dominios extra, los anexamos a las notas.
                extras = payload.get("dominios_extra") or []
                notes = payload.get("scope_notes") or ""
                if extras:
                    tag = "Dominios adicionales: " + ", ".join(extras)
                    notes = (notes + "\n" + tag).strip() if notes else tag

                acceso_id = await insert_acceso(
                    conn,
                    empresa_id=payload["empresa_id"],
                    metodo=payload.get("tunnel"),
                    notas=notes or None,
                    fecha_inicial=payload.get("audit_date"),
                    fecha_final=payload.get("fecha_final"),
                    duracion=payload.get("duration"),
                    horario_preferido=payload.get("horario_preferido"),
                    ref=payload.get("ref"),
                    dominio=payload.get("dominio"),
                    ips=payload.get("ips") or [],
                    scope=payload.get("scope") or [],
                    prioridad=payload.get("priority"),
                    estado_inicial=(
                        "pendiente_pago"
                        if (is_admin and payload.get("skip_descargo"))
                        else "pendiente_descargo"
                    ),
                )
        return {"ok": True, "acceso_id": acceso_id, "contacto_id": contacto_id}
    except asyncpg.exceptions.UniqueViolationError:
        # Idempotencia: cliente reintentó con la misma ref. Mapeado a 409.
        return {"ok": False, "reason": "duplicate_ref"}


# ── Descargo firmado ──────────────────────────────────────────────────────────

async def get_acceso_basic(ref: str) -> dict | None:
    """Lookup mínimo de un Acceso por ref. Devuelve estado + usuario propietario
    de la empresa + nombre empresa. Sin filtro de user (el caller decide perms)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.id AS acceso_id, a.ref, a.estado,
                   e.id AS empresa_id, e.nombre AS empresa_nombre,
                   e.usuario_id AS owner_user_id
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            WHERE a.ref = $1
            """,
            ref,
        )
    return dict(row) if row else None


async def marcar_acceso_completada(ref: str) -> bool:
    """Marca un Acceso como 'completada' (informe entregado). Idempotente.
    La llama el orchestrator vía endpoint interno tras subir los informes a
    MinIO, para que el panel muestre los botones de descarga. No resucita
    auditorías canceladas. Devuelve True si actualizó una fila."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE Acceso SET estado='completada' WHERE ref=$1 AND estado <> 'cancelada'",
            ref,
        )
    try:
        return int(result.split()[-1]) > 0
    except (ValueError, IndexError):
        return False


async def get_acceso_descargo_data(ref: str, user_id: int) -> dict | None:
    """Datos completos del audit + empresa para generar el PDF descargo.
    Sólo devuelve si la auditoría pertenece a una empresa del usuario."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.id              AS acceso_id,
                   a.ref,
                   a.fecha_inicial,
                   a.duracion,
                   a.estado,
                   a.descargo_id,
                   COALESCE(a.dominio, e.dominio)   AS dominio,
                   COALESCE(a.ips,     e.ips)       AS ips,
                   COALESCE(a.scope,   e.scope)     AS scope,
                   e.id              AS empresa_id,
                   e.nombre          AS empresa_nombre,
                   CASE WHEN e.cif_enc IS NULL THEN NULL
                        ELSE pgp_sym_decrypt(e.cif_enc, $3) END AS cif,
                   u.nombre          AS representante
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            JOIN Usuario u ON u.id = e.usuario_id
            WHERE a.ref = $1 AND e.usuario_id = $2
            """,
            ref, user_id, _FK,
        )
    if row is None:
        return None
    d = dict(row)
    if d.get("ips"):
        d["ips"] = [str(ip) for ip in d["ips"]]
    return d


async def insert_descargo_intento(
    *, usuario_id: int, acceso_id: int, pdf_object_key: str,
    sha256: str, signer_dn: str, signer_serial: str,
    firmado_at, valido: bool,
) -> int:
    """Inserta un intento de firma. Si valido=True, lo marca como
    descargo_id de la auditoría (UNIQUE partial garantiza 1 válido/audit)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO DescargoFirmado
                    (usuario_id, acceso_id, pdf_object_key, sha256,
                     signer_dn, signer_serial, firmado_at, valido)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (usuario_id, sha256) DO UPDATE
                  SET acceso_id     = EXCLUDED.acceso_id,
                      pdf_object_key = EXCLUDED.pdf_object_key,
                      signer_dn     = EXCLUDED.signer_dn,
                      signer_serial = EXCLUDED.signer_serial,
                      firmado_at    = EXCLUDED.firmado_at,
                      valido        = EXCLUDED.valido,
                      verificado_at = NOW()
                RETURNING id
                """,
                usuario_id, acceso_id, pdf_object_key, sha256,
                signer_dn or None, signer_serial or None,
                firmado_at, valido,
            )
            descargo_id = row["id"]
            if valido:
                # Tras firmar, el audit pasa a 'pendiente_pago' (todavia
                # bloqueado para el auto-poller). El POST /pay lo mueve a
                # 'pendiente' cuando confirme el pago — sea bypass por
                # codigo promo o webhook BTCPay.
                await conn.execute(
                    """
                    UPDATE Acceso
                    SET descargo_id = $2,
                        estado      = CASE WHEN estado = 'pendiente_descargo'
                                           THEN 'pendiente_pago'
                                           ELSE estado END
                    WHERE id = $1
                    """,
                    acceso_id, descargo_id,
                )
            return descargo_id


# ── Pricing / pagos / códigos promocionales (T22) ────────────────────────────

async def get_acceso_para_pago(ref: str, user_id: int) -> dict | None:
    """Datos del audit del usuario para calcular precio + verificar elegibilidad."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.id              AS acceso_id,
                   a.ref,
                   a.duracion,
                   a.prioridad,
                   a.scope,
                   a.estado,
                   a.descargo_id,
                   a.pago_id,
                   a.pagado_at,
                   e.id              AS empresa_id,
                   e.nombre          AS empresa_nombre,
                   u.email           AS user_email
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            JOIN Usuario u ON u.id = e.usuario_id
            WHERE a.ref = $1 AND e.usuario_id = $2
            """,
            ref, user_id,
        )
    if row is None:
        return None
    d = dict(row)
    d["scope"] = list(d["scope"]) if d["scope"] else []
    return d


async def buscar_codigo_promo(codigo: str, user_id: int) -> dict | None:
    """Devuelve el código si es válido para este usuario, o None."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, codigo, descuento_pct, max_usos, usos,
                   owner_user_id, activo, expira_at
            FROM CodigoPromocional
            WHERE codigo = $1
            """,
            codigo,
        )
    if row is None:
        return None
    d = dict(row)
    if not d["activo"]:
        return None
    if d["expira_at"] is not None:
        from datetime import datetime
        if d["expira_at"] < datetime.utcnow():
            return None
    if d["max_usos"] is not None and d["usos"] >= d["max_usos"]:
        return None
    if d["owner_user_id"] is not None and d["owner_user_id"] != user_id:
        return None
    return d


async def crear_pago(
    *, acceso_id: int, usuario_id: int,
    importe_eur_cents: int, descuento_cents: int, final_eur_cents: int,
    codigo_promo_id: int | None = None,
    btcpay_invoice_id: str | None = None,
    metodo: str = "btcpay",
    estado: str = "pendiente",
    pagado_at=None,
) -> int:
    """Inserta una fila Pago. Si estado='pagado', incrementa usos del cupón
    y enlaza Acceso.pago_id + pagado_at en la misma transacción."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO Pago
                    (acceso_id, usuario_id, importe_eur_cents, descuento_cents,
                     final_eur_cents, codigo_promo_id, btcpay_invoice_id,
                     metodo, estado, pagado_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id
                """,
                acceso_id, usuario_id, importe_eur_cents, descuento_cents,
                final_eur_cents, codigo_promo_id, btcpay_invoice_id,
                metodo, estado, pagado_at,
            )
            pago_id = row["id"]
            if estado == "pagado":
                await conn.execute(
                    """
                    UPDATE Acceso
                    SET pago_id   = $2,
                        pagado_at = COALESCE($3, NOW()),
                        estado    = CASE WHEN estado = 'pendiente_pago'
                                         THEN 'pendiente'
                                         ELSE estado END
                    WHERE id = $1
                    """,
                    acceso_id, pago_id, pagado_at,
                )
                if codigo_promo_id:
                    await conn.execute(
                        "UPDATE CodigoPromocional SET usos = usos + 1 WHERE id = $1",
                        codigo_promo_id,
                    )
            return pago_id


async def confirmar_pago_btcpay(invoice_id: str, raw_payload: dict) -> dict | None:
    """Marca un Pago como pagado a partir del invoice_id del webhook.
    Devuelve {pago_id, acceso_id, ref} o None si no encuentra el invoice."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            pago = await conn.fetchrow(
                """
                SELECT p.id AS pago_id, p.acceso_id, p.codigo_promo_id, p.estado,
                       a.ref
                FROM Pago p JOIN Acceso a ON a.id = p.acceso_id
                WHERE p.btcpay_invoice_id = $1
                FOR UPDATE
                """,
                invoice_id,
            )
            if pago is None:
                return None
            if pago["estado"] == "pagado":
                return {"pago_id": pago["pago_id"], "acceso_id": pago["acceso_id"],
                        "ref": pago["ref"], "already_paid": True}
            await conn.execute(
                """
                UPDATE Pago
                SET estado = 'pagado', pagado_at = NOW(),
                    raw_btcpay = COALESCE(raw_btcpay, '{}'::jsonb) || $2::jsonb
                WHERE id = $1
                """,
                pago["pago_id"],
                __import__("json").dumps(raw_payload),
            )
            await conn.execute(
                """
                UPDATE Acceso
                SET pago_id   = $2,
                    pagado_at = NOW(),
                    estado    = CASE WHEN estado = 'pendiente_pago'
                                     THEN 'pendiente'
                                     ELSE estado END
                WHERE id = $1
                """,
                pago["acceso_id"], pago["pago_id"],
            )
            if pago["codigo_promo_id"]:
                await conn.execute(
                    "UPDATE CodigoPromocional SET usos = usos + 1 WHERE id = $1",
                    pago["codigo_promo_id"],
                )
            return {"pago_id": pago["pago_id"], "acceso_id": pago["acceso_id"],
                    "ref": pago["ref"], "already_paid": False}


# ── Stats públicas anonimizadas (T5 — dashboard /hitos) ──────────────────────

async def get_public_stats(k_min: int = 3) -> dict:
    """Agregados anonimizados de auditorías para mostrar en /hitos.

    Aplica k-anonymity: categorías (tipo, sector) con menos de `k_min`
    auditorías se agrupan en una bucket "Otros" para evitar reidentificación.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows_estado = await conn.fetch(
            """
            SELECT estado, COUNT(*)::int AS n
            FROM Acceso
            GROUP BY estado
            """,
        )
        # Por tipo de auditoría (desplegando array scope)
        rows_tipo = await conn.fetch(
            """
            SELECT unnested AS tipo, COUNT(*)::int AS n
            FROM Acceso, unnest(scope) AS unnested
            WHERE estado IN ('completada', 'en_curso')
            GROUP BY unnested
            ORDER BY n DESC
            """,
        )
        # Por sector (de la empresa)
        rows_sector = await conn.fetch(
            """
            SELECT COALESCE(s.nombre, e.sector, 'Sin sector') AS sector,
                   COUNT(DISTINCT a.id)::int AS n
            FROM Acceso a
            JOIN Empresa e ON e.id = a.empresa_id
            LEFT JOIN EmpresaSector es ON es.empresa_id = e.id
            LEFT JOIN Sector s ON s.id = es.sector_id
            WHERE a.estado IN ('completada', 'en_curso')
            GROUP BY COALESCE(s.nombre, e.sector, 'Sin sector')
            ORDER BY n DESC
            """,
        )
        # Por mes últimos 12 meses
        rows_mes = await conn.fetch(
            """
            SELECT TO_CHAR(fecha_inicial, 'YYYY-MM') AS mes,
                   COUNT(*)::int AS n
            FROM Acceso
            WHERE estado IN ('completada', 'en_curso')
              AND fecha_inicial IS NOT NULL
              AND fecha_inicial >= (CURRENT_DATE - INTERVAL '12 months')
            GROUP BY mes
            ORDER BY mes
            """,
        )
        empresas_unicas = await conn.fetchval(
            """
            SELECT COUNT(DISTINCT empresa_id) FROM Acceso
            WHERE estado IN ('completada', 'en_curso')
            """,
        )

    estados = {r["estado"]: r["n"] for r in rows_estado}
    total_completadas = estados.get("completada", 0)
    total_en_curso    = estados.get("en_curso", 0)
    total_canceladas  = estados.get("cancelada", 0)
    total_fallidas    = estados.get("fallida", 0)

    def k_bucket(rows: list, key: str) -> list[dict]:
        out: list[dict] = []
        otros = 0
        for r in rows:
            n = r["n"]
            if n >= k_min:
                out.append({"label": r[key], "n": n})
            else:
                otros += n
        if otros > 0:
            out.append({"label": "Otros", "n": otros})
        return out

    return {
        "total_completadas": total_completadas,
        "total_en_curso":    total_en_curso,
        "total_canceladas":  total_canceladas,
        "total_fallidas":    total_fallidas,
        "empresas_unicas":   empresas_unicas or 0,
        "k_min":             k_min,
        "por_tipo":   k_bucket(rows_tipo,   "tipo"),
        "por_sector": k_bucket(rows_sector, "sector"),
        "por_mes":    [{"mes": r["mes"], "n": r["n"]} for r in rows_mes],
    }


async def get_descargo_estado(ref: str, user_id: int) -> dict | None:
    """Estado actual de la firma para una auditoría del usuario."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT a.id          AS acceso_id,
                   a.ref,
                   a.estado,
                   a.descargo_id,
                   d.signer_dn,
                   d.signer_serial,
                   d.firmado_at,
                   d.verificado_at,
                   d.valido
            FROM Acceso a
            JOIN Empresa e        ON e.id = a.empresa_id
            LEFT JOIN DescargoFirmado d ON d.id = a.descargo_id
            WHERE a.ref = $1 AND e.usuario_id = $2
            """,
            ref, user_id,
        )
    return dict(row) if row else None
