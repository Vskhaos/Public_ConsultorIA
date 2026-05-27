-- ─────────────────────────────────────────────────────────────────────────────
-- 002_users_scope_acceso.sql
--
-- Migración no destructiva, idempotente. Aplica sobre el schema de init.sql:
--   Empresa, Contacto, Acceso (3 tablas).
--
-- Añade:
--   • Usuario               (auth multi-cliente, semilla auditor admin)
--   • Sector + EmpresaSector (catálogo N:M, sustituye a Empresa.sector text)
--   • Empresa.usuario_id    (FK a Usuario, backfill a auditor)
--   • Acceso.dominio/ips/scope/prioridad (alcance técnico = por auditoría,
--                                        no por empresa). Backfill desde Empresa.
--   • Acceso.estado/reagendada_de/cancelada_at (estado del engagement +
--                                              cancel/reagenda con cutoff 24h)
--   • DescargoFirmado       (PDF firmado digitalmente por el usuario, requerido
--                           para pedir auditoría — verificación con endesive)
--
-- Empresa.{dominio,ips,scope,prioridad,sector} quedan DEPRECATED (no se borran
-- aquí; se eliminan en una migración posterior cuando el código no las use).
--
-- Ejecución en producción (VPS2):
--   docker exec -i $(docker ps -qf name=postgres) \
--       psql -U api_user -d auditoria_db < 002_users_scope_acceso.sql
--
-- Reversible: hay un script 002_rollback.sql que devuelve el schema a v001.
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── 1. Tabla Usuario ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Usuario (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    nombre          VARCHAR(255),
    rol             VARCHAR(20)  NOT NULL DEFAULT 'cliente'
                    CHECK (rol IN ('admin', 'cliente')),
    email_verified  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMP
);

-- Semilla: usuario admin auditor. password_hash = el mismo bcrypt que ya está en
-- el ENV del stack (ADMIN_PASSWORD_HASH), así sigue iniciando con su password.
INSERT INTO Usuario (email, password_hash, nombre, rol, email_verified)
VALUES (
    'auditor@laconsultoria.cat',
    '<REDACTED-BCRYPT>',
    'Auditor Demo',
    'admin',
    TRUE
)
ON CONFLICT (email) DO NOTHING;


-- ── 2. Catálogo de sectores (N:M) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Sector (
    id      SERIAL PRIMARY KEY,
    nombre  VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS EmpresaSector (
    empresa_id  INTEGER NOT NULL REFERENCES Empresa(id) ON DELETE CASCADE,
    sector_id   INTEGER NOT NULL REFERENCES Sector(id)  ON DELETE RESTRICT,
    PRIMARY KEY (empresa_id, sector_id)
);

-- Backfill Sector: cada valor distinto de Empresa.sector → fila Sector.
INSERT INTO Sector (nombre)
SELECT DISTINCT TRIM(sector)
FROM Empresa
WHERE sector IS NOT NULL AND TRIM(sector) <> ''
ON CONFLICT (nombre) DO NOTHING;

-- Backfill EmpresaSector: relación 1:1 inicial (cada empresa con su sector).
INSERT INTO EmpresaSector (empresa_id, sector_id)
SELECT e.id, s.id
FROM Empresa e
JOIN Sector  s ON s.nombre = TRIM(e.sector)
WHERE e.sector IS NOT NULL AND TRIM(e.sector) <> ''
ON CONFLICT DO NOTHING;


-- ── 3. Empresa.usuario_id (1 Usuario → N Empresas) ───────────────────────────
ALTER TABLE Empresa
    ADD COLUMN IF NOT EXISTS usuario_id INTEGER
    REFERENCES Usuario(id) ON DELETE RESTRICT;

-- Backfill: todas las Empresas existentes pertenecen a auditor (admin).
UPDATE Empresa
SET    usuario_id = (SELECT id FROM Usuario
                     WHERE email = 'auditor@laconsultoria.cat')
WHERE  usuario_id IS NULL;

-- Tras backfill, hacer NOT NULL (ya no debe haber filas con NULL).
ALTER TABLE Empresa
    ALTER COLUMN usuario_id SET NOT NULL;


-- ── 4. Acceso: alcance técnico (dominio/ips/scope/prioridad) + estado ───────
ALTER TABLE Acceso
    ADD COLUMN IF NOT EXISTS dominio        VARCHAR(255),
    ADD COLUMN IF NOT EXISTS ips            INET[],
    ADD COLUMN IF NOT EXISTS scope          VARCHAR[],
    ADD COLUMN IF NOT EXISTS prioridad      VARCHAR(50),
    ADD COLUMN IF NOT EXISTS estado         VARCHAR(20) NOT NULL DEFAULT 'pendiente',
    ADD COLUMN IF NOT EXISTS reagendada_de  INTEGER REFERENCES Acceso(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS cancelada_at   TIMESTAMP;

-- Constraint del estado: idempotente (lo creo solo si no existe).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'acceso_estado_check'
    ) THEN
        ALTER TABLE Acceso
            ADD CONSTRAINT acceso_estado_check
            CHECK (estado IN ('pendiente','en_curso','completada','cancelada','fallida'));
    END IF;
END$$;

-- Backfill: copiar dominio/ips/scope/prioridad de Empresa → Acceso.
-- Solo se ejecuta para filas donde dominio aún es NULL (idempotente).
UPDATE Acceso a
SET    dominio   = e.dominio,
       ips       = COALESCE(e.ips, '{}'::inet[]),
       scope     = COALESCE(e.scope, '{}'::varchar[]),
       prioridad = e.prioridad
FROM   Empresa e
WHERE  a.empresa_id = e.id
  AND  a.dominio IS NULL;

-- Marcar como 'completada' los accesos cuya fecha_inicial ya pasó.
-- Caso especial: AUD-U757HD (registro fantasma del 2026-05-06 que el
-- auto-poller nunca recogió porque la hora de inicio ya había pasado).
UPDATE Acceso
SET    estado = 'completada'
WHERE  fecha_inicial < CURRENT_DATE
  AND  estado = 'pendiente';

UPDATE Acceso
SET    estado       = 'cancelada',
       cancelada_at = NOW()
WHERE  ref = 'AUD-U757HD'
  AND  estado <> 'cancelada';


-- ── 5. DescargoFirmado (PDF firmado digitalmente) ────────────────────────────
CREATE TABLE IF NOT EXISTS DescargoFirmado (
    id              SERIAL PRIMARY KEY,
    usuario_id      INTEGER     NOT NULL REFERENCES Usuario(id) ON DELETE CASCADE,
    pdf_object_key  VARCHAR(500) NOT NULL,   -- key en MinIO (bucket audit-files)
    sha256          VARCHAR(64)  NOT NULL,
    signer_dn       TEXT,                    -- Distinguished Name del cert
    signer_serial   VARCHAR(100),            -- nº serie del cert
    firmado_at      TIMESTAMP,               -- de la firma PKCS7 si está
    verificado_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    valido          BOOLEAN      NOT NULL DEFAULT FALSE,
    UNIQUE (usuario_id, sha256)
);


-- ── 6. Índices ───────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_empresa_usuario  ON Empresa  (usuario_id);
CREATE INDEX IF NOT EXISTS idx_acceso_empresa   ON Acceso   (empresa_id);
CREATE INDEX IF NOT EXISTS idx_acceso_estado    ON Acceso   (estado);
CREATE INDEX IF NOT EXISTS idx_acceso_ref       ON Acceso   (ref);
CREATE INDEX IF NOT EXISTS idx_acceso_fecha     ON Acceso   (fecha_inicial);
CREATE INDEX IF NOT EXISTS idx_descargo_usuario ON DescargoFirmado (usuario_id);


-- ── 7. Comentarios de tabla (deprecación de columnas en Empresa) ─────────────
COMMENT ON COLUMN Empresa.dominio    IS 'DEPRECATED — usar Acceso.dominio. Eliminado en migración 003.';
COMMENT ON COLUMN Empresa.ips        IS 'DEPRECATED — usar Acceso.ips. Eliminado en migración 003.';
COMMENT ON COLUMN Empresa.scope      IS 'DEPRECATED — usar Acceso.scope. Eliminado en migración 003.';
COMMENT ON COLUMN Empresa.prioridad  IS 'DEPRECATED — usar Acceso.prioridad. Eliminado en migración 003.';
COMMENT ON COLUMN Empresa.sector     IS 'DEPRECATED — usar Sector + EmpresaSector. Eliminado en migración 003.';

COMMIT;

-- ── Verificación post-migración (manual) ─────────────────────────────────────
-- SELECT * FROM Usuario;
-- SELECT * FROM Sector; SELECT * FROM EmpresaSector;
-- SELECT id, nombre, usuario_id FROM Empresa;
-- SELECT id, ref, dominio, ips, scope, prioridad, estado FROM Acceso;
