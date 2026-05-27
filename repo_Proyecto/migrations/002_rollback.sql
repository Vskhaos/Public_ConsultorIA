-- ─────────────────────────────────────────────────────────────────────────────
-- 002_rollback.sql
--
-- Rollback de 002_users_scope_acceso.sql.
--
-- ⚠️  CUIDADO: solo es seguro ejecutar este rollback INMEDIATAMENTE tras aplicar
--     la migración, ANTES de que la API nueva escriba ningún Acceso usando
--     las columnas nuevas (dominio/ips/scope/prioridad). Si ya hay escrituras
--     con el schema nuevo, este rollback PIERDE esos datos. Para rollback con
--     datos ya escritos, restaurar desde el dump pg_dump previo.
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- DescargoFirmado y EmpresaSector dependen de Usuario/Sector → primero ellas.
DROP TABLE IF EXISTS DescargoFirmado;
DROP TABLE IF EXISTS EmpresaSector;
DROP TABLE IF EXISTS Sector;

-- Empresa.usuario_id (FK → Usuario)
ALTER TABLE Empresa DROP COLUMN IF EXISTS usuario_id;

-- Acceso: columnas y constraint añadidas en 002.
ALTER TABLE Acceso DROP CONSTRAINT IF EXISTS acceso_estado_check;
ALTER TABLE Acceso
    DROP COLUMN IF EXISTS dominio,
    DROP COLUMN IF EXISTS ips,
    DROP COLUMN IF EXISTS scope,
    DROP COLUMN IF EXISTS prioridad,
    DROP COLUMN IF EXISTS estado,
    DROP COLUMN IF EXISTS reagendada_de,
    DROP COLUMN IF EXISTS cancelada_at;

-- Usuario al final (otras tablas tenían FK a él).
DROP TABLE IF EXISTS Usuario;

-- Comentarios de deprecación: limpiarlos.
COMMENT ON COLUMN Empresa.dominio   IS NULL;
COMMENT ON COLUMN Empresa.ips       IS NULL;
COMMENT ON COLUMN Empresa.scope     IS NULL;
COMMENT ON COLUMN Empresa.prioridad IS NULL;
COMMENT ON COLUMN Empresa.sector    IS NULL;

COMMIT;
