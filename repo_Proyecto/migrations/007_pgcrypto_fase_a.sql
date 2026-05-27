-- Migración 007 — Cifrado de columnas sensibles no-buscables (Fase A).
--
-- Cifra con pgcrypto pgp_sym_encrypt las columnas que NO se usan en
-- WHERE/ORDER/UNIQUE/JOIN/unnest del API actual:
--   - Acceso.notas           (scope_notes del cliente)
--   - Empresa.cif            (NIF / CIF empresarial)
--   - Contacto.departamento  (departamento del contacto)
--   - Contacto.rol           (cargo del contacto)
--
-- Master key en env: DB_FIELD_KEY (ver <.env de secrets, fuera de git> y
-- /home/auditor/ai_pentest/orchestrator/.env, chmod 600).
--
-- Estrategia: ADD COLUMN _enc BYTEA + UPDATE backfill. Las columnas
-- planas SIGUEN existiendo (sin NOT NULL) hasta verificación post-deploy.
-- La migración 008 (post-verificación) las droppea.
--
-- Fase B (futura): cifrar identificadores con HMAC determinístico para
-- mantener lookups: usuario.email, empresa.{nombre,dominio}, etc.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Schema changes
ALTER TABLE Acceso   ADD COLUMN IF NOT EXISTS notas_enc        BYTEA;
ALTER TABLE Empresa  ADD COLUMN IF NOT EXISTS cif_enc          BYTEA;
ALTER TABLE Contacto ADD COLUMN IF NOT EXISTS departamento_enc BYTEA;
ALTER TABLE Contacto ADD COLUMN IF NOT EXISTS rol_enc          BYTEA;

-- Backfill: la key se pasa como GUC de sesión para no quemarla en SQL.
-- Uso:
--   psql -v key="'$DB_FIELD_KEY'" -f 007_pgcrypto_fase_a.sql
-- Si invocas manualmente reemplaza :key por '<clave>'.

UPDATE Acceso
   SET notas_enc = pgp_sym_encrypt(notas, :key)
 WHERE notas IS NOT NULL AND notas_enc IS NULL;

UPDATE Empresa
   SET cif_enc = pgp_sym_encrypt(cif, :key)
 WHERE cif IS NOT NULL AND cif_enc IS NULL;

UPDATE Contacto
   SET departamento_enc = CASE WHEN departamento IS NOT NULL
                               THEN pgp_sym_encrypt(departamento, :key)
                               ELSE NULL END,
       rol_enc          = CASE WHEN rol IS NOT NULL
                               THEN pgp_sym_encrypt(rol, :key)
                               ELSE NULL END
 WHERE departamento IS NOT NULL OR rol IS NOT NULL;

COMMIT;
