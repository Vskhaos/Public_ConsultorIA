-- Rollback de la migración 003. Solo seguro inmediatamente — pierde
-- cualquier descargo firmado escrito tras aplicar 003.

BEGIN;

ALTER TABLE Acceso DROP COLUMN IF EXISTS descargo_id;
DROP INDEX IF EXISTS idx_acceso_descargo;

DROP INDEX IF EXISTS idx_descargo_acceso_unico_valido;
DROP INDEX IF EXISTS idx_descargo_acceso;
ALTER TABLE DescargoFirmado DROP COLUMN IF EXISTS acceso_id;

ALTER TABLE Empresa DROP COLUMN IF EXISTS cif;

COMMIT;
