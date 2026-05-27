-- Migración 006: UNIQUE en Acceso.ref como defensa en profundidad contra
-- POSTs duplicados (navegador con retry, doble click, etc.). El frontend
-- también generará la ref una sola vez al abrir el modal, pero esto
-- garantiza idempotencia en BD aunque el cliente la regenere.
BEGIN;

DELETE FROM Acceso a USING Acceso b
WHERE a.id < b.id AND a.ref = b.ref AND a.ref IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_acceso_ref_unique
    ON Acceso (ref) WHERE ref IS NOT NULL;

COMMIT;
