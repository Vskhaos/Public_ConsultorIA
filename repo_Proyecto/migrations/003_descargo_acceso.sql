-- ─────────────────────────────────────────────────────────────────────────────
-- Migración 003: descargo firmado por auditoría (no por usuario)
-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotente. Cambios:
--   1. DescargoFirmado.acceso_id (FK Acceso, ON DELETE CASCADE)
--   2. UNIQUE parcial (acceso_id) WHERE valido = TRUE — un único descargo
--      válido por auditoría (varios intentos fallidos no bloquean)
--   3. Acceso.estado admite 'pendiente_descargo' (sin CHECK constraint nuevo,
--      ya es VARCHAR libre — solo lo documentamos)
--   4. Acceso.descargo_id FK opcional al descargo válido (lookup rápido)
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- CIF/NIF de la empresa contratante: dato necesario para que el descargo
-- legal tenga valor. Opcional al signup; se exige al firmar el descargo.
ALTER TABLE Empresa
    ADD COLUMN IF NOT EXISTS cif VARCHAR(20);

ALTER TABLE DescargoFirmado
    ADD COLUMN IF NOT EXISTS acceso_id INTEGER REFERENCES Acceso(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_descargo_acceso ON DescargoFirmado (acceso_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_descargo_acceso_unico_valido
    ON DescargoFirmado (acceso_id) WHERE valido = TRUE;

ALTER TABLE Acceso
    ADD COLUMN IF NOT EXISTS descargo_id INTEGER REFERENCES DescargoFirmado(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_acceso_descargo ON Acceso (descargo_id);

COMMENT ON COLUMN Acceso.descargo_id IS 'FK al descargo firmado válido. NULL hasta que el cliente sube el PDF firmado y endesive valida la cadena FNMT/Cl@ve.';
COMMENT ON COLUMN DescargoFirmado.acceso_id IS 'Una auditoría → 0..N intentos, 0..1 válido (UNIQUE partial WHERE valido).';

COMMIT;
