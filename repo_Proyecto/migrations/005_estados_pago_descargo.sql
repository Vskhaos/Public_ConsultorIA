-- ─────────────────────────────────────────────────────────────────────────────
-- Migración 005: ampliar acceso_estado_check con 'pendiente_descargo' y
-- 'pendiente_pago' (introducidos en migraciones 003 y 004 por error en código,
-- pero el CHECK constraint no se había ampliado y rechaza los INSERT/UPDATE).
-- ─────────────────────────────────────────────────────────────────────────────
BEGIN;

ALTER TABLE Acceso DROP CONSTRAINT IF EXISTS acceso_estado_check;

ALTER TABLE Acceso
    ADD CONSTRAINT acceso_estado_check
    CHECK (estado IN (
        'pendiente_descargo',  -- creado, falta firma del descargo
        'pendiente_pago',      -- firmado, falta pago
        'pendiente',           -- firmado y pagado, listo para auto-poller
        'en_curso',            -- engagement activo
        'completada',          -- informe entregado
        'cancelada',           -- cancelada por cliente o admin
        'fallida'              -- fallo en orquestador
    ));

COMMIT;
