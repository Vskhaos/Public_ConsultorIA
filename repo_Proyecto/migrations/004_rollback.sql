BEGIN;

ALTER TABLE Acceso
    DROP COLUMN IF EXISTS pago_id,
    DROP COLUMN IF EXISTS pagado_at;
DROP INDEX IF EXISTS idx_acceso_pago;

DROP INDEX IF EXISTS idx_pago_acceso_unico_pagado;
DROP INDEX IF EXISTS idx_pago_btcpay;
DROP INDEX IF EXISTS idx_pago_estado;
DROP INDEX IF EXISTS idx_pago_usuario;
DROP INDEX IF EXISTS idx_pago_acceso;
DROP TABLE IF EXISTS Pago;

DROP INDEX IF EXISTS idx_codigopromo_owner;
DROP INDEX IF EXISTS idx_codigopromo_codigo;
DROP TABLE IF EXISTS CodigoPromocional;

COMMIT;
