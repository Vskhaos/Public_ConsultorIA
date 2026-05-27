-- ─────────────────────────────────────────────────────────────────────────────
-- Migración 004: pricing + códigos promocionales + pagos crypto via BTCPay
-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotente. Cambios:
--   1. Tabla CodigoPromocional (cupones con descuento %, scope opcional al user)
--   2. Tabla Pago (1 audit → N intentos, 0..1 pagado)
--   3. Acceso.pagado_at + Acceso.pago_id (FK al Pago confirmado)
--   4. (Seed de código promocional de pruebas — omitido en la copia pública)
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── 1. Códigos promocionales ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS CodigoPromocional (
    id              SERIAL PRIMARY KEY,
    codigo          VARCHAR(64)  NOT NULL UNIQUE,
    descuento_pct   NUMERIC(5,2) NOT NULL CHECK (descuento_pct >= 0 AND descuento_pct <= 100),
    max_usos        INTEGER,                -- NULL = ilimitado
    usos            INTEGER      NOT NULL DEFAULT 0,
    -- Si owner_user_id != NULL, solo ese usuario puede aplicarlo
    owner_user_id   INTEGER      REFERENCES Usuario(id) ON DELETE CASCADE,
    activo          BOOLEAN      NOT NULL DEFAULT TRUE,
    expira_at       TIMESTAMP,              -- NULL = no expira
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    descripcion     TEXT
);

CREATE INDEX IF NOT EXISTS idx_codigopromo_codigo  ON CodigoPromocional (codigo);
CREATE INDEX IF NOT EXISTS idx_codigopromo_owner   ON CodigoPromocional (owner_user_id);


-- ── 2. Pagos ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Pago (
    id                 SERIAL PRIMARY KEY,
    acceso_id          INTEGER     NOT NULL REFERENCES Acceso(id) ON DELETE CASCADE,
    usuario_id         INTEGER     NOT NULL REFERENCES Usuario(id) ON DELETE RESTRICT,
    -- Importes en céntimos para evitar floats
    importe_eur_cents  INTEGER     NOT NULL,        -- precio bruto antes de descuento
    descuento_cents    INTEGER     NOT NULL DEFAULT 0,
    final_eur_cents    INTEGER     NOT NULL,        -- = importe - descuento
    codigo_promo_id    INTEGER     REFERENCES CodigoPromocional(id) ON DELETE SET NULL,
    btcpay_invoice_id  VARCHAR(64),                  -- NULL si pago bypass por código 100%
    metodo             VARCHAR(20) NOT NULL DEFAULT 'btcpay'
                        CHECK (metodo IN ('btcpay', 'promo_bypass')),
    estado             VARCHAR(20) NOT NULL DEFAULT 'pendiente'
                        CHECK (estado IN ('pendiente', 'pagado', 'expirado', 'cancelado')),
    creado_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
    pagado_at          TIMESTAMP,
    raw_btcpay         JSONB                         -- payload del webhook si aplica
);

CREATE INDEX IF NOT EXISTS idx_pago_acceso   ON Pago (acceso_id);
CREATE INDEX IF NOT EXISTS idx_pago_usuario  ON Pago (usuario_id);
CREATE INDEX IF NOT EXISTS idx_pago_estado   ON Pago (estado);
CREATE INDEX IF NOT EXISTS idx_pago_btcpay   ON Pago (btcpay_invoice_id);
-- Solo un pago confirmado por audit
CREATE UNIQUE INDEX IF NOT EXISTS idx_pago_acceso_unico_pagado
    ON Pago (acceso_id) WHERE estado = 'pagado';


-- ── 3. Acceso: link al pago confirmado ──────────────────────────────────────
ALTER TABLE Acceso
    ADD COLUMN IF NOT EXISTS pago_id  INTEGER REFERENCES Pago(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS pagado_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_acceso_pago ON Acceso (pago_id);


-- ── 4. Seed del código de pruebas para auditor ─────────────────────────────────
-- [seed de código promocional de pruebas eliminado de la copia pública]

COMMIT;
