-- init.sql — Esquema inicial de la base de datos de auditoría
-- Se ejecuta automáticamente al crear el contenedor PostgreSQL por primera vez.

CREATE TABLE IF NOT EXISTS Empresa (
    id        SERIAL PRIMARY KEY,
    nombre    VARCHAR(255) NOT NULL,
    sector    VARCHAR(100),
    dominio   VARCHAR(255),
    ips       INET[],
    scope     VARCHAR[],
    prioridad VARCHAR(50),
    registro  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS Contacto (
    id           SERIAL PRIMARY KEY,
    empresa_id   INTEGER NOT NULL REFERENCES Empresa(id) ON DELETE CASCADE,
    nombre       VARCHAR(255) NOT NULL,
    rol          VARCHAR(100),
    departamento VARCHAR(100),
    email        VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS Acceso (
    id                SERIAL PRIMARY KEY,
    empresa_id        INTEGER NOT NULL REFERENCES Empresa(id) ON DELETE CASCADE,
    metodo            VARCHAR(50),
    notas             TEXT,
    fecha_inicial     DATE,
    fecha_final       DATE,
    duracion          VARCHAR(100),
    horario_preferido VARCHAR(20)
);

-- Migración no destructiva para bases de datos ya existentes
ALTER TABLE IF EXISTS Acceso ADD COLUMN IF NOT EXISTS fecha_final       DATE;
ALTER TABLE IF EXISTS Acceso ADD COLUMN IF NOT EXISTS horario_preferido VARCHAR(20);
ALTER TABLE IF EXISTS Acceso ADD COLUMN IF NOT EXISTS ref               VARCHAR(50);
