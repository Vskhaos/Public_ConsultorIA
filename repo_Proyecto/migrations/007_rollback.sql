-- Rollback de 007_pgcrypto_fase_a.sql
-- Restaura las columnas planas a partir de las _enc (necesita la key
-- DB_FIELD_KEY que se usó para cifrar) y elimina las _enc.

BEGIN;

UPDATE Acceso
   SET notas = pgp_sym_decrypt(notas_enc, :key)
 WHERE notas IS NULL AND notas_enc IS NOT NULL;

UPDATE Empresa
   SET cif = pgp_sym_decrypt(cif_enc, :key)
 WHERE cif IS NULL AND cif_enc IS NOT NULL;

UPDATE Contacto
   SET departamento = CASE WHEN departamento_enc IS NOT NULL AND departamento IS NULL
                           THEN pgp_sym_decrypt(departamento_enc, :key)
                           ELSE departamento END,
       rol          = CASE WHEN rol_enc IS NOT NULL AND rol IS NULL
                           THEN pgp_sym_decrypt(rol_enc, :key)
                           ELSE rol END;

ALTER TABLE Acceso   DROP COLUMN IF EXISTS notas_enc;
ALTER TABLE Empresa  DROP COLUMN IF EXISTS cif_enc;
ALTER TABLE Contacto DROP COLUMN IF EXISTS departamento_enc;
ALTER TABLE Contacto DROP COLUMN IF EXISTS rol_enc;

COMMIT;
