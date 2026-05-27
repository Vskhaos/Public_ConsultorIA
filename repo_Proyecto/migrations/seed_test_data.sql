-- ─────────────────────────────────────────────────────────────────────────────
-- seed_test_data.sql
--
-- Datos sintéticos que reproducen el estado real de producción al 2026-05-06
-- (7 empresas, 7 contactos, 7 accesos). Solo para dry-run en postgres efímero
-- local. NO ejecutar en producción.
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO Empresa (id, nombre, sector, dominio, ips, scope, prioridad, registro) VALUES
 (1, 'ClienteD',     'Tecnología', 'http://cliented.example.com',                 ARRAY[]::inet[],
   ARRAY['pentest_ext','pentest_int','web_app','cloud','compliance','gdpr','phishing','wifi']::varchar[],
   'high',  '2026-04-22 13:46:20'),
 (2, 'ClienteB',         'Tecnología', 'https://clienteb.example.com',                ARRAY[]::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-04 15:37:12'),
 (3, 'ClienteC',       'Tecnología', 'https://clientec.example.com',             ARRAY[]::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-05 13:38:27'),
 (4, 'ClienteA',       'Tecnología', 'https://sso.demo2.clientea.example.com',
   ARRAY['198.51.100.21','198.51.100.22','198.51.100.23','198.51.100.24']::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-05 16:29:18'),
 (5, 'ClienteA',       'Tecnología', 'https://statsv2.demo2.clientea.example.com',
   ARRAY['198.51.100.21','198.51.100.22','198.51.100.23','198.51.100.24']::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-05 16:42:07'),
 (6, 'ClienteA',       'Tecnología', 'https://statsv2.demo2.clientea.example.com',
   ARRAY['198.51.100.24','198.51.100.23','198.51.100.22','198.51.100.21']::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-05 16:49:25'),
 (7, 'laconsultoria', 'Tecnología', 'https://laconsultoria.cat/',
   ARRAY['203.0.113.11']::inet[],
   ARRAY['pentest_ext']::varchar[], 'high', '2026-05-06 15:16:18');

SELECT setval('empresa_id_seq', (SELECT MAX(id) FROM Empresa));

INSERT INTO Contacto (id, empresa_id, nombre, rol, departamento, email) VALUES
 (1, 1, 'Carlos',    'CEO', 'Directivo', 'c@gmail.com'),
 (2, 2, 'Xavi Lara', 'CEO', 'CEO',       'contacto@clientec.example.com'),
 (3, 3, 'Xavi',      'CEO', 'IA',        'contacto@clientec.example.com'),
 (4, 4, 'Auditor',     'CEO', 'IA',        'auditor@laconsultoria.cat'),
 (5, 5, 'Auditor',     'CEO', 'IA',        'auditor@laconsultoria.cat'),
 (6, 6, 'Auditor',     'CEO', 'IA',        'auditor@laconsultoria.cat'),
 (7, 7, 'Auditor',      'CEO', 'CEO',       'auditor@itb.example');

SELECT setval('contacto_id_seq', (SELECT MAX(id) FROM Contacto));

INSERT INTO Acceso (id, empresa_id, ref, fecha_inicial, fecha_final, duracion, metodo, horario_preferido) VALUES
 (1, 1, NULL,         '2026-04-25', '2026-04-27', '2-3d',   'wireguard', '13:30-22:00'),
 (2, 2, 'AUD-RBXDBQ', '2026-05-04', '2026-05-04', '1d',     NULL,        '20:00-22:00'),
 (3, 3, 'AUD-SO5PII', '2026-05-05', NULL,         'custom', NULL,        '16:00-18:00'),
 (4, 4, 'AUD-SUC3X2', '2026-05-05', NULL,         'custom', NULL,        '18:40-20:30'),
 (5, 5, 'AUD-SUS2FJ', '2026-05-05', NULL,         'custom', NULL,        '20:40-21:30'),
 (6, 6, 'AUD-SV36Z3', '2026-05-05', NULL,         'custom', NULL,        '22:40-23:55'),
 (7, 7, 'AUD-U757HD', '2026-05-06', NULL,         'custom', NULL,        '17:18-23:00');

SELECT setval('acceso_id_seq', (SELECT MAX(id) FROM Acceso));
