# ConsultorIA — API de Auditoría de Seguridad

API FastAPI que recibe las solicitudes del formulario HTML, las persiste en
PostgreSQL y sube los archivos adjuntos a MinIO (compatible con AWS S3).

---

## Estructura del proyecto

```
audit-api/
├── app/
│   ├── __init__.py
│   ├── main.py        # Entrypoint FastAPI
│   ├── config.py      # Variables de entorno (Pydantic Settings)
│   ├── database.py    # Pool asyncpg + helpers de inserción
│   ├── storage.py     # Cliente MinIO / S3
│   ├── schemas.py     # Modelos Pydantic (validación)
│   └── routes.py      # Endpoint POST /api/audit-request
├── docker-compose.yml # MinIO únicamente
├── requirements.txt
├── .env.example       # Plantilla de variables de entorno
├── formulario.patch.js # Parche JS para el formulario
└── README.md
```

---

## Puesta en marcha

### 1. Clonar / copiar el proyecto

```bash
cd audit-api
```

### 2. Crear el entorno virtual e instalar dependencias

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configurar variables de entorno

```bash
cp .env.example .env
```

Edita `.env` con tus credenciales reales:

```env
DB_PASSWORD=tu_password_postgres
MINIO_SECRET_KEY=una_clave_segura_minimo_8_chars
```

### 4. Levantar MinIO con Docker

```bash
docker compose up -d
```

- **API S3**: http://localhost:9000  
- **Consola web**: http://localhost:9001 (usuario: `minioadmin`, contraseña: la de `.env`)

El servicio `minio_init` crea el bucket automáticamente.

### 5. Arrancar la API

```bash
uvicorn app.main:app --reload
```

- **API**: http://localhost:8000  
- **Swagger UI**: http://localhost:8000/docs  
- **ReDoc**: http://localhost:8000/redoc

---

## Integrar con el formulario HTML

Añade este `<script>` justo antes de `</body>` en `formulario.html`
(**después** del script inline existente):

```html
<script src="formulario.patch.js"></script>
```

El parche sobreescribe el listener de submit original para enviar
`multipart/form-data` a `http://localhost:8000/api/audit-request`.

---

## Endpoint

### `POST /api/audit-request`

**Content-Type**: `multipart/form-data`

| Campo    | Tipo      | Descripción                                      |
|----------|-----------|--------------------------------------------------|
| `data`   | string    | JSON con el payload del formulario (obligatorio) |
| `wg_conf`| file      | Archivo `.conf` de WireGuard (opcional)          |
| `ssh_key`| file      | Clave privada SSH `.pem`/`.key` (opcional)       |

**Respuesta exitosa (201)**:
```json
{
  "ok": true,
  "ref": "AUD-X7K2P1",
  "empresa_id": 1,
  "contacto_id": 1,
  "acceso_id": 1,
  "uploaded_files": ["AUD-X7K2P1/wg_config.conf"],
  "message": "Solicitud registrada correctamente"
}
```

---

## Migración a AWS S3

Solo cambia estas líneas en `.env`:

```env
MINIO_ENDPOINT=s3.amazonaws.com
MINIO_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
MINIO_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
MINIO_BUCKET=tu-bucket-s3
MINIO_SECURE=true
```

No hay que modificar ningún archivo de código.

---

## Esquema de la base de datos (referencia)

```sql
CREATE DATABASE auditoria_db;
\c auditoria_db;

CREATE TABLE Empresa (
    id       SERIAL PRIMARY KEY,
    nombre   VARCHAR(255) NOT NULL,
    sector   VARCHAR(100),
    dominio  VARCHAR(255),
    ips      INET[],
    scope    VARCHAR[],
    prioridad VARCHAR(50),
    registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Contacto (
    id          SERIAL PRIMARY KEY,
    empresa_id  INT REFERENCES Empresa(id) ON DELETE CASCADE,
    nombre      VARCHAR(255) NOT NULL,
    rol         VARCHAR(100),
    departamento VARCHAR(100),
    email       VARCHAR(255) CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE TABLE Acceso (
    id            SERIAL PRIMARY KEY,
    empresa_id    INT REFERENCES Empresa(id) ON DELETE CASCADE,
    metodo        VARCHAR(100),
    notas         TEXT,
    fecha_inicial DATE,
    duracion      VARCHAR(50),
    fecha_final   DATE
);
```

> **Nota**: el campo `telefono` del contacto no existe en el schema actual.
> Si quieres persistirlo, añade `telefono VARCHAR(50)` a la tabla `Contacto`.
