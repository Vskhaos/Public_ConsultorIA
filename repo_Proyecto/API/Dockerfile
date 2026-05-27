FROM python:3.12-slim

WORKDIR /app

# Dependencias del sistema. build-essential + libpkcs11 para que pip pueda
# compilar pykcs11 (tirado por endesive). pango/cairo/gdk-pixbuf son runtime
# deps de WeasyPrint (informe PDF). Se purgan los de build tras instalar para
# minimizar tamaño de la imagen.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        swig \
        libpcsclite-dev \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python primero (aprovecha caché de capas)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove build-essential swig \
    && rm -rf /var/lib/apt/lists/*

# Copiar el código de la aplicación + certs raíz FNMT/Cl@ve
COPY app/ ./app/
COPY certs/ ./certs/

EXPOSE 8000

# Healthcheck para que Swarm sepa cuando el servicio está listo
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
