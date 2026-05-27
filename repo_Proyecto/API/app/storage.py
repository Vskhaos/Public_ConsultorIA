"""
storage.py — Cliente MinIO para subir archivos de auditoría.

La interfaz es 100 % compatible con AWS S3: para migrar basta
con cambiar las variables MINIO_* en .env a credenciales de AWS
y poner MINIO_SECURE=true.

Estructura de objetos en el bucket:
  audit-files/
    {ref}/
      wg_config.conf
      ssh_key.pem
"""
from __future__ import annotations

import io
from minio import Minio
from minio.error import S3Error

from app.config import settings

# Cliente singleton (thread-safe)
_client: Minio | None = None


def get_client() -> Minio:
    global _client
    if _client is None:
        _client = Minio(
            endpoint=settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
        _ensure_bucket(_client)
    return _client


def _ensure_bucket(client: Minio) -> None:
    """Crea el bucket si no existe todavía."""
    bucket = settings.minio_bucket
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
    except S3Error as exc:
        # En entornos de producción loguear y relanzar
        raise RuntimeError(f"No se pudo verificar/crear el bucket '{bucket}': {exc}") from exc


def upload_file(
    ref: str,
    filename: str,
    data: bytes,
    content_type: str = "application/octet-stream",
) -> str:
    """
    Sube `data` al bucket bajo la ruta `{ref}/{filename}`.

    Devuelve la clave del objeto (object_name) para guardarlo en BBDD
    o incluirlo en la respuesta si hace falta.
    """
    client = get_client()
    object_name = f"{ref}/{filename}"
    client.put_object(
        bucket_name=settings.minio_bucket,
        object_name=object_name,
        data=io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    )
    return object_name


def copy_object(src_key: str, dst_key: str) -> None:
    """Copia un objeto dentro del mismo bucket sin re-uploadear (server-side
    copy de MinIO/S3). Usado para mover archivos pre-subidos a su key final."""
    from minio.commonconfig import CopySource
    client = get_client()
    client.copy_object(
        bucket_name=settings.minio_bucket,
        object_name=dst_key,
        source=CopySource(settings.minio_bucket, src_key),
    )


def remove_object(object_name: str) -> None:
    """Borra un objeto. Tolerante a not-found."""
    client = get_client()
    try:
        client.remove_object(settings.minio_bucket, object_name)
    except S3Error:
        pass


def get_presigned_url(object_name: str, expires_seconds: int = 3600) -> str:
    """
    Genera una URL pre-firmada para descargar un objeto (útil para el panel admin).
    Válida por `expires_seconds` segundos (por defecto 1 hora).
    """
    from datetime import timedelta

    client = get_client()
    return client.presigned_get_object(
        bucket_name=settings.minio_bucket,
        object_name=object_name,
        expires=timedelta(seconds=expires_seconds),
    )


def get_object_bytes(object_name: str) -> bytes | None:
    """Descarga un objeto del bucket y devuelve los bytes.
    Devuelve None si el objeto no existe."""
    client = get_client()
    try:
        resp = client.get_object(settings.minio_bucket, object_name)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()
    except S3Error as exc:
        if exc.code in ("NoSuchKey", "NoSuchObject"):
            return None
        raise
