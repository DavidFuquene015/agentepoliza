"""
doc_storage.py — Almacenamiento de archivos históricos en el filesystem.
================================================================

Qué hace este módulo
--------------------
Guarda y recupera los archivos originales (contrato/póliza) YA CIFRADOS en el
disco del servidor, en lugar de meterlos como BLOB dentro de MySQL. Esto evita
que la base de datos crezca de forma desmedida con archivos binarios grandes.

Es OPCIONAL: solo se activa si la variable de entorno DOCUMENT_STORAGE_ROOT
está configurada Y la tabla `documentos` tiene las columnas
`storage_path_contrato` / `storage_path_poliza`. Si no, los archivos se siguen
guardando dentro de MySQL (ver database.py).

Estructura en disco
-------------------
Cada documento tiene su carpeta por id:
    <DOCUMENT_STORAGE_ROOT>/<doc_id>/contrato
    <DOCUMENT_STORAGE_ROOT>/<doc_id>/poliza
En la base de datos solo se guarda la ruta RELATIVA ("<doc_id>/contrato").

Configuración necesaria para el deploy
--------------------------------------
- DOCUMENT_STORAGE_ROOT = ruta absoluta del directorio base (p. ej.
  /opt/colvatel-app/var/documentos_hist). El usuario del servicio debe tener
  permiso de escritura sobre esa carpeta.

Seguridad
---------
`_validate_rel` sanea la ruta relativa para impedir "path traversal"
(que un id malicioso salga de la carpeta base con "../"). Solo admite el
patrón exacto "<número>/contrato" o "<número>/poliza".

Dependencias
------------
- logging        : registra advertencias (archivo no encontrado, etc.).
- os             : lee DOCUMENT_STORAGE_ROOT y arma rutas del sistema.
- re             : valida que el id de la ruta sean solo dígitos.
- shutil         : borra carpetas de documentos de forma recursiva.
- pathlib.Path   : manejo de rutas multiplataforma.
- dotenv         : carga el .env (python-dotenv).
"""
# `from __future__ import annotations` permite usar tipos como "Path | None"
# en versiones de Python donde esa sintaxis aún no es nativa en anotaciones.
from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Patrón del id de carpeta: solo dígitos. Y las dos únicas "colas" válidas.
_REL_SEGMENT = re.compile(r"^[0-9]+$")
_REL_TAIL = frozenset({"contrato", "poliza"})


def root_dir() -> Path | None:
    """Devuelve la carpeta base de almacenamiento (Path) o None si no está configurada."""
    raw = (os.environ.get("DOCUMENT_STORAGE_ROOT") or "").strip()
    if not raw:
        return None
    # expanduser: resuelve "~"; resolve: pasa a ruta absoluta canónica.
    return Path(raw).expanduser().resolve()


def enabled() -> bool:
    """True si el almacenamiento en filesystem está activo (DOCUMENT_STORAGE_ROOT definido)."""
    return root_dir() is not None


def _validate_rel(rel: str) -> str:
    """Solo permite '123/contrato' o '123/poliza' (segmentos sanitizados)."""
    if not rel or not isinstance(rel, str):
        raise ValueError("ruta vacía")
    # Normaliza separadores de Windows y quita barras al inicio/fin.
    rel = rel.replace("\\", "/").strip("/")
    parts = rel.split("/")
    if len(parts) != 2:
        raise ValueError("ruta inválida")
    d, tail = parts[0], parts[1]
    # El primer segmento debe ser solo dígitos y el segundo, contrato o poliza.
    if not _REL_SEGMENT.fullmatch(d) or tail not in _REL_TAIL:
        raise ValueError("ruta no permitida")
    return f"{d}/{tail}"


def doc_subdir(doc_id: int) -> Path:
    """Ruta absoluta de la carpeta de un documento: <root>/<doc_id>."""
    r = root_dir()
    if r is None:
        raise RuntimeError("DOCUMENT_STORAGE_ROOT no configurado")
    d = int(doc_id)
    return r / str(d)


def write_pair(doc_id: int, contrato_cifrado: bytes | None, poliza_cifrada: bytes | None) -> tuple[str | None, str | None]:
    """Escribe blobs cifrados en disco; devuelve rutas relativas para la BD."""
    base = doc_subdir(doc_id)
    # Crea la carpeta del documento si no existe (no falla si ya existe).
    base.mkdir(parents=True, exist_ok=True)
    rel_c: str | None = None
    rel_p: str | None = None
    # Solo escribe cada archivo si se recibió contenido para él.
    if contrato_cifrado is not None:
        p = base / "contrato"
        p.write_bytes(contrato_cifrado)
        rel_c = f"{doc_id}/contrato"
    if poliza_cifrada is not None:
        p = base / "poliza"
        p.write_bytes(poliza_cifrada)
        rel_p = f"{doc_id}/poliza"
    return rel_c, rel_p


def read_ciphertext(rel: str | None) -> bytes | None:
    """Lee de disco el contenido cifrado dada su ruta relativa; None si no existe."""
    if not rel:
        return None
    # Sanea la ruta antes de tocar el filesystem (anti path-traversal).
    rel = _validate_rel(rel)
    r = root_dir()
    if r is None:
        return None
    # Convierte la ruta relativa al separador propio del sistema operativo.
    path = r / Path(rel.replace("/", os.sep))
    if not path.is_file():
        logger.warning("Archivo de storage no encontrado: %s", path)
        return None
    return path.read_bytes()


def delete_document_dir(doc_id: int) -> None:
    """Borra por completo la carpeta de un documento (usado si falla el guardado en BD)."""
    d = doc_subdir(doc_id)
    if d.is_dir():
        # ignore_errors: no lanza excepción si algún archivo ya no está.
        shutil.rmtree(d, ignore_errors=True)
