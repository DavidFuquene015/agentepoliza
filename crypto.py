"""
crypto.py — Cifrado simétrico de datos sensibles.
================================================================

Qué hace este módulo
--------------------
Cifra y descifra TODO lo sensible que la aplicación guarda en MySQL o en el
filesystem: el JSON con los datos extraídos del contrato/póliza y los propios
archivos originales (PDF/DOCX). Así, si alguien accede a la base de datos o al
disco, no puede leer el contenido sin la clave.

Usa **Fernet** (de la librería `cryptography`), que internamente es
AES-128 en modo CBC + HMAC-SHA256 (cifrado autenticado: detecta manipulación).

Configuración necesaria para el deploy
--------------------------------------
Requiere la variable de entorno **ENCRYPTION_KEY** en el archivo `.env`.
Debe ser una clave Fernet válida (base64 de 32 bytes). Se genera con:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

IMPORTANTE: si se pierde o se cambia esta clave, los documentos ya cifrados
quedan ILEGIBLES. Guárdala de forma segura y no la cambies entre despliegues.

Dependencias
------------
- os                     : lee la variable de entorno ENCRYPTION_KEY.
- cryptography.fernet    : implementación del cifrado Fernet (paquete `cryptography`).
- dotenv (python-dotenv) : carga el archivo .env para que ENCRYPTION_KEY esté disponible.
"""
import os
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

# Carga las variables definidas en el archivo .env al entorno del proceso.
load_dotenv()


def _fernet() -> Fernet:
    """
    Construye el objeto Fernet a partir de la clave ENCRYPTION_KEY del entorno.

    Es una función interna (prefijo _) que centraliza la lectura de la clave.
    Lanza EnvironmentError si la clave no está configurada, para que el fallo
    sea claro durante el arranque/deploy en vez de un error críptico más adelante.
    """
    key = os.environ.get("ENCRYPTION_KEY", "")
    if not key:
        raise EnvironmentError("ENCRYPTION_KEY no está configurada en .env")
    return Fernet(key.encode())


def cifrar_bytes(data: bytes) -> bytes:
    """Cifra bytes (archivos PDF/DOCX). Devuelve token Fernet como bytes."""
    # None se propaga tal cual (p. ej. cuando no hay archivo que guardar).
    if data is None:
        return None
    return _fernet().encrypt(data)


def descifrar_bytes(token) -> bytes:
    """Descifra bytes. Si el dato no estaba cifrado (registros anteriores), lo devuelve tal cual."""
    if token is None:
        return None
    try:
        # bytes(token) admite tanto bytes como bytearray/memoryview que devuelve MySQL.
        return _fernet().decrypt(bytes(token))
    except (InvalidToken, Exception):
        # Compatibilidad hacia atrás: si el registro se guardó SIN cifrar
        # (antes de activar el cifrado), se devuelve el contenido original.
        return bytes(token)


def cifrar_texto(text: str) -> str:
    """Cifra una cadena de texto (JSON). Devuelve token Fernet como string ASCII."""
    if text is None:
        return None
    token = _fernet().encrypt(text.encode("utf-8"))
    return token.decode("ascii")


def descifrar_texto(token: str) -> str:
    """Descifra texto. Si no estaba cifrado (registros anteriores), lo devuelve tal cual."""
    if token is None:
        return None
    try:
        data = _fernet().decrypt(token.encode("ascii"))
        return data.decode("utf-8")
    except (InvalidToken, Exception):
        # Igual que en descifrar_bytes: tolera registros antiguos sin cifrar.
        return token
