"""
database.py — Capa de acceso a la base de datos MySQL.
================================================================

Qué hace este módulo
--------------------
Concentra TODA la interacción con MySQL. El resto de la app (app.py) nunca
escribe SQL directamente: llama a las funciones de aquí. Guarda y recupera:
  - `documentos`          : cada análisis de contrato+póliza (datos + archivos + resultado).
  - `manual_contratacion` : las versiones del Manual de Contratación y sus parámetros.

Los datos sensibles (JSON de resultados y archivos) se cifran con crypto.py
ANTES de guardarse, y se descifran al leerse.

Esquema flexible
----------------
La app se adapta a variantes del esquema: algunas columnas son opcionales
(num_polizas, usuario_cedula, storage_path_contrato/poliza). Se detecta cuáles
existen consultando information_schema (con cache) y se ajustan los INSERT/SELECT.

Configuración necesaria para el deploy
--------------------------------------
Variables de entorno (.env): DB_HOST, DB_PORT (opc., 3306), DB_USER, DB_PASSWORD,
DB_NAME. La base debe tener al menos las tablas `documentos` y `manual_contratacion`.

Dependencias
------------
- mysql.connector : driver oficial de MySQL (paquete mysql-connector-python).
- json            : serializa el diccionario de datos antes de cifrarlo.
- logging         : registra errores de BD sin tumbar la app.
- os              : lee las variables DB_* del entorno.
- dotenv          : carga el .env (python-dotenv).
- crypto          : cifra/descifra los datos y archivos.
- doc_storage     : guarda archivos en el filesystem cuando está habilitado.
"""
import mysql.connector
import json
import logging
import os
from dotenv import load_dotenv
import crypto
import doc_storage

load_dotenv()

logger = logging.getLogger(__name__)

# Cache de columnas de `documentos` (evita consultar information_schema en cada request).
_DOCUMENTOS_COLUMNS: set[str] | None = None


def _columnas_tabla_documentos() -> set[str]:
    """
    Devuelve el conjunto de columnas de la tabla `documentos` (con cache en memoria).

    Como algunas columnas son opcionales, se consulta information_schema UNA sola
    vez y se cachea el resultado, para adaptar los INSERT/SELECT a lo que exista.
    """
    global _DOCUMENTOS_COLUMNS
    if _DOCUMENTOS_COLUMNS is not None:
        return _DOCUMENTOS_COLUMNS
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COLUMN_NAME FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'documentos'
            """
        )
        _DOCUMENTOS_COLUMNS = {r[0] for r in cur.fetchall()}
        conn.close()
    except Exception as e:
        logger.warning("No se pudieron leer columnas de documentos: %s", e)
        _DOCUMENTOS_COLUMNS = set()
    return _DOCUMENTOS_COLUMNS


def invalidate_documentos_column_cache() -> None:
    """Tras ALTER TABLE en `documentos`, llamar para que se relea information_schema."""
    global _DOCUMENTOS_COLUMNS
    _DOCUMENTOS_COLUMNS = None


# Parámetros de conexión a MySQL, leídos del entorno (.env). DB_HOST/DB_USER/
# DB_PASSWORD/DB_NAME son obligatorios; DB_PORT por defecto 3306.
# charset utf8mb4 = soporte completo de acentos/emoji; use_pure = driver Python puro.
DB_CONFIG = {
    "host":     os.environ["DB_HOST"],
    "port":     int(os.environ.get("DB_PORT", 3306)),
    "user":     os.environ["DB_USER"],
    "password": os.environ["DB_PASSWORD"],
    "database": os.environ["DB_NAME"],
    "charset":  "utf8mb4",
    "use_pure": True,
}


def get_connection():
    """Abre y devuelve una nueva conexión a MySQL usando DB_CONFIG (variables DB_*)."""
    return mysql.connector.connect(**DB_CONFIG)


# ── API keys cifradas (tabla api_keys) ────────────────────────
# Las claves de los motores de IA se guardan CIFRADAS (Fernet) en la tabla
# `api_keys` en lugar del archivo .env. app.py las lee al arrancar con
# get_api_key(); si la tabla no existe o está vacía, usa el .env como respaldo.

def get_api_key(nombre: str) -> str | None:
    """
    Lee y DESCIFRA una API key guardada en la tabla `api_keys`.

    nombre: identificador de la clave (p. ej. 'GEMINI_API_KEY').
    Devuelve la clave en claro, o None si no existe o si hay cualquier error
    (BD caída, tabla inexistente...). Nunca lanza excepción: el llamador decide
    el respaldo (variable de entorno).
    """
    try:
        conn = get_connection()
    except Exception as e:
        logger.warning("get_api_key(%s): sin conexión a BD (%s)", nombre, e)
        return None
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT valor_cifrado FROM api_keys WHERE nombre = %s LIMIT 1",
            (nombre,),
        )
        row = cur.fetchone()
        if not row or not row.get("valor_cifrado"):
            return None
        return crypto.descifrar_texto(row["valor_cifrado"])
    except Exception as e:
        logger.warning("Error leyendo API key %s: %s", nombre, e)
        return None
    finally:
        conn.close()


def guardar_api_key(nombre: str, valor: str) -> bool:
    """
    Cifra y guarda (o actualiza) una API key en la tabla `api_keys`.

    Útil para rotar claves sin tocar el .env:
        python -c "import database; database.guardar_api_key('GEMINI_API_KEY', 'nueva-clave')"
    """
    conn = get_connection()
    try:
        token = crypto.cifrar_texto(valor)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO api_keys (nombre, valor_cifrado) VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE valor_cifrado = VALUES(valor_cifrado)
            """,
            (nombre, token),
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error("Error guardando API key %s: %s", nombre, e)
        return False
    finally:
        conn.close()


def listar_api_keys() -> list:
    """
    Lista las API keys guardadas SIN descifrar los valores (para el panel /admin/apis).

    Devuelve [{nombre, actualizado}]. El valor cifrado nunca sale hacia la UI.
    """
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT nombre, actualizado FROM api_keys ORDER BY nombre")
        rows = cur.fetchall()
        for r in rows:
            if r.get("actualizado"):
                r["actualizado"] = r["actualizado"].strftime("%d/%m/%Y %H:%M")
        return rows
    except Exception as e:
        logger.warning("Error listando API keys: %s", e)
        return []
    finally:
        conn.close()


def eliminar_api_key(nombre: str) -> bool:
    """Borra una API key de la tabla. La app volverá al respaldo del .env (si existe)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM api_keys WHERE nombre = %s", (nombre,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error eliminando API key %s: %s", nombre, e)
        return False
    finally:
        conn.close()


# ── Proveedores de IA (tabla proveedores_ia) ──────────────────
# Cada proveedor define cómo conectarse (tipo gemini u openai_compatible +
# base_url) y qué API key usa. Gestionables desde /admin/apis.

def listar_proveedores() -> list:
    """Devuelve los proveedores de API como lista de dicts (orden de creación)."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, clave, etiqueta, tipo, base_url, api_key_nombre
            FROM proveedores_ia ORDER BY id
            """
        )
        return cur.fetchall()
    except Exception as e:
        logger.warning("Error listando proveedores IA: %s", e)
        return []
    finally:
        conn.close()


def guardar_proveedor(datos: dict) -> tuple[bool, str]:
    """Crea un proveedor de API nuevo. Devuelve (ok, mensaje_error)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO proveedores_ia (clave, etiqueta, tipo, base_url, api_key_nombre)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (datos["clave"], datos["etiqueta"], datos["tipo"],
             datos["base_url"], datos["api_key_nombre"]),
        )
        conn.commit()
        return True, ""
    except mysql.connector.errors.IntegrityError:
        return False, f"Ya existe un proveedor con la clave '{datos.get('clave')}'."
    except Exception as e:
        logger.error("Error guardando proveedor IA: %s", e)
        return False, str(e)
    finally:
        conn.close()


def actualizar_proveedor(proveedor_id: int, etiqueta: str, base_url: str) -> bool:
    """Actualiza nombre y URL base de un proveedor (la clave y su api_key_nombre no cambian)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE proveedores_ia SET etiqueta = %s, base_url = %s WHERE id = %s",
            (etiqueta, base_url, proveedor_id),
        )
        conn.commit()
        return cur.rowcount >= 0
    except Exception as e:
        logger.error("Error actualizando proveedor %s: %s", proveedor_id, e)
        return False
    finally:
        conn.close()


def eliminar_proveedor(proveedor_id: int) -> bool:
    """Borra un proveedor por id (app.py valida antes que ningún motor lo use)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM proveedores_ia WHERE id = %s", (proveedor_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error eliminando proveedor IA %s: %s", proveedor_id, e)
        return False
    finally:
        conn.close()


# ── Motores de IA (tabla motores_ia) ──────────────────────────
# Cada fila es un motor/botón seleccionable en la app. Se gestionan
# desde /admin/apis. app.py los lee con listar_motores() en cada request.

def listar_motores(solo_activos: bool = True) -> list:
    """
    Devuelve los motores de IA como lista de dicts (en el orden de creación).

    solo_activos=True  -> únicamente los visibles en la app (botones).
    solo_activos=False -> todos, para el panel de administración.
    """
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        where = "WHERE activo = 1" if solo_activos else ""
        cur.execute(
            f"""
            SELECT id, clave, etiqueta, chip, descripcion, proveedor,
                   model_id, max_tokens, activo
            FROM motores_ia {where}
            ORDER BY id
            """
        )
        return cur.fetchall()
    except Exception as e:
        logger.warning("Error listando motores IA: %s", e)
        return []
    finally:
        conn.close()


def guardar_motor(datos: dict) -> tuple[bool, str]:
    """
    Crea o actualiza un motor de IA. Si datos trae 'id', actualiza; si no, inserta.

    Devuelve (ok, mensaje_error). La validación de formato la hace app.py;
    aquí solo se controla la unicidad de la clave.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        if datos.get("id"):
            cur.execute(
                """
                UPDATE motores_ia
                SET clave=%s, etiqueta=%s, chip=%s, descripcion=%s,
                    proveedor=%s, model_id=%s, max_tokens=%s, activo=%s
                WHERE id=%s
                """,
                (datos["clave"], datos["etiqueta"], datos["chip"], datos["descripcion"],
                 datos["proveedor"], datos["model_id"], datos["max_tokens"], datos["activo"],
                 datos["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO motores_ia
                  (clave, etiqueta, chip, descripcion, proveedor, model_id, max_tokens, activo)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (datos["clave"], datos["etiqueta"], datos["chip"], datos["descripcion"],
                 datos["proveedor"], datos["model_id"], datos["max_tokens"], datos["activo"]),
            )
        conn.commit()
        return True, ""
    except mysql.connector.errors.IntegrityError:
        return False, f"Ya existe un motor con la clave '{datos.get('clave')}'."
    except Exception as e:
        logger.error("Error guardando motor IA: %s", e)
        return False, str(e)
    finally:
        conn.close()


def eliminar_motor(motor_id: int) -> bool:
    """Borra un motor de IA por id (el botón desaparece de la app)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM motores_ia WHERE id = %s", (motor_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error eliminando motor IA %s: %s", motor_id, e)
        return False
    finally:
        conn.close()


# ── Documentos ────────────────────────────────────────────────

def guardar_documento(modelo: str,
                      archivo_contrato: str, archivo_poliza: str,
                      datos: dict, resultado: str,
                      bytes_contrato: bytes = None,
                      bytes_poliza: bytes = None,
                      num_polizas: int = 1) -> int | None:
    """
    Guarda un análisis en la tabla `documentos` y devuelve su id (o None si falla).

    Cifra el JSON de datos y los archivos antes de guardarlos. Si el almacenamiento
    en filesystem está activo (doc_storage) y existen las columnas storage_path_*,
    escribe los archivos cifrados en disco y guarda solo la ruta; si no, guarda los
    blobs cifrados dentro de MySQL. Todo dentro de una transacción: si algo falla,
    revierte y borra los archivos que hubiera escrito en disco.
    """
    conn = None
    doc_id = None
    written_fs = False
    try:
        datos_json_cifrado = crypto.cifrar_texto(json.dumps(datos, ensure_ascii=False))
        contrato_cifrado = crypto.cifrar_bytes(bytes_contrato)
        poliza_cifrada = crypto.cifrar_bytes(bytes_poliza)

        cols = _columnas_tabla_documentos()
        np = max(1, int(num_polizas or 1))
        if np > 1 and "num_polizas" not in cols:
            logger.warning(
                "Se guardan %s pólizas pero falta la columna documentos.num_polizas; "
                "el listado histórico puede no mostrar todas las descargas. "
                "Ejecute: ALTER TABLE documentos ADD COLUMN num_polizas INT NOT NULL DEFAULT 1;",
                np,
            )

        use_fs = (
            doc_storage.enabled()
            and "storage_path_contrato" in cols
            and "storage_path_poliza" in cols
        )
        if doc_storage.enabled() and not use_fs:
            logger.warning(
                "DOCUMENT_STORAGE_ROOT está definido pero faltan columnas "
                "storage_path_contrato / storage_path_poliza; "
                "se siguen guardando los archivos dentro de MySQL."
            )

        blob_c = None if use_fs else contrato_cifrado
        blob_p = None if use_fs else poliza_cifrada

        conn = get_connection()
        conn.autocommit = False
        cur = conn.cursor()
        tiene_uc = "usuario_cedula" in cols

        if not tiene_uc:
            if "num_polizas" in cols:
                cur.execute(
                    """
                    INSERT INTO documentos
                      (modelo, archivo_contrato, archivo_poliza, num_polizas,
                       num_contrato, contratista, nit_contratista, tipo_contrato,
                       valor_sin_iva, valor_total, resultado, datos_json,
                       contenido_contrato, contenido_poliza)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        modelo,
                        archivo_contrato,
                        archivo_poliza,
                        np,
                        datos.get("numero_contrato", ""),
                        datos.get("contratista", ""),
                        datos.get("nit_contratista", ""),
                        datos.get("tipo", ""),
                        float(datos.get("valor_sin_iva", 0) or 0),
                        float(datos.get("valor_total", 0) or 0),
                        resultado,
                        datos_json_cifrado,
                        blob_c,
                        blob_p,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO documentos
                      (modelo, archivo_contrato, archivo_poliza,
                       num_contrato, contratista, nit_contratista, tipo_contrato,
                       valor_sin_iva, valor_total, resultado, datos_json,
                       contenido_contrato, contenido_poliza)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        modelo,
                        archivo_contrato,
                        archivo_poliza,
                        datos.get("numero_contrato", ""),
                        datos.get("contratista", ""),
                        datos.get("nit_contratista", ""),
                        datos.get("tipo", ""),
                        float(datos.get("valor_sin_iva", 0) or 0),
                        float(datos.get("valor_total", 0) or 0),
                        resultado,
                        datos_json_cifrado,
                        blob_c,
                        blob_p,
                    ),
                )
        else:
            valor_uc = (os.environ.get("APP_DOC_USER_CEDULA") or "").strip() or ""
            if "num_polizas" in cols:
                cur.execute(
                    """
                    INSERT INTO documentos
                      (usuario_cedula, modelo, archivo_contrato, archivo_poliza, num_polizas,
                       num_contrato, contratista, nit_contratista, tipo_contrato,
                       valor_sin_iva, valor_total, resultado, datos_json,
                       contenido_contrato, contenido_poliza)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        valor_uc if valor_uc else None,
                        modelo,
                        archivo_contrato,
                        archivo_poliza,
                        np,
                        datos.get("numero_contrato", ""),
                        datos.get("contratista", ""),
                        datos.get("nit_contratista", ""),
                        datos.get("tipo", ""),
                        float(datos.get("valor_sin_iva", 0) or 0),
                        float(datos.get("valor_total", 0) or 0),
                        resultado,
                        datos_json_cifrado,
                        blob_c,
                        blob_p,
                    ),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO documentos
                      (usuario_cedula, modelo, archivo_contrato, archivo_poliza,
                       num_contrato, contratista, nit_contratista, tipo_contrato,
                       valor_sin_iva, valor_total, resultado, datos_json,
                       contenido_contrato, contenido_poliza)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        valor_uc if valor_uc else None,
                        modelo,
                        archivo_contrato,
                        archivo_poliza,
                        datos.get("numero_contrato", ""),
                        datos.get("contratista", ""),
                        datos.get("nit_contratista", ""),
                        datos.get("tipo", ""),
                        float(datos.get("valor_sin_iva", 0) or 0),
                        float(datos.get("valor_total", 0) or 0),
                        resultado,
                        datos_json_cifrado,
                        blob_c,
                        blob_p,
                    ),
                )

        doc_id = cur.lastrowid
        if use_fs:
            rel_c, rel_p = doc_storage.write_pair(doc_id, contrato_cifrado, poliza_cifrada)
            written_fs = True
            cur.execute(
                """
                UPDATE documentos
                SET storage_path_contrato = %s, storage_path_poliza = %s
                WHERE id = %s
                """,
                (rel_c, rel_p, doc_id),
            )
        conn.commit()
        return doc_id
    except Exception as e:
        if conn is not None:
            conn.rollback()
        if doc_id is not None and written_fs:
            doc_storage.delete_document_dir(doc_id)
        logger.error("Error guardando documento: %s", e)
        return None
    finally:
        if conn is not None:
            conn.close()


def get_archivo_documento(doc_id: int, tipo: str):
    """
    Devuelve {nombre, contenido} del archivo ('contrato' o 'poliza') de un documento.

    El contenido se devuelve YA DESCIFRADO. Lo lee del filesystem si hay
    storage_path_*; si no, del BLOB guardado en MySQL. contenido = None si no existe.
    """
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cols_set = _columnas_tabla_documentos()
        col = "contenido_contrato" if tipo == "contrato" else "contenido_poliza"
        nom = "archivo_contrato" if tipo == "contrato" else "archivo_poliza"
        sp_col = (
            "storage_path_contrato"
            if tipo == "contrato"
            else "storage_path_poliza"
        )

        selects = [
            f"{col} AS contenido_blob",
            f"{nom} AS nombre",
        ]
        if "storage_path_contrato" in cols_set:
            selects.append("storage_path_contrato")
            selects.append("storage_path_poliza")
        cur.execute(
            f"SELECT {', '.join(selects)} FROM documentos WHERE id = %s",
            (doc_id,),
        )
        row = cur.fetchone()
        if not row:
            return None

        spath = row.get(sp_col) if sp_col in cols_set else None
        token = None
        if spath and doc_storage.enabled():
            token = doc_storage.read_ciphertext(spath)
        if token is None and row.get("contenido_blob") is not None:
            token = row["contenido_blob"]

        out = {"nombre": row.get("nombre")}
        if token is not None:
            out["contenido"] = crypto.descifrar_bytes(token)
        else:
            out["contenido"] = None
        return out
    finally:
        conn.close()


def get_documento_json(doc_id: int):
    """Devuelve la fila de un documento con su datos_json DESCIFRADO (para regenerar Excel o recalcular)."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT datos_json, archivo_contrato, archivo_poliza, modelo, resultado, "
            "num_polizas FROM documentos WHERE id = %s",
            (doc_id,),
        )
        row = cur.fetchone()
        if row and row.get("datos_json"):
            row["datos_json"] = crypto.descifrar_texto(row["datos_json"])
        return row
    finally:
        conn.close()


def actualizar_documento_datos(doc_id: int, datos: dict, resultado: str) -> bool:
    """Actualiza el JSON de datos (re-cifrado) y el resultado de un documento; usado tras un recálculo manual de fechas."""
    conn = get_connection()
    try:
        datos_json_cifrado = crypto.cifrar_texto(json.dumps(datos, ensure_ascii=False))
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE documentos
            SET datos_json = %s, resultado = %s
            WHERE id = %s
            """,
            (datos_json_cifrado, resultado, doc_id),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error actualizando documento %s: %s", doc_id, e)
        return False
    finally:
        conn.close()


def _partes_sel_historico() -> list[str]:
    """Arma la lista de columnas del SELECT del histórico, incluyendo las opcionales que existan (usuario_cedula, num_polizas)."""
    cols = _columnas_tabla_documentos()
    sel = [
        "id",
        "fecha",
        "modelo",
        "archivo_contrato",
        "archivo_poliza",
        "num_contrato",
        "contratista",
        "nit_contratista",
        "tipo_contrato",
        "valor_sin_iva",
        "valor_total",
        "resultado",
    ]
    if "usuario_cedula" in cols:
        sel.insert(2, "usuario_cedula")
    if "num_polizas" in cols:
        i = sel.index("archivo_poliza") + 1
        sel.insert(i, "num_polizas")
    return sel


# ── Manual de Contratación ────────────────────────────────────

def guardar_manual(nombre_archivo: str, contenido_texto: str, subido_por: str = "") -> int | None:
    """Inserta una nueva versión del Manual de Contratación (con su texto extraído). Devuelve su id o None."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO manual_contratacion (nombre_archivo, contenido_texto, subido_por)
            VALUES (%s, %s, %s)
            """,
            (nombre_archivo, contenido_texto, subido_por),
        )
        conn.commit()
        return cur.lastrowid
    except Exception as e:
        logger.error("Error guardando manual: %s", e)
        return None
    finally:
        conn.close()


def actualizar_parametros_manual(manual_id: int, parametros_json: str) -> bool:
    """Guarda el JSON de parámetros (tipos de contrato, %, vigencias) extraído de un manual."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE manual_contratacion SET parametros_json = %s WHERE id = %s",
            (parametros_json, manual_id),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error actualizando parámetros de manual %s: %s", manual_id, e)
        return False
    finally:
        conn.close()


def activar_manual(manual_id: int) -> bool:
    """Marca un manual como el vigente (activo=1) y desactiva los demás; sus parámetros pasan a regir la validación."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE manual_contratacion SET activo = 0 WHERE activo = 1")
        cur.execute("UPDATE manual_contratacion SET activo = 1 WHERE id = %s", (manual_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error("Error activando manual %s: %s", manual_id, e)
        return False
    finally:
        conn.close()


def get_manual_activo() -> dict | None:
    """Devuelve el manual activo (id, nombre, parametros_json, fecha...) o None si no hay ninguno."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, nombre_archivo, parametros_json, fecha_subida, subido_por
            FROM manual_contratacion WHERE activo = 1 LIMIT 1
            """
        )
        row = cur.fetchone()
        if row and row.get("fecha_subida"):
            row["fecha_subida"] = row["fecha_subida"].strftime("%d/%m/%Y %H:%M")
        return row
    except Exception as e:
        logger.warning("Error leyendo manual activo: %s", e)
        return None
    finally:
        conn.close()


def listar_manuales(limit: int = 20) -> list:
    """Lista los manuales subidos (más recientes primero) con un flag de si ya tienen parámetros extraídos."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, nombre_archivo, activo, fecha_subida, subido_por,
                   CASE WHEN parametros_json IS NOT NULL AND parametros_json != ''
                        THEN 1 ELSE 0 END AS tiene_params
            FROM manual_contratacion
            ORDER BY fecha_subida DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        for row in rows:
            if row.get("fecha_subida"):
                row["fecha_subida"] = row["fecha_subida"].strftime("%d/%m/%Y %H:%M")
        return rows
    except Exception as e:
        logger.warning("Error listando manuales: %s", e)
        return []
    finally:
        conn.close()


def get_manual_texto(manual_id: int) -> str | None:
    """Devuelve el texto completo extraído de un manual (para reenviarlo a la IA y extraer parámetros)."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT contenido_texto FROM manual_contratacion WHERE id = %s",
            (manual_id,),
        )
        row = cur.fetchone()
        return row["contenido_texto"] if row else None
    except Exception as e:
        logger.warning("Error leyendo texto manual %s: %s", manual_id, e)
        return None
    finally:
        conn.close()


def eliminar_manual(manual_id: int) -> bool:
    """Borra un manual del historial por id. Devuelve True si se borró alguna fila."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM manual_contratacion WHERE id = %s", (manual_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error("Error eliminando manual %s: %s", manual_id, e)
        return False
    finally:
        conn.close()


def get_manual_params(manual_id: int) -> str | None:
    """Devuelve el JSON de parámetros de un manual (para mostrarlo/editarlo en la UI)."""
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT parametros_json FROM manual_contratacion WHERE id = %s",
            (manual_id,),
        )
        row = cur.fetchone()
        return row["parametros_json"] if row else None
    except Exception as e:
        logger.warning("Error leyendo params manual %s: %s", manual_id, e)
        return None
    finally:
        conn.close()


def get_historico(usuario_cedula: str | None = None, limit: int = 100) -> list:
    """
    Devuelve los últimos análisis para la vista de histórico.

    Formatea fechas y valores, y deriva la lista de nombres de pólizas (una o varias).
    El filtro por cédula solo se aplica si la columna usuario_cedula existe en la tabla.
    """
    partes_sel = _partes_sel_historico()
    col_sql = ", ".join(partes_sel)
    cols = _columnas_tabla_documentos()
    uc = (usuario_cedula or "").strip()

    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        if uc and "usuario_cedula" in cols:
            cur.execute(
                f"""
                SELECT {col_sql}
                FROM documentos
                WHERE usuario_cedula = %s
                ORDER BY fecha DESC
                LIMIT %s
                """,
                (uc, limit),
            )
        else:
            if uc and "usuario_cedula" not in cols:
                logger.warning(
                    "get_historico: filtro por cédula ignorado — la tabla ya no tiene la columna usuario_cedula."
                )
            cur.execute(
                f"""
                SELECT {col_sql}
                FROM documentos
                ORDER BY fecha DESC
                LIMIT %s
                """,
                (limit,),
            )
        rows = cur.fetchall()
        for row in rows:
            if row.get("fecha"):
                row["fecha"] = row["fecha"].strftime("%d/%m/%Y %H:%M")
            row["valor_sin_iva"] = float(row["valor_sin_iva"] or 0)
            row["valor_total"]   = float(row["valor_total"]   or 0)

            n_db = row.get("num_polizas")
            try:
                n_db = int(n_db) if n_db is not None else None
            except (TypeError, ValueError):
                n_db = None

            ap = row.get("archivo_poliza")
            ap = str(ap).strip() if ap is not None else ""
            poliza_nombres = [p.strip() for p in ap.split("|") if p.strip()]

            if n_db and n_db > 1 and len(poliza_nombres) < n_db:
                if not poliza_nombres:
                    poliza_nombres = [f"Póliza {i}" for i in range(1, n_db + 1)]
                else:
                    j = len(poliza_nombres) + 1
                    while len(poliza_nombres) < n_db:
                        poliza_nombres.append(f"Archivo {j}")
                        j += 1

            row["poliza_nombres"] = poliza_nombres
            row["poliza_es_multi"] = len(poliza_nombres) > 1
        return rows
    finally:
        conn.close()
