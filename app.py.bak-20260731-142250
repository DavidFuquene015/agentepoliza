from flask import Flask, request, jsonify, send_file, render_template
from flask_cors import CORS
from datetime import date, datetime, timedelta
from dotenv import load_dotenv
import pdfplumber                                   # extracción de texto de PDF
import docx                                         # extracción de texto de DOCX (python-docx)
import json
import os
import io
import tempfile                                     # archivos temporales (PDF/DOCX/Excel)
from google import genai                            # SDK de Google Gemini/Gemma
import openai as _openai_sdk                         # SDK de OpenAI (también sirve para NVIDIA NIM)
from openpyxl import Workbook                        # creación de libros Excel
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side  # estilos del Excel
import re
import logging
import zipfile                                      # empaqueta varias pólizas en un .zip
import unicodedata                                  # normaliza acentos al comparar claves de amparos
import mimetypes                                    # tipos MIME de los archivos estáticos (ver nota abajo)
import database                                     # módulo propio: acceso a MySQL

load_dotenv()

# ── Tipos MIME correctos en cualquier máquina ─────────────────
# En Windows, Flask consulta el REGISTRO del sistema para saber qué tipo es un
# archivo .js/.css. En algunas máquinas ese registro está dañado y responde
# "text/plain"; como la app envía la cabecera de seguridad X-Content-Type-
# Options: nosniff, el navegador se niega a ejecutar los scripts y la interfaz
# queda muerta (ReferenceError: ... is not defined). Estas dos líneas fijan el
# tipo correcto en el código, sin depender del registro de cada PC.
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")

APP_ACTOR_LABEL = (os.environ.get("APP_ACTOR_LABEL") or "Colvatel-interno").strip() or "Colvatel-interno"

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# ── Sesiones: expiran a las 8 horas de inactividad ───────────
app.config["MAX_CONTENT_LENGTH"]       = 50 * 1024 * 1024  # 50 MB límite global
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# ── CORS configurable por entorno ────────────────────────────
_allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
if _allowed_origins == "*":
    CORS(app, supports_credentials=True)
else:
    CORS(app, origins=_allowed_origins.split(","), supports_credentials=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# ── API interna: clave compartida (integración ColvaContratos) ──
# Si INTERNAL_API_KEY está definida, los endpoints del agente exigen la cabecera
# HTTP  X-Internal-Key  con ese mismo valor. Así el motor solo atiende llamadas
# de ColvaContratos (que la envía por su proxy) y nadie más. Sin la variable, no
# cambia nada: la app funciona igual (útil en desarrollo o para su propia UI).
INTERNAL_API_KEY = (os.environ.get("INTERNAL_API_KEY") or "").strip()
# Rutas que solo debe poder invocar ColvaContratos (todas las de acción/datos).
_RUTAS_API_PROTEGIDAS = ("/api/", "/admin/")


@app.before_request
def _exigir_api_key_interna():
    """Si INTERNAL_API_KEY está configurada, exige la cabecera X-Internal-Key en las rutas protegidas."""
    if not INTERNAL_API_KEY:
        return None
    path = request.path or ""
    if any(path.startswith(p) for p in _RUTAS_API_PROTEGIDAS):
        if request.headers.get("X-Internal-Key", "") != INTERNAL_API_KEY:
            return jsonify({"error": "No autorizado (falta o no coincide la cabecera X-Internal-Key)."}), 401
    return None


# ── Headers de seguridad HTTP ─────────────────────────────────
@app.after_request
def set_security_headers(response):
    """Añade cabeceras de seguridad HTTP a TODAS las respuestas (anti-clickjacking, anti MIME-sniffing, etc.)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    return response


# ── Validación de archivos subidos ───────────────────────────
EXTENSIONES_PERMITIDAS = {"pdf", "docx", "doc"}
MAX_ARCHIVO_BYTES      = 20 * 1024 * 1024  # 20 MB


def _validar_archivo(f) -> tuple[bool, str]:
    """Valida un archivo subido: extensión permitida (PDF/DOCX/DOC) y tamaño ≤ 20 MB. Devuelve (ok, mensaje_error)."""
    nombre = (f.filename or "").lower()
    ext = nombre.rsplit(".", 1)[-1] if "." in nombre else ""
    if ext not in EXTENSIONES_PERMITIDAS:
        return False, f"Tipo de archivo no permitido (.{ext}). Solo se aceptan PDF y DOCX."
    contenido = f.read()
    f.seek(0)
    if len(contenido) > MAX_ARCHIVO_BYTES:
        return False, "El archivo supera el límite de 20 MB."
    return True, ""


def _empaquetar_polizas_almacenamiento(polizas: list[tuple[bytes, str]]) -> tuple[bytes, str]:
    """Si hay una sola póliza, devuelve sus bytes y el nombre; si hay varias, un ZIP y nombres unidos con |."""
    if not polizas:
        raise ValueError("Sin archivos de póliza")
    nombres = [fn or f"poliza_{i + 1}.pdf" for i, (_, fn) in enumerate(polizas)]
    etiqueta = "|".join(nombres)
    if len(polizas) == 1:
        return polizas[0][0], etiqueta
    buf = io.BytesIO()
    usados = set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, ((data, _), fname) in enumerate(zip(polizas, nombres)):
            arcname = fname
            base, suf = (fname.rsplit(".", 1)[0], fname.rsplit(".", 1)[-1]) if "." in fname else (fname, "")
            n = 1
            while arcname in usados:
                arcname = f"{base}_{n}.{suf}" if suf else f"{base}_{n}"
                n += 1
            usados.add(arcname)
            zf.writestr(arcname, data)
    return buf.getvalue(), etiqueta


def _construir_texto_polizas(
    polizas: list[tuple[bytes, str]],
    extraer,
    max_chars: int | None,
) -> str:
    """Extrae y concatena el texto de todas las pólizas en un bloque, con encabezados separadores; trunca al tope max_chars si aplica."""
    partes = []
    for i, (content, fname) in enumerate(polizas, 1):
        t = extraer(content, fname)
        partes.append(
            f"===== DOCUMENTO DE PÓLIZA {i} DE {len(polizas)} — {fname} =====\n{t}"
        )
    full = "\n\n".join(partes)
    if max_chars is not None and max_chars > 0 and len(full) > max_chars:
        logger.warning(
            "Texto combinado de pólizas truncado de %s a %s caracteres (MAX_CHARS_POLIZAS_IA)",
            len(full),
            max_chars,
        )
        full = full[:max_chars]
    return full


def _es_zip_bytes(data: bytes) -> bool:
    """True si los bytes parecen un ZIP (empiezan por 'PK'); se usa para pólizas múltiples empaquetadas."""
    return bool(data) and len(data) >= 4 and data[:2] == b"PK"


# ── API Keys ──────────────────────────────────────────────────
# Las claves de IA viven CIFRADAS en la tabla `api_keys` de MySQL (ver
# database.get_api_key y sql/000_esquema_completo.sql) y se gestionan desde
# el panel /admin/apis. Se leen EN CADA USO (no al arrancar): así, al cambiar
# una clave desde el panel, aplica de inmediato sin reiniciar la app.
# Si la BD no está disponible o la clave no existe en la tabla, se usa la
# variable de entorno del .env como RESPALDO.
def _api_key(nombre: str) -> str:
    """Obtiene una API key: primero de la BD (descifrada); si no, del entorno (.env)."""
    valor = database.get_api_key(nombre)
    if valor:
        return valor
    return os.environ.get(nombre, "")


# ── Proveedores de API (tabla proveedores_ia, gestionados en /admin/apis) ──
# Cada proveedor define: tipo ('gemini' usa el SDK google-genai; cualquier otro
# usa el SDK openai como API "compatible con OpenAI"), base_url (vacío = API
# oficial de OpenAI) y el nombre de su API key en la tabla api_keys.
# El usuario puede AÑADIR proveedores nuevos desde el panel (Groq, Mistral,
# OpenRouter, DeepSeek oficial, un servidor local, etc.).
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

_PROVEEDORES_FALLBACK = {
    "gemini": {"clave": "gemini", "etiqueta": "Google Gemini", "tipo": "gemini",
               "base_url": "", "api_key_nombre": "GEMINI_API_KEY"},
    "openai": {"clave": "openai", "etiqueta": "OpenAI", "tipo": "openai_compatible",
               "base_url": "", "api_key_nombre": "OPENAI_API_KEY"},
    "nvidia": {"clave": "nvidia", "etiqueta": "NVIDIA NIM", "tipo": "openai_compatible",
               "base_url": NVIDIA_BASE_URL, "api_key_nombre": "NVIDIA_API_KEY"},
}


def get_proveedores() -> dict:
    """
    Proveedores de API como dict {clave: cfg}, leídos de la BD en cada llamada
    (los cambios del panel aplican al instante). Fallback estático si la tabla
    no existe o está vacía.
    """
    try:
        rows = database.listar_proveedores()
        if rows:
            return {r["clave"]: r for r in rows}
    except Exception as e:
        logger.warning("No se pudieron leer proveedores de la BD: %s — usando fallback", e)
    return _PROVEEDORES_FALLBACK


def _key_de_proveedor(proveedor: str) -> str:
    """API key (descifrada) del proveedor indicado ('' si no está configurada)."""
    prov = get_proveedores().get(proveedor)
    if not prov:
        return ""
    return _api_key(prov["api_key_nombre"])


def _cliente_openai_compat(prov_cfg: dict):
    """
    Cliente del SDK openai para un proveedor 'openai_compatible'.

    Si el proveedor tiene base_url usa ese endpoint (NVIDIA, Groq, etc.);
    si está vacío, la API oficial de OpenAI. Lanza ValueError sin API key.
    """
    api_key = _api_key(prov_cfg["api_key_nombre"])
    if not api_key:
        raise ValueError(
            f"La API key del proveedor '{prov_cfg['clave']}' no está configurada "
            f"({prov_cfg['api_key_nombre']} — panel /admin/apis)."
        )
    # timeout / max_retries: sin esto el SDK espera indefinidamente y reintenta
    # 2 veces más, así que un proveedor lento (p. ej. NVIDIA devolviendo 504 a
    # los 5 min) tardaba ~15 minutos en fallar. Con estos topes el error llega
    # rápido y el usuario puede cambiar de motor.
    timeout_s = float(os.environ.get("IA_TIMEOUT_SEGUNDOS", "150"))
    reintentos = int(os.environ.get("IA_MAX_REINTENTOS", "1"))
    base_url = (prov_cfg.get("base_url") or "").strip()
    if base_url:
        return _openai_sdk.OpenAI(base_url=base_url, api_key=api_key,
                                  timeout=timeout_s, max_retries=reintentos)
    return _openai_sdk.OpenAI(api_key=api_key,
                              timeout=timeout_s, max_retries=reintentos)


# ── Motores de IA (tabla motores_ia, gestionados en /admin/apis) ──
# Cada motor: {clave, etiqueta, chip, descripcion, proveedor, model_id, max_tokens}.
# _MOTORES_FALLBACK se usa solo si la tabla no existe o está vacía (p. ej.
# primer arranque sin migrar la BD): son los mismos 6 motores originales.
_MOTORES_FALLBACK = {
    "gemini":   {"clave": "gemini",   "etiqueta": "Gemini",   "chip": "Gemma 4",  "descripcion": "Google Gemini.",
                 "proveedor": "gemini", "model_id": os.environ.get("GEMINI_MODEL", "gemma-4-31b-it"),
                 "max_tokens": min(int(os.environ.get("GEMINI_MAX_OUTPUT_TOKENS", "8192")), 65536)},
    "openai":   {"clave": "openai",   "etiqueta": "ChatGPT",  "chip": "GPT",      "descripcion": "OpenAI ChatGPT.",
                 "proveedor": "openai", "model_id": os.environ.get("OPENAI_MODEL", "gpt-4o"),
                 "max_tokens": min(int(os.environ.get("OPENAI_MAX_OUTPUT_TOKENS", "4096")), 16384)},
    "deepseek": {"clave": "deepseek", "etiqueta": "DeepSeek", "chip": "V4 Pro",   "descripcion": "Vía NVIDIA NIM.",
                 "proveedor": "nvidia", "model_id": os.environ.get("DEEPSEEK_MODEL", "deepseek-ai/deepseek-v4-pro"),
                 "max_tokens": min(int(os.environ.get("DEEPSEEK_MAX_OUTPUT_TOKENS", "4096")), 16384)},
    "qwen":     {"clave": "qwen",     "etiqueta": "Qwen",     "chip": "3.5 397B", "descripcion": "Vía NVIDIA NIM.",
                 "proveedor": "nvidia", "model_id": os.environ.get("QWEN_MODEL", "qwen/qwen3.5-397b-a17b"),
                 "max_tokens": min(int(os.environ.get("QWEN_MAX_OUTPUT_TOKENS", "4096")), 16384)},
    "minimax":  {"clave": "minimax",  "etiqueta": "MiniMax",  "chip": "M3",       "descripcion": "Vía NVIDIA NIM.",
                 "proveedor": "nvidia", "model_id": os.environ.get("MINIMAX_MODEL", "minimaxai/minimax-m3"),
                 "max_tokens": min(int(os.environ.get("MINIMAX_MAX_OUTPUT_TOKENS", "4096")), 16384)},
    "glm":      {"clave": "glm",      "etiqueta": "GLM",      "chip": "5.1",      "descripcion": "Vía NVIDIA NIM.",
                 "proveedor": "nvidia", "model_id": os.environ.get("GLM_MODEL", "z-ai/glm-5.1"),
                 "max_tokens": min(int(os.environ.get("GLM_MAX_OUTPUT_TOKENS", "4096")), 16384)},
}


def get_motores() -> dict:
    """
    Motores de IA ACTIVOS como dict {clave: cfg}, leídos de la BD en cada llamada.

    Leerlos siempre frescos hace que los cambios del panel /admin/apis
    (añadir/editar/borrar motores) apliquen de inmediato sin reiniciar.
    Si la tabla no existe o está vacía, devuelve el fallback estático.
    """
    try:
        rows = database.listar_motores(solo_activos=True)
        if rows:
            return {r["clave"]: r for r in rows}
    except Exception as e:
        logger.warning("No se pudieron leer motores de la BD: %s — usando fallback", e)
    return _MOTORES_FALLBACK


def _normalizar_modelo(modelo_raw: str, motores: dict) -> str:
    """Normaliza el motor pedido por el front (minúsculas + mapeo del valor legado 'groq')."""
    m = (modelo_raw or "gemini").strip().lower()
    if m == "groq" and "groq" not in motores:
        # Valor legado de versiones antiguas del front → primer motor utilizable.
        return _resolver_modelo_ia_aux(None) or "gemini"
    return m


def _opcional_limite_entero_positive(env_key: str) -> int | None:
    """Variable vacía, ''0'' o valor inválido → sin límite (None)."""
    raw = (os.environ.get(env_key) or "").strip()
    if not raw or raw == "0":
        return None
    try:
        n = int(raw)
        return n if n > 0 else None
    except ValueError:
        return None


def _aplicar_tope_opcional_texto(texto: str, env_key: str) -> str:
    """Trunca el texto al límite definido por la variable env_key (o lo deja intacto si no hay límite)."""
    lim = _opcional_limite_entero_positive(env_key)
    if lim is None or len(texto) <= lim:
        return texto
    logger.warning("Texto truncado por %s: %s → %s caracteres", env_key, len(texto), lim)
    return texto[:lim]


def _resolver_modelo_ia_aux(modelo_solicitado: str | None) -> str | None:
    """
    Devuelve un motor UTILIZABLE (con API key configurada) para tareas auxiliares
    (p. ej. explicaciones de incumplimientos tras un recálculo).

    Prefiere el motor solicitado si su proveedor tiene clave; si no, el primer
    motor activo cuyo proveedor tenga clave. None si ninguno es utilizable.
    """
    motores = get_motores()
    m = (modelo_solicitado or "").strip().lower()
    # Mantener el motor pedido si su proveedor tiene API key disponible.
    if m in motores and _key_de_proveedor(motores[m]["proveedor"]):
        return m
    # Fallback: primer motor activo con API key configurada.
    for clave, cfg in motores.items():
        if _key_de_proveedor(cfg["proveedor"]):
            return clave
    return None

# ── Configuración de tipos de contrato (Anexo 1 Manual Colvatel) ──
TIPOS_CONTRATO = {
    "servicios": {
        "nombre": "Prestación de servicios",
        "amparos": ["cumplimiento", "salarios", "calidad", "rce"],
        "pct": {"cumplimiento": 20, "salarios": 5, "calidad": 20, "rce": 20},
        "ext_meses": {"cumplimiento": 4, "salarios": 36, "calidad": 4, "rce": 4}
    },
    "suministro": {
        "nombre": "Suministro",
        "amparos": ["cumplimiento", "calidad_bienes"],
        "pct": {"cumplimiento": 20, "calidad_bienes": 20},
        "ext_meses": {"cumplimiento": 4, "calidad_bienes": 4}
    },
    "consultoria": {
        "nombre": "Consultoría",
        "amparos": ["cumplimiento", "salarios", "calidad", "rce"],
        "pct": {"cumplimiento": 20, "salarios": 5, "calidad": 20, "rce": 20},
        "ext_meses": {"cumplimiento": 4, "salarios": 36, "calidad": 4, "rce": 4}
    },
    "obra": {
        "nombre": "Ejecución de obra / concesión",
        "amparos": ["cumplimiento", "salarios", "calidad", "estabilidad", "rce"],
        "pct": {"cumplimiento": 20, "salarios": 5, "calidad": 20, "estabilidad": 20, "rce": 20},
        "ext_meses": {"cumplimiento": 4, "salarios": 36, "calidad": 4, "estabilidad": 60, "rce": 4}
    },
    "otros": {
        "nombre": "Otros contratos",
        "amparos": ["cumplimiento", "salarios", "rce"],
        "pct": {"cumplimiento": 10, "salarios": 5, "rce": 10},
        "ext_meses": {"cumplimiento": 4, "salarios": 36, "rce": 4}
    }
}

AMPARO_LABELS = {
    "cumplimiento": "Cumplimiento",
    "salarios": "Salarios y Prestaciones Sociales",
    "calidad": "Calidad del Servicio",
    "calidad_bienes": "Calidad de Bienes/Equipos",
    "estabilidad": "Estabilidad y Calidad de Obra",
    "rce": "Responsabilidad Civil Extracontractual",
}

# ── Config dinámica desde el Manual ──────────────────────────
# None = no cargado aún; dict = cargado (puede ser el fallback hardcodeado).
_CFG_CACHE: dict | None = None


def _invalidar_cache_manual():
    """Borra la cache de configuración del manual para forzar su recarga desde la BD (tras activar otro manual)."""
    global _CFG_CACHE
    _CFG_CACHE = None


def _cargar_cfg_manual() -> dict:
    """Carga la config desde el manual activo en BD o devuelve los valores hardcodeados."""
    global _CFG_CACHE
    if _CFG_CACHE is not None:
        return _CFG_CACHE
    try:
        manual = database.get_manual_activo()
        if manual and manual.get("parametros_json"):
            cfg = json.loads(manual["parametros_json"])
            tipos = cfg.get("tipos_contrato")
            if isinstance(tipos, dict) and tipos:
                _CFG_CACHE = cfg
                logger.info(
                    "Configuración cargada del manual activo (id=%s, archivo=%s)",
                    manual.get("id"), manual.get("nombre_archivo"),
                )
                return _CFG_CACHE
    except Exception as e:
        logger.warning("No se pudo cargar config del manual: %s — usando valores por defecto", e)
    _CFG_CACHE = {"tipos_contrato": TIPOS_CONTRATO, "amparo_labels": AMPARO_LABELS}
    return _CFG_CACHE


def get_tipos_contrato() -> dict:
    """Devuelve el dict de tipos de contrato vigente (del manual activo o los valores por defecto)."""
    return _cargar_cfg_manual().get("tipos_contrato", TIPOS_CONTRATO)


def get_amparo_labels() -> dict:
    """Devuelve las etiquetas legibles de los amparos (del manual activo o las por defecto)."""
    return _cargar_cfg_manual().get("amparo_labels", AMPARO_LABELS)

# Claves que el JSON de la IA debe incluir siempre (evita omisiones si la salida se trunca).
_AMPAROS_JSON_CLAVES = (
    "cumplimiento", "salarios", "calidad", "rce", "calidad_bienes", "estabilidad",
)

# Sinónimos que a veces devuelve el modelo → clave esperada por validar_amparos.
_AMPARO_ALIAS_A_CANONICO = {
    "salario": "salarios",
    "salarios_y_prestaciones_sociales": "salarios",
    "salarios_y_prestaciones": "salarios",
    "prestaciones_sociales": "salarios",
    "spps": "salarios",
    "sueldos": "salarios",
    "nomina": "salarios",
    "nomina_y_prestaciones": "salarios",
    "salarios_prestaciones": "salarios",
    "amparo_salarios": "salarios",
    "riesgos_laborales": "salarios",
    "riesgos_laboral": "salarios",
    "riesgo_laboral": "salarios",
    "cumplimiento_contractual": "cumplimiento",
    "resp_civil": "rce",
    "responsabilidad_civil": "rce",
    "responsabilidad_civil_extracontractual": "rce",
    "rce_extracontractual": "rce",
    "calidad_servicio": "calidad",
    "calidad_del_servicio": "calidad",
    "calidad_bienes_equipos": "calidad_bienes",
    "calidad_de_bienes": "calidad_bienes",
    "estabilidad_obra": "estabilidad",
    "estabilidad_y_calidad_de_obra": "estabilidad",
}


def _clave_amparo_canonica(k) -> str:
    """Normaliza una clave de amparo de la IA a su nombre canónico (p. ej. 'salario' → 'salarios'), quitando acentos y sinónimos."""
    if not isinstance(k, str):
        return k
    kl = k.strip().lower().replace(" ", "_").replace("-", "_")
    kl = "".join(
        ch for ch in unicodedata.normalize("NFD", kl) if unicodedata.category(ch) != "Mn"
    )
    if kl in _AMPARO_ALIAS_A_CANONICO:
        return _AMPARO_ALIAS_A_CANONICO[kl]
    if kl in _AMPAROS_JSON_CLAVES:
        return kl
    return k


def _fusionar_amparos_claves_alias(amparos: dict) -> None:
    """Unifica sinónimos (p. ej. salario → salarios) antes de rellenar claves faltantes con 0."""
    if not isinstance(amparos, dict):
        return
    fusionado: dict = {}
    for k, v in list(amparos.items()):
        ck = _clave_amparo_canonica(k)
        if not isinstance(v, dict):
            v = {"valor": 0, "desde": "", "hasta": ""}
        if ck not in fusionado:
            fusionado[ck] = {"valor": v.get("valor", 0), "desde": v.get("desde", ""), "hasta": v.get("hasta", "")}
            continue
        ex = fusionado[ck]
        va, vb = _a_numero(v.get("valor", 0), 0), _a_numero(ex.get("valor", 0), 0)
        ex["valor"] = max(va, vb)
        ha, hb = _normalizar_fecha(v.get("hasta", "")), _normalizar_fecha(ex.get("hasta", ""))
        ex["hasta"] = ha if ha > hb else hb
        da, db = _normalizar_fecha(v.get("desde", "")), _normalizar_fecha(ex.get("desde", ""))
        if da and (not db or da < db):
            ex["desde"] = da
        elif db and not ex.get("desde"):
            ex["desde"] = db
    amparos.clear()
    amparos.update(fusionado)


def _a_numero(valor, default=0):
    """Convierte a número un valor que puede venir como texto con formato colombiano ('3.464.000'); devuelve default si no puede."""
    if isinstance(valor, (int, float)):
        return valor
    if valor is None:
        return default
    if isinstance(valor, str):
        limpio = valor.strip()
        if not limpio:
            return default
        limpio = re.sub(r"[^0-9,.\-]", "", limpio)
        if "," in limpio and "." in limpio:
            limpio = limpio.replace(".", "").replace(",", ".")
        elif "," in limpio and "." not in limpio:
            limpio = limpio.replace(",", ".")
        try:
            n = float(limpio)
            return int(n) if n.is_integer() else n
        except ValueError:
            logger.warning("No se pudo convertir a número: %r", valor)
            return default
    return default


def _normalizar_fecha(fecha_str) -> str:
    """Convert DD/MM/YYYY, DD-MM-YYYY or YYYY/MM/DD → YYYY-MM-DD for reliable comparison."""
    if not fecha_str:
        return ""
    s = str(fecha_str).strip()
    if not s or s in ("0", "null", "None"):
        return ""
    # Already YYYY-MM-DD
    if re.match(r'^\d{4}-\d{2}-\d{2}$', s):
        return s
    # DD/MM/YYYY  or  D/M/YYYY
    m = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', s)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"
    # DD-MM-YYYY  (day-month-year, not YYYY-MM-DD)
    m = re.match(r'^(\d{1,2})-(\d{1,2})-(\d{4})$', s)
    if m:
        return f"{m.group(3)}-{m.group(2).zfill(2)}-{m.group(1).zfill(2)}"
    # YYYY/MM/DD
    m = re.match(r'^(\d{4})/(\d{2})/(\d{2})$', s)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    logger.warning("Formato de fecha no reconocido: %r — se comparará tal cual", s)
    return s


_RE_LINEA_TERMINACION = re.compile(
    r"(?i)terminaci[oó]n|vencimiento\s+del\s+contrato|plazo\s+de\s+ejecuci[oó]n"
    r"|ejecuci[oó]n\s+del\s+contrato|finaliza(ción)?\s+del\s+contrato"
    r"|fecha\s+de\s+terminaci[oó]n",
)
_RE_FECHA_DMY = re.compile(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})")
_MESES_ES = {
    "enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6,
    "julio": 7, "agosto": 8, "septiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12,
}
_RE_FECHA_ES = re.compile(
    r"(\d{1,2})\s+de\s+(enero|febrero|marzo|abril|mayo|junio|julio|agosto"
    r"|septiembre|octubre|noviembre|diciembre)\s+de\s+(\d{4})",
    re.IGNORECASE,
)


_KW_TERM_RE = re.compile(
    r"(?:terminaci[oó]n(?:\s+del\s+contrato)?|plazo\s+de\s+ejecuci[oó]n"
    r"(?:\s+del\s+contrato)?|fecha\s+de\s+terminaci[oó]n)",
    re.IGNORECASE,
)


def _extraer_fecha_terminacion_desde_texto_contrato(texto: str, ia_fin: str = "") -> str:
    """
    Busca la fecha exacta de terminación del contrato en el texto.
    La IA tiende a redondear al último día del mes; aquí se prefiere la fecha más temprana
    del mismo mes encontrada cerca de palabras clave de terminación/plazo.
    Desactivar: USAR_FECHA_TERMINACION_REGEX=0
    """
    if not texto or len(texto) < 30:
        return ""
    if os.environ.get("USAR_FECHA_TERMINACION_REGEX", "1") != "1":
        return ""
    chunk = texto[:90000]
    tomados: set[str] = set()

    def _registrar(d, m, y):
        """Registra una fecha (día, mes, año) en el conjunto de candidatas si es válida y del rango 2020-2050."""
        try:
            dt = datetime(y, m, d)
            if 2020 <= y <= 2050:
                tomados.add(dt.strftime("%Y-%m-%d"))
        except ValueError:
            pass

    # Paso 1 — línea a línea: recoger fechas en líneas con palabras clave
    for line in chunk.splitlines():
        if not _RE_LINEA_TERMINACION.search(line):
            continue
        ln = line.lower()
        fechas = _RE_FECHA_DMY.findall(line)
        if fechas:
            if "hasta" in ln or (len(fechas) >= 2 and ("desde" in ln or "del" in ln)):
                raw = fechas[-1]
            else:
                raw = fechas[0]
            _registrar(int(raw[0]), int(raw[1]), int(raw[2]))
        for mf in _RE_FECHA_ES.finditer(line):
            mes_num = _MESES_ES.get(mf.group(2).lower(), 0)
            if mes_num:
                _registrar(int(mf.group(1)), mes_num, int(mf.group(3)))

    # Paso 2 — búsqueda multi-línea: SIEMPRE se ejecuta (el contrato puede tener la fecha
    # en la línea siguiente al keyword, p.ej. celda de tabla en PDF)
    for km in _KW_TERM_RE.finditer(chunk):
        ventana = chunk[km.start(): km.start() + 250]
        # Fecha numérica DD/MM/YYYY
        for mf in _RE_FECHA_DMY.finditer(ventana):
            _registrar(int(mf.group(1)), int(mf.group(2)), int(mf.group(3)))
        # Fecha en español "15 de junio de 2026"
        for mf in _RE_FECHA_ES.finditer(ventana):
            mes_num = _MESES_ES.get(mf.group(2).lower(), 0)
            if mes_num:
                _registrar(int(mf.group(1)), mes_num, int(mf.group(3)))

    if not tomados:
        return ""

    uniq = sorted(tomados)
    if len(uniq) == 1:
        return uniq[0]

    # Si hay varias fechas, preferir la más temprana del mismo mes que la IA propone:
    # la IA tiende a usar el último día del mes, el texto contiene el día exacto.
    if ia_fin and len(ia_fin) >= 7:
        ym = ia_fin[:7]
        mismo_mes = [x for x in uniq if x[:7] == ym]
        if mismo_mes:
            return min(mismo_mes)
    if ia_fin and ia_fin in uniq:
        return ia_fin
    return uniq[-1]


def _coercer_amparos_entrada(amparos_raw):
    """La IA a veces devolvía amparos como lista de objetos; antes se reemplazaba por dict vacío y se perdía todo."""
    if isinstance(amparos_raw, dict):
        return amparos_raw
    if not isinstance(amparos_raw, list):
        return {}
    out = {}
    for item in amparos_raw:
        if not isinstance(item, dict):
            continue
        nombre = None
        for k in (
            "amparo", "nombre", "tipo", "cobertura", "clave", "name", "titulo",
            "descripcion", "item", "detalle", "label",
        ):
            v = item.get(k)
            if v and isinstance(v, str) and v.strip():
                nombre = v.strip()
                break
            if isinstance(v, dict) and v.get("es"):
                nombre = str(v.get("es")).strip()
                if nombre:
                    break
        if not nombre:
            continue
        ck = _clave_amparo_canonica(nombre)
        val = item.get(
            "valor",
            item.get("monto", item.get("valor_asegurado", item.get("suma_asegurada", item.get("capital", 0)))),
        )
        desde = item.get("desde", item.get("fecha_inicio", item.get("vigencia_desde", "")))
        hasta = item.get("hasta", item.get("fecha_fin", item.get("vigencia_hasta", "")))
        block = {"valor": val, "desde": desde, "hasta": hasta}
        if ck in out:
            ex = out[ck]
            va, vb = _a_numero(val, 0), _a_numero(ex.get("valor", 0), 0)
            ex["valor"] = max(va, vb)
            ha, hb = _normalizar_fecha(hasta), _normalizar_fecha(ex.get("hasta", ""))
            ex["hasta"] = ha if ha > hb else hb
            da, db = _normalizar_fecha(desde), _normalizar_fecha(ex.get("desde", ""))
            if da and (not db or da < db):
                ex["desde"] = da
        else:
            out[ck] = block
    if out:
        logger.info(
            "amparos recibidos como lista (%s ítems) → dict con %s claves",
            len(amparos_raw),
            len(out),
        )
    elif amparos_raw:
        logger.warning("amparos era lista pero no se reconoció ningún ítem: %s", amparos_raw[:500] if len(str(amparos_raw)) > 500 else amparos_raw)
    return out


def _extraer_montos_candidatos_cop(fragmento: str) -> list[int]:
    """Enteros COP típicos: miles con punto (3.464.000) o 6+ dígitos seguidos."""
    candidatos = []
    for m in re.finditer(r"(?<![\d.])(?:\$?\s*)?(\d{1,3}(?:\.\d{3})+|\d{6,})(?![\d])", fragmento):
        raw = m.group(1)
        if "." in raw and re.match(r"^\d{1,3}(\.\d{3})+$", raw):
            n = int(raw.replace(".", ""))
        else:
            try:
                n = int(raw)
            except ValueError:
                continue
        if n >= 50_000:
            candidatos.append(n)
    return candidatos


def _elegir_monto_salarios(candidatos: list[int], valor_objetivo: int | None) -> int:
    """Elige el monto de salarios más plausible entre los candidatos, priorizando el cercano al valor esperado (5% del contrato)."""
    if not candidatos:
        return 0
    if valor_objetivo and valor_objetivo > 0:
        banda = [n for n in candidatos if valor_objetivo * 0.35 <= n <= valor_objetivo * 2.6]
        if banda:
            return min(banda, key=lambda x: abs(x - valor_objetivo))
    return max(candidatos)


def _fechas_en_fragmento_poliza(fragmento: str) -> list[str]:
    """Extrae todas las fechas (DD/MM/YYYY o YYYY-MM-DD) de un fragmento de texto, normalizadas a YYYY-MM-DD."""
    fechas = []
    for m in re.finditer(r"\b(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})\b", fragmento):
        fechas.append(_normalizar_fecha(f"{m.group(1)}/{m.group(2)}/{m.group(3)}"))
    for m in re.finditer(r"\b(\d{4})[/\-](\d{1,2})[/\-](\d{1,2})\b", fragmento):
        y, mo, d = m.group(1), m.group(2).zfill(2), m.group(3).zfill(2)
        if re.match(r"^\d{4}-\d{2}-\d{2}$", f"{y}-{mo}-{d}"):
            fechas.append(f"{y}-{mo}-{d}")
    return [f for f in fechas if f and re.match(r"^\d{4}-\d{2}-\d{2}$", f)]


def _intentar_completar_salarios_desde_texto_poliza(texto_poliza: str, datos: dict) -> list[str]:
    """
    Completa valor/hasta de salarios desde el texto de la póliza.
    También alarga «hasta» si hay una fecha más tardía cerca de palabras clave de SPPS
    (la IA a veces copia la vigencia de otro amparo con fecha más corta).
    """
    adv: list[str] = []
    if not texto_poliza or len(texto_poliza) < 80:
        return adv
    amparos = datos.get("amparos")
    if not isinstance(amparos, dict):
        return adv
    sal = amparos.get("salarios")
    if not isinstance(sal, dict):
        return adv
    v_act = _a_numero(sal.get("valor"), 0)
    h_act = (sal.get("hasta") or "").strip()

    valor_base = _a_numero(datos.get("valor_sin_iva"), 0)
    objetivo = round(valor_base * 0.05) if valor_base > 0 else None

    kw = re.compile(
        r"(?is)(?:salarios\s*y\s*prestaciones(?:\s+sociales)?|prestaciones\s+sociales"
        r"|amparo\s+de\s+salarios|cobertura\s+de\s+salarios|\bspps\b"
        r"|riesgos\s+laborales|salarios\s+y\s+prestaci|amparo.*salario|salario.*amparo"
        r"|s\.?p\.?p\.?s|pago\s+de\s+salarios|cobertura\s+laboral)",
    )
    mejor_valor = 0
    mejor_hasta = ""
    chunk_len = 1500  # ventana amplia para capturar valor y fechas del mismo bloque
    for m in kw.finditer(texto_poliza):
        # buscar también 300 chars antes del keyword (el valor puede estar antes)
        inicio = max(0, m.start() - 300)
        chunk = texto_poliza[inicio: m.start() + chunk_len]
        cands = _extraer_montos_candidatos_cop(chunk)
        v = _elegir_monto_salarios(cands, objetivo)
        if v > mejor_valor:
            mejor_valor = v
        for ft in _fechas_en_fragmento_poliza(chunk):
            if not mejor_hasta or ft > mejor_hasta:
                mejor_hasta = ft

    # Si el respaldo por keyword no encontró nada, hacer una búsqueda genérica
    # en TODO el texto de la póliza buscando el monto objetivo (5% del contrato)
    if mejor_valor == 0 and objetivo and objetivo > 0:
        todos_cands = _extraer_montos_candidatos_cop(texto_poliza[:60000])
        mejor_valor = _elegir_monto_salarios(todos_cands, objetivo)
        if mejor_valor > 0:
            logger.info("Salarios: monto hallado por búsqueda global en póliza — %s", mejor_valor)

    if v_act <= 0 and mejor_valor > 0:
        sal["valor"] = mejor_valor
        adv.append(
            "ℹ️ «Salarios y Prestaciones Sociales» se completó con un monto leído en el texto de la póliza "
            f"({_format_cop_adv(mejor_valor)}) porque el modelo había dejado $0."
        )
        logger.info("Salarios: respaldo por texto de póliza — valor=%s", mejor_valor)

    if not mejor_hasta:
        # Último intento: buscar la fecha más tardía del texto completo de la póliza
        # que coincida con el mes esperado de vencimiento de salarios
        todas_fechas = _fechas_en_fragmento_poliza(texto_poliza[:60000])
        if todas_fechas:
            mejor_hasta = max(todas_fechas)
            logger.info("Salarios: fecha hasta tomada de búsqueda global en póliza — %s", mejor_hasta)

    if not mejor_hasta:
        return adv

    if not h_act:
        sal["hasta"] = mejor_hasta
        if not adv:
            adv.append(
                "ℹ️ La fecha «hasta» de Salarios se tomó del texto de la póliza (búsqueda por palabras clave)."
            )
    elif h_act < mejor_hasta:
        sal["hasta"] = mejor_hasta
        adv.append(
            f"ℹ️ La vigencia «hasta» de Salarios se ajustó de {h_act} a {mejor_hasta} "
            "por una fecha más tardía asociada en el texto a salarios/prestaciones sociales."
        )
        logger.info("Salarios: fecha hasta ampliada por texto — %s → %s", h_act, mejor_hasta)

    return adv


def _format_cop_adv(n: int) -> str:
    """Formatea un entero como monto en pesos colombianos para los mensajes de advertencia (p. ej. '$3.464.000')."""
    return "$" + f"{n:,.0f}".replace(",", ".")


def _normalizar_datos_analisis(datos, texto_poliza: str | None = None):
    """
    Limpia y completa el JSON devuelto por la IA antes de validarlo.

    Convierte montos y fechas a formatos uniformes, unifica las claves de amparos
    (sinónimos), rellena con ceros las que falten y, si es posible, completa el
    amparo de salarios leyéndolo del texto de la póliza cuando la IA lo dejó vacío.
    """
    if not isinstance(datos, dict):
        logger.warning("La respuesta de la IA no fue dict, se usa objeto vacío")
        return {}

    for campo in ["valor_sin_iva", "iva", "valor_total"]:
        datos[campo] = _a_numero(datos.get(campo, 0), 0)

    # Normalizar fechas del contrato a YYYY-MM-DD
    datos["fecha_inicio"] = _normalizar_fecha(datos.get("fecha_inicio", ""))
    datos["fecha_fin"]    = _normalizar_fecha(datos.get("fecha_fin", ""))

    amparos_raw = datos.get("amparos")
    amparos = _coercer_amparos_entrada(amparos_raw)
    datos["amparos"] = amparos
    _fusionar_amparos_claves_alias(amparos)

    advertencias_amp = []
    for clave in _AMPAROS_JSON_CLAVES:
        if clave not in amparos:
            amparos[clave] = {"valor": 0, "desde": "", "hasta": ""}
            etiqueta = AMPARO_LABELS.get(clave, clave)
            msg = (
                f"⚠️ El modelo no incluyó el amparo «{etiqueta}» en el JSON "
                f"(salida truncada u omisión). Se rellenó con $0 y sin fechas; revisa el resultado."
            )
            advertencias_amp.append(msg)
            logger.warning(
                "Amparo %r ausente en JSON del modelo — completado con valores vacíos",
                clave,
            )

    for amparo, info in list(amparos.items()):
        if not isinstance(info, dict):
            amparos[amparo] = {"valor": 0, "desde": "", "hasta": ""}
            continue
        info["valor"] = _a_numero(info.get("valor", 0), 0)
        info["desde"]  = _normalizar_fecha(info.get("desde", ""))
        info["hasta"]  = _normalizar_fecha(info.get("hasta", ""))

    # Log para diagnóstico
    logger.info(
        "Datos extraídos — tipo=%s | valor_sin_iva=%s | fecha_fin=%s",
        datos.get("tipo"), datos.get("valor_sin_iva"), datos.get("fecha_fin")
    )
    for k, v in datos.get("amparos", {}).items():
        logger.info(
            "  Amparo %-20s valor=%-12s  hasta=%s",
            k, v.get("valor"), v.get("hasta")
        )

    if advertencias_amp:
        datos["_advertencias_amparos_ia"] = advertencias_amp

    if texto_poliza:
        adv_txt = _intentar_completar_salarios_desde_texto_poliza(texto_poliza, datos)
        if adv_txt:
            datos["_advertencias_amparos_ia"] = (datos.get("_advertencias_amparos_ia") or []) + adv_txt

    return datos


def extraer_texto_pdf(file_bytes):
    """Extrae el texto de un PDF con pdfplumber. Devuelve cadena (casi) vacía si el PDF es una imagen escaneada sin texto seleccionable."""
    texto = ""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    try:
        with pdfplumber.open(tmp_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    texto += t + "\n"
    finally:
        os.unlink(tmp_path)
    return texto


def extraer_texto_docx(file_bytes):
    """Extrae el texto de un Word .docx (párrafos y celdas de tablas) con python-docx."""
    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    try:
        doc = docx.Document(tmp_path)
        lines = [p.text for p in doc.paragraphs if p.text.strip()]
        for table in doc.tables:
            for row in table.rows:
                lines.append(" | ".join(c.text.strip() for c in row.cells if c.text.strip()))
        return "\n".join(lines)
    finally:
        os.unlink(tmp_path)


def _extraer_json_respuesta(raw):
    """Parsea la respuesta de la IA como JSON, tolerando bloques markdown ```json y texto alrededor. Lanza JSONDecodeError si no hay JSON válido."""
    limpio = re.sub(r"```json\s*", "", raw or "")
    limpio = re.sub(r"```\s*", "", limpio).strip()
    try:
        resultado = json.loads(limpio)
        logger.info("JSON parseado correctamente (parse directo)")
        return resultado
    except json.JSONDecodeError:
        pass

    logger.warning("Parse directo falló — intentando extracción por llaves")
    inicio = limpio.find("{")
    fin = limpio.rfind("}")
    if inicio == -1 or fin == -1 or fin <= inicio:
        logger.error("No se encontró objeto JSON válido en la respuesta del modelo")
        raise json.JSONDecodeError("No se encontró objeto JSON válido en la respuesta", limpio, 0)
    resultado = json.loads(limpio[inicio:fin + 1])
    logger.info("JSON extraído por llaves correctamente")
    return resultado


# ── Prompt de análisis compartido por todos los motores de IA ──
_SYSTEM_ANALISIS = (
    "Eres un experto jurídico en contratos colombianos y pólizas de seguro. "
    "Responde ÚNICAMENTE con JSON válido, sin markdown, sin texto adicional."
)

# La regla extra sobre el amparo de salarios la reciben OpenAI y los motores NVIDIA NIM.
# El prompt de Gemini no la incluía; se conserva ese comportamiento con el flag.
_REGLA_SALARIOS_ANALISIS = (
    '\n- "salarios" cubre "Salarios y Prestaciones Sociales", "SPPS", "Riesgos Laborales", "Amparo de Salarios"\n'
    "  o cualquier variante. NO lo dejes en $0 si existe algún monto o vigencia en los documentos de póliza\n"
    "  relacionado con salarios/prestaciones."
)


def _construir_prompt_analisis(texto_contrato: str, texto_poliza: str,
                               incluir_regla_salarios: bool) -> str:
    """Prompt único de extracción contrato+póliza compartido por todos los motores de IA."""
    regla_salarios = _REGLA_SALARIOS_ANALISIS if incluir_regla_salarios else ""
    return f"""Analiza los documentos proporcionados y extrae ÚNICAMENTE un objeto JSON válido.
NO incluyas markdown, NO incluyas texto adicional, NO uses bloques de código. Solo el JSON puro.

ESTRUCTURA EXACTA REQUERIDA:
{{
  "numero_contrato": "",
  "tipo": "servicios",
  "contratista": "",
  "nit_contratista": "",
  "fecha_inicio": "YYYY-MM-DD",
  "fecha_fin": "YYYY-MM-DD",
  "valor_sin_iva": 0,
  "iva": 0,
  "valor_total": 0,
  "requiere_liquidacion": true,
  "aseguradora": "",
  "num_poliza": "",
  "aseguradora_rce": "",
  "num_poliza_rce": "",
  "prima_pagada": false,
  "recibo_pago": "",
  "firmada": false,
  "amparos": {{
    "cumplimiento": {{"valor": 0, "desde": "YYYY-MM-DD", "hasta": "YYYY-MM-DD"}},
    "salarios": {{"valor": 0, "desde": "YYYY-MM-DD", "hasta": "YYYY-MM-DD"}},
    "calidad": {{"valor": 0, "desde": "YYYY-MM-DD", "hasta": "YYYY-MM-DD"}},
    "rce": {{"valor": 0, "desde": "YYYY-MM-DD", "hasta": "YYYY-MM-DD"}},
    "calidad_bienes": {{"valor": 0, "desde": "", "hasta": ""}},
    "estabilidad": {{"valor": 0, "desde": "", "hasta": ""}}
  }}
}}

REGLAS:
- "tipo" solo puede ser: servicios, suministro, consultoria, obra, u otros
- Fechas formato YYYY-MM-DD
- fecha_inicio y fecha_fin del CONTRATO: copia EXACTAMENTE el día, mes y año indicados para inicio y terminación (o vencimiento/plazo de ejecución) del contrato. NO sustituyas por el último día del mes salvo que el documento lo diga literalmente. NO uses fechas de pagos, actas de inicio u otros conceptos. La fecha_fin determina los plazos de vigencia exigidos en póliza (p. ej. liquidación 6 meses + ampliación por amparo).
- Valores numéricos SIN puntos, comas ni símbolos (ej: 80000000)
- Si un campo no existe en el documento, usa "" o 0 según corresponda
- prima_pagada = true si el documento indica que fue pagada
- firmada = true si hay firmas o firma digital mencionada
- OBLIGATORIO: en "amparos" incluye SIEMPRE las 6 claves cumplimiento, salarios, calidad, rce, calidad_bienes, estabilidad.
  Ninguna puede faltar ni quedar a medias; si una cobertura no está en los documentos, usa valor 0 y fechas "".
- Nombres de clave en "amparos": usa exactamente esos identificadores (inglés). Es "salarios" con S final, no "salario", "prestaciones_sociales" ni otros sinónimos como clave.
- "amparos" DEBE ser un solo objeto JSON con esas seis claves (no un arreglo/lista de coberturas).
- RCE también puede aparecer como "responsabilidad civil extracontractual" o "RCE"; asígnalo al amparo "rce".
- Si hay VARIOS documentos en la sección PÓLIZAS (separados por líneas "===== DOCUMENTO DE PÓLIZA"),
  consolida la información en UN solo JSON: para cada amparo, usa el MAYOR valor entre documentos
  y la fecha "hasta" MÁS TARDÍA; combina num_poliza/aseguradora si procede.{regla_salarios}

CONTRATO:
{_aplicar_tope_opcional_texto(texto_contrato, "MAX_CHARS_PROMPT_CONTRATO")}

PÓLIZAS (uno o más documentos):
{_aplicar_tope_opcional_texto(texto_poliza, "MAX_CHARS_PROMPT_POLIZAS")}"""


# ── Medición de consumo de tokens ─────────────────────────────
# Permite saber cuánto "gasta" cada análisis y detectar a tiempo si un
# documento se está acercando (o pasando) al límite del modelo.

# Relación aproximada caracteres→tokens en español (1 token ≈ 3,6 chars).
_CHARS_POR_TOKEN = 3.6


def estimar_tokens(texto: str) -> int:
    """Estimación rápida de tokens ANTES de llamar a la IA (para avisar si el documento es grande)."""
    return int(len(texto or "") / _CHARS_POR_TOKEN)


def _uso_desde_respuesta(response, tipo: str) -> dict:
    """
    Extrae el consumo REAL de tokens que reporta el proveedor.

    Cada SDK lo nombra distinto: el compatible con OpenAI usa `usage`
    (prompt_tokens/completion_tokens) y Gemini usa `usage_metadata`
    (prompt_token_count/candidates_token_count). Devuelve siempre el mismo
    diccionario; si el proveedor no informa el dato, queda en 0.
    """
    entrada = salida = total = 0
    try:
        if tipo == "gemini":
            um = getattr(response, "usage_metadata", None)
            if um is not None:
                entrada = int(getattr(um, "prompt_token_count", 0) or 0)
                salida = int(getattr(um, "candidates_token_count", 0) or 0)
                total = int(getattr(um, "total_token_count", 0) or 0)
        else:
            us = getattr(response, "usage", None)
            if us is not None:
                entrada = int(getattr(us, "prompt_tokens", 0) or 0)
                salida = int(getattr(us, "completion_tokens", 0) or 0)
                total = int(getattr(us, "total_tokens", 0) or 0)
    except (AttributeError, TypeError, ValueError):
        pass
    if total == 0:
        total = entrada + salida
    return {"entrada": entrada, "salida": salida, "total": total}


def _largo_efectivo(texto: str, env_key: str) -> int:
    """Caracteres que REALMENTE se envían tras aplicar el tope (sin duplicar el aviso del log)."""
    lim = _opcional_limite_entero_positive(env_key)
    n = len(texto or "")
    return min(n, lim) if lim else n


def _log_consumo(etiqueta: str, model_id: str, uso: dict, chars_contrato: int,
                 chars_poliza: int, max_tokens: int,
                 env_contrato: int | None = None, env_poliza: int | None = None) -> None:
    """Escribe en el log el informe de consumo del análisis, en formato legible."""
    # env_* = lo realmente enviado tras el recorte; si no llega, se asume completo.
    env_contrato = chars_contrato if env_contrato is None else env_contrato
    env_poliza = chars_poliza if env_poliza is None else env_poliza
    est = estimar_tokens("x" * (env_contrato + env_poliza))
    mil = lambda n: f"{n:,}".replace(",", ".")   # separador de miles a la española
    recortado = (env_contrato < chars_contrato) or (env_poliza < chars_poliza)
    logger.info("=== INFORME DE CONSUMO ============================")
    logger.info("   Motor            : %s (%s)", etiqueta, model_id)
    logger.info("   Documentos       : contrato %s chars + polizas %s chars", mil(chars_contrato), mil(chars_poliza))
    if recortado:
        logger.info("   ENVIADO a la IA  : contrato %s + polizas %s chars  (recortado por MAX_CHARS_*)",
                    mil(env_contrato), mil(env_poliza))
    else:
        logger.info("   ENVIADO a la IA  : todo completo (sin recorte)")
    logger.info("   Tokens ENTRADA   : %s   (estimado previo: %s)", mil(uso["entrada"]), mil(est))
    logger.info("   Tokens SALIDA    : %s   (tope del motor: %s)", mil(uso["salida"]), mil(max_tokens))
    logger.info("   Tokens TOTAL     : %s", mil(uso["total"]))
    if uso["salida"] and max_tokens and uso["salida"] >= max_tokens * 0.95:
        logger.warning("   [!] La respuesta toco el tope de salida: puede venir incompleta. Sube 'Tokens' del motor.")
    if uso["entrada"] > 16000:
        logger.warning("   [!] Entrada > 16.000 tokens: supera el cupo gratuito de Gemini y ralentiza a los demas.")
    logger.info("===================================================")


def analizar_con_gemini(texto_contrato, texto_poliza, model_id, max_tokens, prov_cfg=None, uso_out=None):
    """Envía contrato+póliza a Google Gemini/Gemma (SDK google-genai) y devuelve el JSON de datos extraídos."""
    logger.info("Invocando Gemini (%s) — contrato=%s chars, poliza=%s chars",
                model_id, len(texto_contrato), len(texto_poliza))
    nombre_key = (prov_cfg or {}).get("api_key_nombre", "GEMINI_API_KEY")
    api_key = _api_key(nombre_key)
    if not api_key:
        raise ValueError(f"La API key de Gemini no está configurada ({nombre_key} — panel /admin/apis).")

    client_g = genai.Client(api_key=api_key)

    system = _SYSTEM_ANALISIS
    prompt = _construir_prompt_analisis(texto_contrato, texto_poliza, incluir_regla_salarios=False)

    response = client_g.models.generate_content(
        model=model_id,
        contents=prompt,
        config=genai.types.GenerateContentConfig(
            system_instruction=system,
            temperature=0,
            max_output_tokens=max_tokens,
        ),
    )
    raw = (response.text or "").strip()
    try:
        cand = response.candidates[0]
        fr = getattr(cand, "finish_reason", None)
        if fr is not None and "MAX" in str(fr).upper():
            logger.warning(
                "Gemini terminó por límite de tokens (finish_reason=%s). Respuesta=%s chars. "
                "Aumenta max_tokens del motor en /admin/apis si faltan amparos.",
                fr,
                len(raw),
            )
    except (IndexError, AttributeError, TypeError):
        pass
    logger.info("Gemini respondió — respuesta=%s chars", len(raw))
    uso = _uso_desde_respuesta(response, "gemini")
    _log_consumo("Gemini", model_id, uso, len(texto_contrato), len(texto_poliza), max_tokens,
                 _largo_efectivo(texto_contrato, "MAX_CHARS_PROMPT_CONTRATO"),
                 _largo_efectivo(texto_poliza, "MAX_CHARS_PROMPT_POLIZAS"))
    if uso_out is not None:
        uso_out.update(uso)
    return _extraer_json_respuesta(raw)


def analizar_con_openai_compat(texto_contrato, texto_poliza, model_id, max_tokens, prov_cfg, etiqueta, uso_out=None):
    """
    Envía contrato+póliza a cualquier proveedor con API compatible con OpenAI
    (OpenAI oficial, NVIDIA NIM, Groq, Mistral, etc.) y devuelve el JSON extraído.

    prov_cfg: configuración del proveedor (tabla proveedores_ia) con base_url y api_key_nombre.
    """
    logger.info("Invocando %s vía %s (%s) — contrato=%s chars, poliza=%s chars",
                etiqueta, prov_cfg["clave"], model_id, len(texto_contrato), len(texto_poliza))
    client = _cliente_openai_compat(prov_cfg)

    system = _SYSTEM_ANALISIS
    prompt = _construir_prompt_analisis(texto_contrato, texto_poliza, incluir_regla_salarios=True)

    response = client.chat.completions.create(
        model=model_id,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        max_completion_tokens=max_tokens,
        response_format={"type": "json_object"},
    )

    choice = response.choices[0]
    raw = (choice.message.content or "").strip()
    fr = getattr(choice, "finish_reason", None)
    if fr == "length":
        logger.warning(
            "%s terminó por límite de tokens (finish_reason=length). Respuesta=%s chars. "
            "Aumenta max_tokens del motor en /admin/apis si el JSON falla o faltan amparos.",
            etiqueta, len(raw),
        )
    logger.info("%s respondió — respuesta=%s chars, finish_reason=%s", etiqueta, len(raw), fr)
    uso = _uso_desde_respuesta(response, "openai_compatible")
    _log_consumo(etiqueta, model_id, uso, len(texto_contrato), len(texto_poliza), max_tokens,
                 _largo_efectivo(texto_contrato, "MAX_CHARS_PROMPT_CONTRATO"),
                 _largo_efectivo(texto_poliza, "MAX_CHARS_PROMPT_POLIZAS"))
    if uso_out is not None:
        uso_out.update(uso)
    return _extraer_json_respuesta(raw)


def add_meses(fecha_str, meses):
    """Suma N meses a una fecha YYYY-MM-DD (ajustando el día al último válido del mes). Devuelve '' si la fecha es inválida."""
    if not fecha_str:
        return ""
    try:
        d = datetime.strptime(fecha_str, "%Y-%m-%d")
        mes = d.month - 1 + meses
        año = d.year + mes // 12
        mes = mes % 12 + 1
        import calendar
        ultimo_dia = calendar.monthrange(año, mes)[1]
        dia = min(d.day, ultimo_dia)
        return datetime(año, mes, dia).strftime("%Y-%m-%d")
    except Exception:
        logger.warning("add_meses: no se pudo parsear la fecha %r", fecha_str)
        return ""


def validar_amparos(datos):
    """
    Corazón de la validación: compara la póliza contra lo exigido por el manual.

    Para el tipo de contrato, calcula por cada amparo el valor mínimo (% del valor
    sin IVA) y la fecha 'hasta' requerida (fecha fin + meses de liquidación +
    ampliación del amparo), y los compara con lo que trae la póliza. Devuelve una
    lista de resultados con ok_valor / ok_hasta / ok (CUMPLE o NO CUMPLE) por amparo.
    """
    tipo = datos.get("tipo", "otros")
    tc = get_tipos_contrato()
    cfg = tc.get(tipo, tc.get("otros", TIPOS_CONTRATO["otros"]))
    valor_base = datos.get("valor_sin_iva", 0)
    fecha_fin = datos.get("fecha_fin", "")
    liq_meses = 6 if datos.get("requiere_liquidacion", True) else 0

    resultados = []
    al = get_amparo_labels()
    for amparo in cfg["amparos"]:
        pct = cfg["pct"].get(amparo, 0)
        ext = cfg["ext_meses"].get(amparo, 0)
        valor_min = round(valor_base * pct / 100)
        hasta_req = add_meses(add_meses(fecha_fin, liq_meses), ext)

        info_poliza = datos.get("amparos", {}).get(amparo, {})
        valor_poliza = info_poliza.get("valor", 0)
        hasta_poliza = info_poliza.get("hasta", "")
        desde_poliza = info_poliza.get("desde", "")

        if valor_base == 0:
            ok_valor = False
        elif valor_min == 0:
            ok_valor = True
        else:
            ok_valor = valor_poliza >= valor_min

        ok_hasta = hasta_poliza >= hasta_req if hasta_req and hasta_poliza else False
        ok = ok_valor and ok_hasta

        resultados.append({
            "amparo": amparo,
            "label": al.get(amparo, AMPARO_LABELS.get(amparo, amparo)),
            "pct_requerido": pct,
            "valor_minimo": valor_min,
            "valor_poliza": valor_poliza,
            "hasta_requerido": hasta_req,
            "hasta_poliza": hasta_poliza,
            "desde_poliza": desde_poliza,
            "ok_valor": ok_valor,
            "ok_hasta": ok_hasta,
            "ok": ok
        })

    return resultados


def _fmt_monto_col(v) -> str:
    """Formatea un valor como monto en pesos colombianos ('$1.234.567'); si no es número, lo devuelve como texto."""
    try:
        return f"${float(v):,.0f}".replace(",", ".")
    except (TypeError, ValueError):
        return str(v)


def _motivo_no_cumple_deterministico(r: dict) -> str:
    """Explicación breve sin IA (respaldo si falla el modelo)."""
    partes = []
    if not r.get("ok_valor", True):
        partes.append(
            f"El valor en póliza ({_fmt_monto_col(r.get('valor_poliza'))}) es inferior al mínimo exigido "
            f"({_fmt_monto_col(r.get('valor_minimo'))}, {r.get('pct_requerido')}% del contrato sin IVA)."
        )
    if not r.get("ok_hasta", True):
        hp = r.get("hasta_poliza") or "sin fecha"
        hr = r.get("hasta_requerido") or "N/D"
        extra_sal = ""
        if r.get("amparo") == "salarios" and r.get("ok_valor"):
            extra_sal = (
                " Para Salarios el manual exige una vigencia mayor (p. ej. más meses tras liquidación "
                "que cumplimiento o calidad)."
            )
        partes.append(
            f"La vigencia hasta en póliza ({hp}) es anterior a la fecha hasta requerida ({hr}).{extra_sal}"
        )
    return " ".join(partes) if partes else "No cumple los requisitos del manual de contratación."


def generar_explicaciones_no_cumple_ia(resultados: list, modelo: str) -> dict[str, str]:
    """Una sola llamada al modelo: { amparo_key: frase breve en español }."""
    fallos = [r for r in resultados if not r.get("ok")]
    if not fallos:
        return {}

    claves = [r["amparo"] for r in fallos]
    lineas = []
    for r in fallos:
        lineas.append(
            f'{r["amparo"]}: ok_valor={r["ok_valor"]}, valor_poliza={r["valor_poliza"]}, '
            f'valor_minimo={r["valor_minimo"]}, pct={r["pct_requerido"]}%; '
            f'ok_hasta={r["ok_hasta"]}, hasta_poliza={r["hasta_poliza"] or "N/D"}, '
            f'hasta_requerido={r["hasta_requerido"] or "N/D"}'
        )
    prompt = f"""Eres auditor de pólizas contractuales (Colombia). Para cada incumplimiento, una sola frase breve en español (máximo 22 palabras) que diga por qué NO cumple; menciona montos o fechas solo si el dato está en la línea.

Datos por amparo:
{chr(10).join(lineas)}

Responde ÚNICAMENTE con JSON válido, sin markdown. Las claves del objeto deben ser EXACTAMENTE: {json.dumps(claves, ensure_ascii=False)}. Cada valor es un string (la frase)."""

    modelo_eff = _resolver_modelo_ia_aux(modelo)
    if not modelo_eff:
        return {}

    try:
        # Config del motor resuelto y su proveedor (deciden SDK, endpoint y clave).
        motor = get_motores().get(modelo_eff) or _MOTORES_FALLBACK.get(modelo_eff)
        if not motor:
            return {}
        prov_cfg = get_proveedores().get(motor["proveedor"])
        if not prov_cfg:
            return {}
        if prov_cfg["tipo"] == "gemini":
            client_g = genai.Client(api_key=_api_key(prov_cfg["api_key_nombre"]))
            response = client_g.models.generate_content(
                model=motor["model_id"],
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=min(int(motor["max_tokens"]), 2048),
                ),
            )
            raw = (response.text or "").strip()
        else:  # cualquier proveedor compatible con OpenAI
            oa = _cliente_openai_compat(prov_cfg)
            resp = oa.chat.completions.create(
                model=motor["model_id"],
                messages=[{"role": "user", "content": prompt}],
                max_completion_tokens=1024,
                response_format={"type": "json_object"},
            )
            raw = (resp.choices[0].message.content or "").strip()
        obj = _extraer_json_respuesta(raw)
        if not isinstance(obj, dict):
            return {}
        out: dict[str, str] = {}
        for r in fallos:
            k = r["amparo"]
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                out[k] = v.strip()[:450]
        return out
    except Exception as e:
        logger.warning("Explicaciones IA (no cumple): %s", e)
        return {}


def generar_excel(datos, resultados_amparos):
    """
    Genera el Acta de Aprobación de Pólizas (formato A08.P02.F20) como archivo .xlsx.

    Construye un Excel con estilo: datos del contrato, de la póliza, la tabla de
    amparos (verde=cumple / rojo=no cumple), verificaciones, observaciones y el
    resultado global. Devuelve la RUTA del archivo temporal generado.
    """
    wb = Workbook()
    ws = wb.active
    ws.title = "Acta Aprobacion Polizas"

    AZUL_OSC = "1F3864"
    AZUL_MED = "2E5FA3"
    AZUL_CLR = "D9E2F3"
    GRIS     = "F2F2F2"
    VRD_OK   = "E2EFDA"
    VRD_TXT  = "375623"
    RJO_NO   = "FCE4D6"
    RJO_TXT  = "9C0006"
    BLANCO   = "FFFFFF"

    def bd():
        """Devuelve un borde fino gris para las celdas del Excel."""
        s = Side(style="thin", color="AAAAAA")
        return Border(left=s, right=s, top=s, bottom=s)

    def fill(c):
        """Devuelve un relleno sólido del color hexadecimal indicado."""
        return PatternFill("solid", fgColor=c)

    def fnt(bold=False, color="000000", size=10, italic=False):
        """Devuelve una fuente Arial con las opciones dadas (negrita, color, tamaño, cursiva)."""
        return Font(bold=bold, color=color, size=size, italic=italic, name="Arial")

    def aln(h="left", v="center", wrap=False):
        """Devuelve una alineación de celda (horizontal, vertical, ajuste de texto)."""
        return Alignment(horizontal=h, vertical=v, wrap_text=wrap)

    widths = {"A": 30, "B": 18, "C": 20, "D": 22, "E": 16, "F": 18, "G": 16, "H": 14}
    for col, w in widths.items():
        ws.column_dimensions[col].width = w

    r = 1
    tc = get_tipos_contrato()
    tipo_cfg = tc.get(datos.get("tipo", "otros"), tc.get("otros", TIPOS_CONTRATO["otros"]))

    def header_row(text, color=AZUL_MED, size=10):
        """Escribe una fila de encabezado de sección (celda combinada A:H con color de fondo)."""
        nonlocal r
        ws.merge_cells(f"A{r}:H{r}")
        ws[f"A{r}"] = text
        ws[f"A{r}"].font = fnt(bold=True, color=BLANCO, size=size)
        ws[f"A{r}"].fill = fill(color)
        ws[f"A{r}"].alignment = aln("left")
        ws.row_dimensions[r].height = 20
        r += 1

    def data_row(label, val1, label2=None, val2=None):
        """Escribe una fila de datos con una o dos parejas etiqueta/valor."""
        nonlocal r
        ws[f"A{r}"] = label
        ws[f"A{r}"].font = fnt(bold=True, size=9)
        ws[f"A{r}"].fill = fill(AZUL_CLR)
        ws[f"A{r}"].border = bd()
        if label2 and val2 is not None:
            ws.merge_cells(f"B{r}:C{r}")
            ws[f"B{r}"] = val1
            ws[f"B{r}"].font = fnt(size=9)
            ws[f"B{r}"].border = bd()
            ws[f"D{r}"] = label2
            ws[f"D{r}"].font = fnt(bold=True, size=9)
            ws[f"D{r}"].fill = fill(AZUL_CLR)
            ws[f"D{r}"].border = bd()
            ws.merge_cells(f"E{r}:H{r}")
            ws[f"E{r}"] = val2
            ws[f"E{r}"].font = fnt(size=9)
            ws[f"E{r}"].border = bd()
        else:
            ws.merge_cells(f"B{r}:H{r}")
            ws[f"B{r}"] = val1
            ws[f"B{r}"].font = fnt(size=9)
            ws[f"B{r}"].border = bd()
        ws.row_dimensions[r].height = 18
        r += 1

    ws.merge_cells(f"A{r}:H{r}")
    ws[f"A{r}"] = "COLVATEL S.A. E.S.P."
    ws[f"A{r}"].font = fnt(bold=True, color=BLANCO, size=14)
    ws[f"A{r}"].fill = fill(AZUL_OSC)
    ws[f"A{r}"].alignment = aln("center")
    ws.row_dimensions[r].height = 26
    r += 1

    ws.merge_cells(f"A{r}:H{r}")
    ws[f"A{r}"] = "ACTA DE APROBACIÓN DE PÓLIZAS CONTRACTUALES"
    ws[f"A{r}"].font = fnt(bold=True, color=BLANCO, size=12)
    ws[f"A{r}"].fill = fill(AZUL_MED)
    ws[f"A{r}"].alignment = aln("center")
    ws.row_dimensions[r].height = 22
    r += 1

    ws.merge_cells(f"A{r}:H{r}")
    ws[f"A{r}"] = "Código: A08.P02.F20  |  Versión: 1  |  Fecha aprobación formato: 28/08/2023"
    ws[f"A{r}"].font = fnt(italic=True, color="555555", size=9)
    ws[f"A{r}"].fill = fill(AZUL_CLR)
    ws[f"A{r}"].alignment = aln("center")
    r += 1

    ws.merge_cells(f"A{r}:H{r}")
    ws[f"A{r}"] = f"Fecha de aprobación del acta: {date.today().strftime('%d/%m/%Y')}"
    ws[f"A{r}"].font = fnt(bold=True, size=10)
    ws[f"A{r}"].fill = fill(GRIS)
    ws[f"A{r}"].alignment = aln("right")
    r += 2

    header_row("1. DATOS DEL CONTRATO")
    data_row("Contrato No.", datos.get("numero_contrato", ""), "Tipo", tipo_cfg["nombre"])
    data_row("Contratante", "COLVATEL S.A. E.S.P. — NIT: 800.149.877-3")
    data_row("Contratista", f"{datos.get('contratista', '')}  NIT: {datos.get('nit_contratista', '')}")
    data_row("Fecha suscripción", datos.get("fecha_inicio", ""), "Fecha terminación", datos.get("fecha_fin", ""))

    ws[f"A{r}"] = "Cuantía"
    ws[f"A{r}"].font = fnt(bold=True, size=9)
    ws[f"A{r}"].fill = fill(AZUL_CLR)
    ws[f"A{r}"].border = bd()
    for c, txt in [("B", "Valor sin IVA"), ("D", "IVA"), ("F", "Valor Total con IVA")]:
        ws[f"{c}{r}"] = txt
        ws[f"{c}{r}"].font = fnt(bold=True, size=9)
        ws[f"{c}{r}"].fill = fill(AZUL_CLR)
        ws[f"{c}{r}"].alignment = aln("center")
        ws[f"{c}{r}"].border = bd()
    for c in ["C", "E", "G", "H"]:
        ws[f"{c}{r}"].border = bd()
    ws.row_dimensions[r].height = 18
    r += 1

    def fmt_money(v):
        """Formatea un número como monto en pesos ('$1.234.567')."""
        return f"${v:,.0f}".replace(",", ".")

    ws[f"A{r}"].border = bd()
    for c, v in [("B", fmt_money(datos.get("valor_sin_iva", 0))),
                 ("D", fmt_money(datos.get("iva", 0))),
                 ("F", fmt_money(datos.get("valor_total", 0)))]:
        ws.merge_cells(f"{c}{r}:{chr(ord(c)+1)}{r}")
        ws[f"{c}{r}"] = v
        ws[f"{c}{r}"].font = fnt(bold=True, size=10)
        ws[f"{c}{r}"].alignment = aln("center")
        ws[f"{c}{r}"].border = bd()
    for c in ["A", "C", "E", "G", "H"]:
        ws[f"{c}{r}"].border = bd()
    ws.row_dimensions[r].height = 20
    r += 2

    header_row("2. DATOS DE LA PÓLIZA")
    data_row("Aseguradora (Cumplimiento)", datos.get("aseguradora", ""), "Póliza No.", datos.get("num_poliza", ""))
    data_row("Aseguradora (RCE)", datos.get("aseguradora_rce", "") or datos.get("aseguradora", ""),
             "Póliza No. RCE", datos.get("num_poliza_rce", "") or datos.get("num_poliza", ""))
    r += 1

    header_row("3. AMPAROS — VERIFICACIÓN DE VALORES Y VIGENCIAS")
    hdrs = ["Amparo", "% Req.", "Valor mínimo\nrequerido", "Valor en\npóliza",
            "Vigencia\ndesde", "Hasta\nrequerido", "Hasta en\npóliza", "Estado"]
    cols = list("ABCDEFGH")
    for i, h in enumerate(hdrs):
        ws[f"{cols[i]}{r}"] = h
        ws[f"{cols[i]}{r}"].font = fnt(bold=True, color=BLANCO, size=9)
        ws[f"{cols[i]}{r}"].fill = fill(AZUL_OSC)
        ws[f"{cols[i]}{r}"].alignment = aln("center", wrap=True)
        ws[f"{cols[i]}{r}"].border = bd()
    ws.row_dimensions[r].height = 30
    r += 1

    todos_ok = True
    for res in resultados_amparos:
        ok = res["ok"]
        if not ok:
            todos_ok = False
        bg = VRD_OK if ok else RJO_NO
        vals = [
            res["label"], f"{res['pct_requerido']}%",
            fmt_money(res["valor_minimo"]), fmt_money(res["valor_poliza"]),
            res["desde_poliza"], res["hasta_requerido"],
            res["hasta_poliza"], "CUMPLE" if ok else "NO CUMPLE"
        ]
        for i, (c, v) in enumerate(zip(cols, vals)):
            ws[f"{c}{r}"] = v
            color_txt = (VRD_TXT if ok else RJO_TXT) if i == 7 else (
                RJO_TXT if (i == 3 and not res["ok_valor"]) or (i == 6 and not res["ok_hasta"]) else "000000"
            )
            ws[f"{c}{r}"].font = fnt(bold=(i == 7), size=9, color=color_txt)
            ws[f"{c}{r}"].fill = fill(bg)
            ws[f"{c}{r}"].alignment = aln("center" if i > 0 else "left", wrap=True)
            ws[f"{c}{r}"].border = bd()
        ws.row_dimensions[r].height = 22
        r += 1
    r += 1

    header_row("4. VERIFICACIONES DE LA PÓLIZA")
    verifs = [
        ("Firmas", datos.get("firmada", False), "Póliza firmada digitalmente por la aseguradora"),
        ("Constancia de pago", datos.get("prima_pagada", False),
         f"Prima pagada — Recibo: {datos.get('recibo_pago', 'N/D')}"),
        ("Valor asegurado", all(x["ok_valor"] for x in resultados_amparos),
         "Todos los amparos cumplen el porcentaje mínimo requerido"),
        ("Vigencias", all(x["ok_hasta"] for x in resultados_amparos),
         "Todas las fechas 'Hasta' cumplen la extensión requerida por el Manual"),
    ]
    for lbl, ok, desc in verifs:
        ws[f"A{r}"] = lbl
        ws[f"A{r}"].font = fnt(bold=True, size=9)
        ws[f"A{r}"].fill = fill(AZUL_CLR)
        ws[f"A{r}"].border = bd()
        ws.merge_cells(f"B{r}:F{r}")
        ws[f"B{r}"] = desc
        ws[f"B{r}"].font = fnt(size=9)
        ws[f"B{r}"].alignment = aln(wrap=True)
        ws[f"B{r}"].border = bd()
        ws.merge_cells(f"G{r}:H{r}")
        ws[f"G{r}"] = "CUMPLE" if ok else "NO CUMPLE"
        ws[f"G{r}"].font = fnt(bold=True, size=9, color=VRD_TXT if ok else RJO_TXT)
        ws[f"G{r}"].fill = fill(VRD_OK if ok else RJO_NO)
        ws[f"G{r}"].alignment = aln("center")
        ws[f"G{r}"].border = bd()
        ws.row_dimensions[r].height = 20
        r += 1
    r += 1

    header_row("5. OBSERVACIONES")
    obs_list = ["• El cálculo se realiza sobre el valor del contrato SIN IVA."]
    for res in resultados_amparos:
        if not res["ok_valor"]:
            obs_list.append(f"• {res['label']}: valor en póliza {fmt_money(res['valor_poliza'])} inferior al mínimo requerido {fmt_money(res['valor_minimo'])} ({res['pct_requerido']}%). REQUIERE CORRECCIÓN.")
        if not res["ok_hasta"]:
            obs_list.append(f"• {res['label']}: vigencia hasta {res['hasta_poliza']} insuficiente, se requiere hasta {res['hasta_requerido']}. REQUIERE CORRECCIÓN.")
    if todos_ok:
        obs_list.append("• Todos los amparos cumplen los requisitos del Manual de Contratación. Póliza apta para aprobación.")

    for obs in obs_list:
        ws.merge_cells(f"A{r}:H{r}")
        ws[f"A{r}"] = obs
        is_error = "CORRECCIÓN" in obs
        ws[f"A{r}"].font = fnt(size=9, color=RJO_TXT if is_error else "000000")
        ws[f"A{r}"].fill = fill(RJO_NO if is_error else GRIS)
        ws[f"A{r}"].alignment = aln(wrap=True)
        ws[f"A{r}"].border = bd()
        ws.row_dimensions[r].height = 18
        r += 1
    r += 1

    resultado_txt = "PÓLIZA APROBADA" if todos_ok else "PÓLIZA OBSERVADA — REQUIERE CORRECCIONES"
    res_color = VRD_OK if todos_ok else RJO_NO
    res_txt_c = VRD_TXT if todos_ok else RJO_TXT
    ws.merge_cells(f"A{r}:D{r}")
    ws[f"A{r}"] = "RESULTADO GLOBAL:"
    ws[f"A{r}"].font = fnt(bold=True, size=12, color=BLANCO)
    ws[f"A{r}"].fill = fill(AZUL_OSC)
    ws[f"A{r}"].alignment = aln("right")
    ws.merge_cells(f"E{r}:H{r}")
    ws[f"E{r}"] = resultado_txt
    ws[f"E{r}"].font = fnt(bold=True, size=12, color=res_txt_c)
    ws[f"E{r}"].fill = fill(res_color)
    ws[f"E{r}"].alignment = aln("center")
    ws.row_dimensions[r].height = 26
    r += 2

    header_row("6. APROBADO POR")
    data_row("Nombre", "________________________________", "Cargo", "________________________________")
    data_row("Firma", "________________________________", "Fecha", date.today().strftime("%d/%m/%Y"))
    ws.merge_cells(f"A{r}:H{r}")
    ws[f"A{r}"] = "La aprobación de esta acta habilita el inicio de ejecución del contrato según el Manual de Contratación de Colvatel."
    ws[f"A{r}"].font = fnt(italic=True, size=9, color="555555")
    ws[f"A{r}"].alignment = aln("center", wrap=True)
    ws.row_dimensions[r].height = 20

    ws.freeze_panes = "A6"
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToPage = True
    ws.page_setup.fitToWidth = 1

    tmp = tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False)
    wb.save(tmp.name)
    return tmp.name


# ── RUTAS PRINCIPALES ─────────────────────────────────────────

@app.route("/")
def index():
    """Ruta '/': página principal para subir el contrato y las pólizas. Los botones de motor se generan desde la BD."""
    return render_template("index.html", motores=get_motores())


@app.route("/historico")
def historico():
    """Ruta '/historico': tabla con todos los análisis realizados y sus descargas."""
    registros = database.get_historico(None)
    return render_template(
        "historico.html",
        registros=registros,
    )


@app.route("/api/analizar", methods=["POST"])
def analizar():
    """
    Ruta POST '/api/analizar' — endpoint principal de la aplicación.

    Recibe el contrato y una o varias pólizas (multipart/form-data) y el motor de IA.
    Valida los archivos, extrae su texto, llama a la IA para obtener el JSON, valida
    los amparos contra el manual, genera el Acta Excel y guarda el análisis en la BD.
    Devuelve un JSON con datos, resultados, advertencias y el id del documento.
    """
    # Motores disponibles (leídos de la BD; gestionables en /admin/apis).
    motores = get_motores()
    modelo = _normalizar_modelo(request.form.get("modelo"), motores)
    if modelo not in motores:
        return jsonify({"error": f"Modelo no válido. Use uno de: {', '.join(motores.keys())}."}), 400

    motor_cfg = motores[modelo]
    prov_cfg = get_proveedores().get(motor_cfg["proveedor"])
    if not prov_cfg:
        return jsonify({"error": (
            f"El motor '{modelo}' usa el proveedor '{motor_cfg['proveedor']}', que ya no existe. "
            "Edita el motor en el panel Claves APIs (/admin/apis)."
        )}), 500
    if not _api_key(prov_cfg["api_key_nombre"]):
        return jsonify({"error": (
            f"La API key del proveedor '{prov_cfg['clave']}' ({prov_cfg['api_key_nombre']}) no está configurada. "
            "Gestiónala en el panel Claves APIs (/admin/apis)."
        )}), 500

    archivo_contrato = request.files.get("contrato")
    lista = request.files.getlist("polizas")
    if not lista or not any(getattr(f, "filename", None) for f in lista):
        p0 = request.files.get("poliza")
        lista = [p0] if p0 and p0.filename else []

    if not archivo_contrato or not lista:
        return jsonify({"error": "Se debe subir el contrato y al menos un archivo de póliza"}), 400

    ok_c, msg_c = _validar_archivo(archivo_contrato)
    if not ok_c:
        return jsonify({"error": f"Contrato: {msg_c}"}), 400

    polizas_leidas: list[tuple[bytes, str]] = []
    for i, archivo_poliza in enumerate(lista):
        if not archivo_poliza or not archivo_poliza.filename:
            continue
        ok_p, msg_p = _validar_archivo(archivo_poliza)
        if not ok_p:
            return jsonify({"error": f"Póliza #{i + 1} ({archivo_poliza.filename}): {msg_p}"}), 400
        polizas_leidas.append((archivo_poliza.read(), archivo_poliza.filename))

    if not polizas_leidas:
        return jsonify({"error": "No hay archivos de póliza válidos"}), 400

    lim_pol = _opcional_limite_entero_positive("MAX_POLIZAS_POR_ANALISIS")
    if lim_pol is not None and len(polizas_leidas) > lim_pol:
        return jsonify({"error": f"Máximo {lim_pol} archivos de póliza por análisis."}), 400

    try:
        logger.info(
            "Inicio /api/analizar (actor=%s, modelo=%s, num_polizas=%s)",
            APP_ACTOR_LABEL,
            modelo,
            len(polizas_leidas),
        )

        bytes_contrato = archivo_contrato.read()

        def extraer(contenido, nombre):
            n = (nombre or "").lower()
            if n.endswith(".pdf"):
                return extraer_texto_pdf(contenido)
            elif n.endswith(".docx"):
                return extraer_texto_docx(contenido)
            return contenido.decode("utf-8", errors="ignore")

        texto_contrato = extraer(bytes_contrato, archivo_contrato.filename)
        max_chars_pol_ia = _opcional_limite_entero_positive("MAX_CHARS_POLIZAS_IA")
        texto_poliza = _construir_texto_polizas(
            polizas_leidas, extraer, max_chars=max_chars_pol_ia
        )
        logger.info(
            "Texto extraído (contrato=%s chars, pólizas combinadas=%s chars, archivos=%s)",
            len(texto_contrato),
            len(texto_poliza),
            len(polizas_leidas),
        )

        if len(texto_contrato) < 50:
            return jsonify({"error": "No se pudo extraer texto del contrato. Verifica que el PDF no sea imagen escaneada."}), 400
        if len(texto_poliza) < 50:
            return jsonify({"error": "No se pudo extraer texto de la póliza. Verifica que el PDF no sea imagen escaneada."}), 400

        # Aviso PREVIO: estimación del tamaño antes de gastar la llamada.
        est_tokens = estimar_tokens(texto_contrato) + estimar_tokens(texto_poliza)
        logger.info(
            "Estimación previa de entrada: ~%s tokens (contrato+pólizas)",
            f"{est_tokens:,}".replace(",", "."),
        )
        if est_tokens > 16000:
            logger.warning(
                "El envío estimado (~%s tokens) supera 16.000: puede fallar en Gemini gratuito "
                "y tardar mucho en modelos de razonamiento. Ajusta MAX_CHARS_PROMPT_* si falla.",
                f"{est_tokens:,}".replace(",", "."),
            )

        # uso_tokens se rellena dentro de las funciones de análisis con el
        # consumo REAL que informa el proveedor.
        uso_tokens: dict = {}

        # Despacho por TIPO de proveedor: 'gemini' usa su SDK propio; cualquier
        # otro proveedor se atiende por la API compatible con OpenAI.
        if prov_cfg["tipo"] == "gemini":
            datos = analizar_con_gemini(
                texto_contrato, texto_poliza,
                motor_cfg["model_id"], int(motor_cfg["max_tokens"]), prov_cfg,
                uso_out=uso_tokens,
            )
        else:
            datos = analizar_con_openai_compat(
                texto_contrato, texto_poliza,
                motor_cfg["model_id"], int(motor_cfg["max_tokens"]),
                prov_cfg, motor_cfg["etiqueta"],
                uso_out=uso_tokens,
            )

        datos = _normalizar_datos_analisis(datos, texto_poliza=texto_poliza)
        amp_ia_warn = datos.pop("_advertencias_amparos_ia", None) or []
        ia_ff = datos.get("fecha_fin", "")
        ff_regex = _extraer_fecha_terminacion_desde_texto_contrato(texto_contrato, ia_fin=ia_ff)
        if ff_regex and ff_regex != ia_ff:
            logger.info("fecha_fin ajustada por texto del contrato: IA=%s → %s", ia_ff, ff_regex)
            datos["fecha_fin"] = ff_regex
            amp_ia_warn.append(
                "ℹ️ La fecha de terminación del contrato se ajustó según el texto del documento "
                f"({ff_regex}) para alinearla con el Excel/manual; la IA había propuesto {ia_ff or 'N/D'}."
            )

        logger.info("Respuesta de %s parseada correctamente", modelo)

        resultados = validar_amparos(datos)
        explic_ia = generar_explicaciones_no_cumple_ia(resultados, modelo)
        for r in resultados:
            if r["ok"]:
                r["explicacion_no_cumple"] = None
            else:
                r["explicacion_no_cumple"] = (
                    explic_ia.get(r["amparo"]) or _motivo_no_cumple_deterministico(r)
                )

        todos_ok = all(r["ok"] for r in resultados)
        cumplidos = sum(1 for r in resultados if r["ok"])
        logger.info(
            "Validación de amparos completada — %s/%s cumplen — resultado: %s",
            cumplidos, len(resultados),
            "APROBADA" if todos_ok else "OBSERVADA"
        )

        resultado_str = "APROBADA" if todos_ok else "OBSERVADA"

        advertencias = []
        if amp_ia_warn:
            advertencias.extend(amp_ia_warn)
        if datos.get("valor_sin_iva", 0) == 0:
            advertencias.append(
                "⚠️ No se pudo extraer el valor del contrato (quedó en $0). "
                "Las verificaciones de montos de amparos se marcaron como NO CUMPLE. "
                "Revisa que el PDF/DOCX no sea imagen escaneada y que el valor esté claramente escrito."
            )
        if not datos.get("fecha_fin"):
            advertencias.append(
                "⚠️ No se pudo extraer la fecha de terminación del contrato. "
                "Las verificaciones de vigencias no pudieron calcularse."
            )

        bytes_poliza_guardar, etiqueta_polizas = _empaquetar_polizas_almacenamiento(polizas_leidas)

        # Guardar en MySQL (incluyendo bytes originales)
        doc_id = database.guardar_documento(
            modelo=modelo,
            archivo_contrato=archivo_contrato.filename,
            archivo_poliza=etiqueta_polizas,
            datos=datos,
            resultado=resultado_str,
            bytes_contrato=bytes_contrato,
            bytes_poliza=bytes_poliza_guardar,
            num_polizas=len(polizas_leidas),
        )
        if doc_id is None:
            advertencias.append(
                "⚠️ El análisis terminó bien pero no se pudo registrar en la base de datos "
                "(no aparecerá en Histórico). Revise los logs del servidor: suelen indicar errores de MySQL "
                "o restricciones FK (documentos → usuarios)."
            )

        excel_path = generar_excel(datos, resultados)
        logger.info("Excel generado en %s", excel_path)

        app.config["LAST_EXCEL"] = excel_path

        if len(polizas_leidas) > 1:
            advertencias.append(
                "ℹ️ Se analizaron varias pólizas en un solo envío. "
                "La IA debe consolidar montos y vigencias; revisa el detalle si algún amparo quedó incompleto."
            )

        return jsonify({
            "datos": datos,
            "resultados": resultados,
            "todos_ok": todos_ok,
            "excel_listo": True,
            "modelo_usado": modelo,
            "doc_id": doc_id,
            # Informe de consumo para mostrarlo en la interfaz.
            "uso_tokens": {
                "entrada": uso_tokens.get("entrada", 0),
                "salida": uso_tokens.get("salida", 0),
                "total": uso_tokens.get("total", 0),
                "estimado_entrada": est_tokens,
                "tope_salida_motor": int(motor_cfg["max_tokens"]),
                "chars_contrato": len(texto_contrato),
                "chars_polizas": len(texto_poliza),
                "modelo_id": motor_cfg["model_id"],
            },
            "advertencias": advertencias,
            "num_archivos_poliza": len(polizas_leidas),
        })

    except json.JSONDecodeError as e:
        logger.exception("Error parseando JSON del modelo")
        return jsonify({"error": f"El modelo devolvió una respuesta inválida. Detalle: {str(e)}"}), 500
    except _openai_sdk.APITimeoutError:
        # El SDK reporta el timeout como "Connection error." (APITimeoutError
        # hereda de APIConnectionError), lo que despistaba: parecía un fallo de
        # red cuando en realidad el modelo tardó demasiado.
        logger.warning("El modelo %s superó el tiempo de espera", modelo)
        return jsonify({"error": (
            f"El motor «{modelo}» tardó demasiado y se canceló la petición. "
            "Suele pasar con modelos de razonamiento (DeepSeek) y documentos extensos. "
            "Prueba con Gemini o ChatGPT, o reduce el tamaño de los documentos."
        )}), 504
    except _openai_sdk.RateLimitError:
        logger.warning("Cuota agotada en el proveedor del motor %s", modelo)
        return jsonify({"error": (
            f"El proveedor del motor «{modelo}» rechazó la petición por límite de uso (cuota agotada). "
            "Espera un minuto y reintenta, usa otro motor, o revisa el plan de tu API key."
        )}), 429
    except _openai_sdk.APIConnectionError as e:
        logger.warning("Sin conexión con el proveedor del motor %s: %s", modelo, e)
        return jsonify({"error": (
            f"No se pudo contactar al proveedor del motor «{modelo}». "
            "Revisa la conexión a internet y que la URL base del proveedor sea correcta (panel Claves APIs)."
        )}), 502
    except Exception as e:
        logger.exception("Error inesperado en /api/analizar")
        return jsonify({"error": str(e)}), 500


@app.route("/api/recalcular", methods=["POST"])
def recalcular():
    """Recalcula la validación con fechas corregidas por el usuario."""
    try:
        body = request.get_json()
        doc_id = body.get("doc_id")
        fecha_inicio = _normalizar_fecha(body.get("fecha_inicio", ""))
        fecha_fin    = _normalizar_fecha(body.get("fecha_fin", ""))

        if not doc_id:
            return jsonify({"error": "doc_id requerido"}), 400
        if fecha_fin and not re.match(r'^\d{4}-\d{2}-\d{2}$', fecha_fin):
            return jsonify({"error": "Formato de fecha_fin inválido (use YYYY-MM-DD)"}), 400
        if fecha_inicio and not re.match(r'^\d{4}-\d{2}-\d{2}$', fecha_inicio):
            return jsonify({"error": "Formato de fecha_inicio inválido (use YYYY-MM-DD)"}), 400

        row = database.get_documento_json(doc_id)
        if not row:
            return jsonify({"error": "Documento no encontrado"}), 404

        datos = json.loads(row["datos_json"])

        if fecha_inicio:
            datos["fecha_inicio"] = fecha_inicio
        if fecha_fin:
            datos["fecha_fin"] = fecha_fin

        resultados = validar_amparos(datos)
        modelo = row.get("modelo") or "gemini"
        explic_ia = generar_explicaciones_no_cumple_ia(resultados, modelo)
        for r in resultados:
            if r["ok"]:
                r["explicacion_no_cumple"] = None
            else:
                r["explicacion_no_cumple"] = (
                    explic_ia.get(r["amparo"]) or _motivo_no_cumple_deterministico(r)
                )

        todos_ok = all(r["ok"] for r in resultados)
        resultado_str = "APROBADA" if todos_ok else "OBSERVADA"

        database.actualizar_documento_datos(doc_id, datos, resultado_str)

        excel_path = generar_excel(datos, resultados)
        app.config["LAST_EXCEL"] = excel_path

        logger.info(
            "Recálculo doc_id=%s — fecha_fin=%s → %s",
            doc_id, fecha_fin, resultado_str,
        )
        return jsonify({
            "datos": datos,
            "resultados": resultados,
            "todos_ok": todos_ok,
            "excel_listo": True,
            "modelo_usado": modelo,
            "doc_id": doc_id,
            "advertencias": ["ℹ️ Resultado recalculado con fechas corregidas manualmente."],
            "num_archivos_poliza": 1,
        })
    except Exception as e:
        logger.exception("Error en /api/recalcular")
        return jsonify({"error": str(e)}), 500


@app.route("/api/chat", methods=["POST"])
def chat():
    """Ruta POST '/api/chat': asistente que responde preguntas sobre el análisis ya hecho, con el contexto de datos y resultados."""
    try:
        body = request.get_json()
        messages = body.get("messages", [])
        context = body.get("context", {})
        logger.info("Inicio /api/chat (actor=%s, mensajes=%s)", APP_ACTOR_LABEL, len(messages))

        if not messages:
            return jsonify({"error": "No hay mensajes"}), 400

        datos = context.get("datos", {})
        resultados = context.get("resultados", [])

        tc = get_tipos_contrato()
        tipo_cfg = tc.get(datos.get("tipo", "otros"), tc.get("otros", TIPOS_CONTRATO["otros"]))
        todos_ok = all(r["ok"] for r in resultados) if resultados else False

        def fmt(v):
            try:
                return f"${float(v):,.0f}"
            except Exception:
                return str(v)

        resumen_amparos = "\n".join([
            f"  - {r['label']}: valor en póliza {fmt(r['valor_poliza'])} "
            f"(mínimo requerido {fmt(r['valor_minimo'])}, {r['pct_requerido']}% del contrato), "
            f"vigencia hasta {r['hasta_poliza'] or 'N/D'} "
            f"(se requiere hasta {r['hasta_requerido'] or 'N/D'}). "
            f"Estado: {'CUMPLE' if r['ok'] else 'NO CUMPLE'}"
            for r in resultados
        ]) or "  (Sin amparos validados)"

        observaciones = [
            f"  - {r['label']}: {'Valor insuficiente. ' if not r['ok_valor'] else ''}"
            f"{'Vigencia insuficiente.' if not r['ok_hasta'] else ''}"
            for r in resultados if not r["ok"]
        ]
        obs_txt = "\n".join(observaciones) if observaciones else "  Ninguna. Todos los amparos cumplen."

        system_prompt = f"""Eres un asistente experto en contratos y pólizas de seguros para Colvatel S.A. E.S.P. (empresa de servicios públicos colombiana).
Acabas de analizar un par de documentos y tienes los siguientes datos extraídos y validados:

--- CONTRATO ---
- Número: {datos.get('numero_contrato', 'N/D')}
- Tipo: {tipo_cfg.get('nombre', datos.get('tipo', 'N/D'))}
- Contratista: {datos.get('contratista', 'N/D')} (NIT: {datos.get('nit_contratista', 'N/D')})
- Fecha inicio: {datos.get('fecha_inicio', 'N/D')}
- Fecha fin: {datos.get('fecha_fin', 'N/D')}
- Valor sin IVA: {fmt(datos.get('valor_sin_iva', 0))}
- IVA: {fmt(datos.get('iva', 0))}
- Valor total: {fmt(datos.get('valor_total', 0))}
- Requiere liquidación: {'Sí' if datos.get('requiere_liquidacion', True) else 'No'}

--- PÓLIZA ---
- Aseguradora (cumplimiento): {datos.get('aseguradora', 'N/D')}
- Póliza No.: {datos.get('num_poliza', 'N/D')}
- Aseguradora (RCE): {datos.get('aseguradora_rce') or datos.get('aseguradora', 'N/D')}
- Póliza RCE No.: {datos.get('num_poliza_rce') or datos.get('num_poliza', 'N/D')}
- Prima pagada: {'Sí' if datos.get('prima_pagada') else 'No'}
- Firmada por aseguradora: {'Sí' if datos.get('firmada') else 'No'}

--- VERIFICACIÓN DE AMPAROS ---
{resumen_amparos}

--- RESULTADO GLOBAL ---
{'✅ PÓLIZA APROBADA' if todos_ok else '⚠️ PÓLIZA OBSERVADA — REQUIERE CORRECCIONES'}

--- OBSERVACIONES ---
{obs_txt}

Responde siempre en español, de manera clara y precisa. Cuando expliques cálculos, muestra el procedimiento paso a paso. Si el usuario pregunta qué debe corregirse, detalla exactamente qué valores o fechas deben ajustarse y por qué según el Manual de Contratación de Colvatel."""

        # Motor elegido en el front → config desde la BD (misma lógica que /api/analizar).
        motores = get_motores()
        modelo = _normalizar_modelo(body.get("modelo"), motores)
        if modelo not in motores:
            return jsonify({"error": f"Modelo no válido. Use uno de: {', '.join(motores.keys())}."}), 400

        motor_cfg = motores[modelo]
        prov_cfg = get_proveedores().get(motor_cfg["proveedor"])
        if not prov_cfg:
            return jsonify({"error": f"El proveedor '{motor_cfg['proveedor']}' del motor ya no existe (panel /admin/apis)."}), 500
        api_key = _api_key(prov_cfg["api_key_nombre"])
        if not api_key:
            return jsonify({"error": f"API key del proveedor '{prov_cfg['clave']}' no configurada (panel /admin/apis)."}), 500

        if prov_cfg["tipo"] == "gemini":
            client_g = genai.Client(api_key=api_key)
            history = [
                genai.types.Content(
                    role="user" if msg["role"] == "user" else "model",
                    parts=[genai.types.Part(text=msg["content"])],
                )
                for msg in messages[:-1]
            ]
            chat_session = client_g.chats.create(
                model=motor_cfg["model_id"],
                config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.3,
                    max_output_tokens=1000,
                ),
                history=history,
            )
            response = chat_session.send_message(messages[-1]["content"])
            reply = response.text.strip()
        else:  # cualquier proveedor compatible con OpenAI (OpenAI, NVIDIA, Groq...)
            oa = _cliente_openai_compat(prov_cfg)
            oa_messages = [{"role": "system", "content": system_prompt}] + messages
            resp = oa.chat.completions.create(
                model=motor_cfg["model_id"],
                messages=oa_messages,
                max_completion_tokens=1000,
            )
            reply = resp.choices[0].message.content.strip()

        logger.info("Respuesta de chat generada — %s chars", len(reply))
        return jsonify({"reply": reply})

    except Exception as e:
        logger.exception("Error en /api/chat (actor=%s)", APP_ACTOR_LABEL)
        return jsonify({"error": str(e)}), 500


@app.route("/api/descargar-archivo/<int:doc_id>/<tipo>")
def descargar_archivo(doc_id, tipo):
    """
    Ruta '/api/descargar-archivo/<id>/<tipo>': descarga el archivo original DESCIFRADO.

    tipo = 'contrato' o 'poliza'. Si hay varias pólizas se guardan en un ZIP:
    sin ?idx devuelve el ZIP completo; con ?idx=N devuelve solo la póliza número N.
    """
    if tipo not in ("contrato", "poliza"):
        return jsonify({"error": "Tipo inválido"}), 400
    doc = database.get_archivo_documento(doc_id, tipo)
    if not doc or not doc.get("contenido"):
        return jsonify({"error": "Archivo no disponible. Solo se pueden descargar análisis realizados después de esta actualización."}), 404
    nombre = doc["nombre"] or f"{tipo}_{doc_id}.pdf"
    contenido = doc["contenido"]
    idx = request.args.get("idx", type=int)

    if tipo == "poliza" and _es_zip_bytes(contenido):
        try:
            with zipfile.ZipFile(io.BytesIO(contenido), "r") as zf:
                miembros = [n for n in zf.namelist() if not n.endswith("/")]
                if not miembros:
                    return jsonify({"error": "ZIP de pólizas vacío"}), 404
                if idx is not None:
                    if idx < 0 or idx >= len(miembros):
                        return jsonify({"error": "Índice de póliza inválido"}), 400
                    inner_name = miembros[idx]
                    contenido = zf.read(inner_name)
                    nombre = inner_name
                else:
                    return send_file(
                        io.BytesIO(contenido),
                        as_attachment=True,
                        download_name=f"polizas_{doc_id}.zip",
                        mimetype="application/zip",
                    )
        except zipfile.BadZipFile:
            return jsonify({"error": "No se pudo leer el archivo de pólizas"}), 500

    ext = nombre.rsplit(".", 1)[-1].lower() if "." in nombre else "pdf"
    mimetypes_map = {
        "pdf":  "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "doc":  "application/msword",
        "zip":  "application/zip",
    }
    mime = mimetypes_map.get(ext, "application/octet-stream")
    return send_file(
        io.BytesIO(contenido),
        as_attachment=True,
        download_name=nombre,
        mimetype=mime,
    )


@app.route("/api/descargar-excel/<int:doc_id>")
def descargar_excel_historico(doc_id):
    """Ruta '/api/descargar-excel/<id>': regenera y descarga el Acta Excel de un análisis del histórico."""
    doc = database.get_documento_json(doc_id)
    if not doc:
        return jsonify({"error": "Documento no encontrado"}), 404
    try:
        datos = json.loads(doc["datos_json"])
        datos = _normalizar_datos_analisis(datos)
        resultados = validar_amparos(datos)
        excel_path = generar_excel(datos, resultados)
        num = datos.get("numero_contrato", str(doc_id))
        return send_file(
            excel_path,
            as_attachment=True,
            download_name=f"Acta_{num}_{date.today().strftime('%Y%m%d')}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        logger.exception("Error regenerando Excel doc_id=%s", doc_id)
        return jsonify({"error": str(e)}), 500


@app.route("/api/exportar-historico-excel")
def exportar_historico_excel():
    """Exporta un Excel con el resumen de todos los documentos del histórico (sin archivos adjuntos)."""
    try:
        registros = database.get_historico(None)

        wb = Workbook()
        ws = wb.active
        ws.title = "Histórico"

        _navy  = "0B2257"
        _blue  = "1A50AA"
        _green = "1E6B2E"
        _gbg   = "E4F4E8"
        _red   = "9C0006"
        _rbg   = "FCE4D6"
        _alt   = "F5F9FF"
        _white = "FFFFFF"

        thin   = Side(style="thin", color="CCCCCC")
        brd    = Border(left=thin, right=thin, top=thin, bottom=thin)
        c_aln  = Alignment(horizontal="center", vertical="center", wrap_text=False)
        l_aln  = Alignment(horizontal="left",   vertical="center", wrap_text=False)

        # ── Fila 1: título ──────────────────────────────────────────
        NCOLS = 11
        ws.merge_cells(f"A1:{chr(64 + NCOLS)}1")
        tc = ws["A1"]
        tc.value     = f"COLVATEL S.A. E.S.P.  —  Histórico de Documentos  —  Exportado: {date.today().strftime('%d/%m/%Y')}"
        tc.font      = Font(name="Arial", bold=True, color=_white, size=12)
        tc.fill      = PatternFill("solid", fgColor=_blue)
        tc.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[1].height = 26

        # ── Fila 2: encabezados de columna ──────────────────────────
        headers = [
            "#", "Fecha y Hora", "N° Contrato", "Contratista", "NIT / CC",
            "Tipo de Contrato", "Valor sin IVA ($)", "Valor Total ($)",
            "Resultado", "Archivo Contrato", "Archivo(s) Póliza",
        ]
        col_widths = [5, 20, 18, 32, 16, 22, 19, 19, 12, 34, 36]

        for col_idx, (hdr, w) in enumerate(zip(headers, col_widths), 1):
            cell = ws.cell(row=2, column=col_idx, value=hdr)
            cell.font      = Font(name="Arial", bold=True, color=_white, size=10)
            cell.fill      = PatternFill("solid", fgColor=_navy)
            cell.alignment = c_aln
            cell.border    = brd
            ws.column_dimensions[chr(64 + col_idx)].width = w

        ws.row_dimensions[2].height = 20

        # ── Filas de datos ──────────────────────────────────────────
        for i, r in enumerate(registros, 1):
            polizas = " | ".join(
                r.get("poliza_nombres") or
                ([r["archivo_poliza"]] if r.get("archivo_poliza") else ["—"])
            )
            fila = [
                i,
                r.get("fecha", ""),
                r.get("num_contrato", "") or "Sin número",
                r.get("contratista", "") or "—",
                r.get("nit_contratista", "") or "—",
                r.get("tipo_contrato", "") or "—",
                r.get("valor_sin_iva") or "",
                r.get("valor_total") or "",
                r.get("resultado", "") or "—",
                r.get("archivo_contrato", "") or "—",
                polizas,
            ]

            row_num = i + 2
            resultado = r.get("resultado", "")
            alt_fill  = PatternFill("solid", fgColor=_alt) if i % 2 == 0 else None

            for col_idx, valor in enumerate(fila, 1):
                cell = ws.cell(row=row_num, column=col_idx, value=valor)
                cell.border = brd
                cell.font   = Font(name="Arial", size=10)
                cell.alignment = c_aln if col_idx in (1, 9) else l_aln

                if col_idx == 9:  # columna Resultado → color semántico
                    if resultado == "APROBADA":
                        cell.font = Font(name="Arial", bold=True, color=_green, size=10)
                        cell.fill = PatternFill("solid", fgColor=_gbg)
                    elif resultado == "OBSERVADA":
                        cell.font = Font(name="Arial", bold=True, color=_red, size=10)
                        cell.fill = PatternFill("solid", fgColor=_rbg)
                    else:
                        if alt_fill:
                            cell.fill = alt_fill
                elif alt_fill:
                    cell.fill = alt_fill

            ws.row_dimensions[row_num].height = 16

        # ── Paneles congelados y autofiltro ────────────────────────
        ws.freeze_panes = "A3"
        ws.auto_filter.ref = f"A2:{chr(64 + NCOLS)}{len(registros) + 2}"

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
        wb.save(tmp.name)
        tmp.close()

        return send_file(
            tmp.name,
            as_attachment=True,
            download_name=f"Historico_Documentos_{date.today().strftime('%Y%m%d')}.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        logger.exception("Error exportando histórico Excel")
        return jsonify({"error": str(e)}), 500


# ── Manual de Contratación — rutas y extracción ───────────────

_PROMPT_EXTRACCION_MANUAL = """Eres experto en contratación pública colombiana.
Lee el Manual de Contratación y Supervisión de Colvatel S.A. E.S.P. que se adjunta a continuación y extrae la configuración completa de garantías/pólizas contractuales requeridas.

Para cada TIPO DE CONTRATO identifica:
  - Nombre legible del tipo
  - Qué amparos (coberturas) se exigen
  - El porcentaje del valor del contrato (SIN IVA) que debe cubrir cada amparo
  - Cuántos meses de vigencia adicional se exigen DESPUÉS de terminado el contrato para cada amparo
    (si menciona período de liquidación, inclúyelo sumado al plazo del amparo)

Usa EXACTAMENTE estas claves de amparos (minúsculas, sin tildes):
  cumplimiento, salarios, calidad, calidad_bienes, estabilidad, rce

Claves de tipo de contrato recomendadas (agrega más si el manual las define):
  servicios, suministro, consultoria, obra, otros

El manual puede presentar la información en tablas, listas o párrafos.
Extrae TODOS los tipos que encuentres aunque el texto no sea continuo.

Responde ÚNICAMENTE con JSON válido, sin markdown, con esta estructura exacta:
{
  "tipos_contrato": {
    "servicios": {
      "nombre": "Prestación de servicios",
      "amparos": ["cumplimiento", "salarios", "calidad", "rce"],
      "pct": {"cumplimiento": 20, "salarios": 5, "calidad": 20, "rce": 20},
      "ext_meses": {"cumplimiento": 4, "salarios": 36, "calidad": 4, "rce": 4}
    }
  },
  "amparo_labels": {
    "cumplimiento": "Cumplimiento",
    "salarios": "Salarios y Prestaciones Sociales",
    "calidad": "Calidad del Servicio",
    "calidad_bienes": "Calidad de Bienes/Equipos",
    "estabilidad": "Estabilidad y Calidad de Obra",
    "rce": "Responsabilidad Civil Extracontractual"
  },
  "notas": "Observaciones relevantes del manual en máx 300 caracteres"
}

Si un amparo no aplica para un tipo de contrato, no lo incluyas en su lista.

MANUAL COMPLETO:
"""


def _extraer_config_manual_ia(texto: str, modelo: str) -> dict:
    """Envía el texto completo del manual a la IA para extraer la configuración."""
    logger.info("Enviando %s chars al modelo %s para extracción de manual", len(texto), modelo)
    prompt = _PROMPT_EXTRACCION_MANUAL + texto

    # Config del motor desde la BD; su proveedor decide SDK, endpoint y clave.
    motor = get_motores().get(modelo)
    if not motor:
        raise ValueError(f"Modelo no válido. Use uno de: {', '.join(get_motores().keys())}.")
    prov_cfg = get_proveedores().get(motor["proveedor"])
    if not prov_cfg:
        raise ValueError(f"El proveedor '{motor['proveedor']}' del motor ya no existe (panel /admin/apis).")
    api_key = _api_key(prov_cfg["api_key_nombre"])
    if not api_key:
        raise ValueError(f"No hay API key del proveedor '{prov_cfg['clave']}' configurada (panel /admin/apis).")

    if prov_cfg["tipo"] == "gemini":
        client_g = genai.Client(api_key=api_key)
        response = client_g.models.generate_content(
            model=motor["model_id"],
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=min(int(motor["max_tokens"]), 4096),
            ),
        )
        raw = (response.text or "").strip()
    else:  # cualquier proveedor compatible con OpenAI
        oa = _cliente_openai_compat(prov_cfg)
        resp = oa.chat.completions.create(
            model=motor["model_id"],
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=min(int(motor["max_tokens"]), 4096),
            response_format={"type": "json_object"},
        )
        raw = (resp.choices[0].message.content or "").strip()

    resultado = _extraer_json_respuesta(raw)

    if not isinstance(resultado.get("tipos_contrato"), dict) or not resultado["tipos_contrato"]:
        logger.warning(
            "La IA no encontró tipos_contrato. Respuesta raw (primeros 500 chars): %s",
            raw[:500],
        )

    return resultado


@app.route("/admin/manual")
def admin_manual():
    """Ruta '/admin/manual': panel para subir, revisar, editar y activar versiones del Manual de Contratación."""
    manuales = database.listar_manuales()
    manual_activo = database.get_manual_activo()
    return render_template("manual.html", manuales=manuales, manual_activo=manual_activo,
                           motores=get_motores())


@app.route("/api/manual/subir", methods=["POST"])
def manual_subir():
    """Sube el manual, extrae texto y devuelve el id para luego extraer con IA."""
    archivo = request.files.get("manual")
    if not archivo or not archivo.filename:
        return jsonify({"error": "No se recibió el archivo del manual"}), 400

    nombre = archivo.filename.lower()
    if not (nombre.endswith(".pdf") or nombre.endswith(".docx")):
        return jsonify({"error": "Solo se aceptan archivos PDF o DOCX"}), 400

    contenido = archivo.read()
    if len(contenido) > 30 * 1024 * 1024:
        return jsonify({"error": "El archivo supera el límite de 30 MB"}), 400

    try:
        if nombre.endswith(".pdf"):
            texto = extraer_texto_pdf(contenido)
        else:
            texto = extraer_texto_docx(contenido)
    except Exception as e:
        logger.exception("Error extrayendo texto del manual")
        return jsonify({"error": f"No se pudo leer el archivo: {e}"}), 500

    if len(texto) < 200:
        return jsonify({"error": "El archivo parece vacío o es una imagen escaneada sin texto seleccionable"}), 400

    manual_id = database.guardar_manual(
        nombre_archivo=archivo.filename,
        contenido_texto=texto,
        subido_por=APP_ACTOR_LABEL,
    )
    if manual_id is None:
        return jsonify({"error": "Error guardando el manual en la base de datos"}), 500

    logger.info("Manual subido: id=%s, archivo=%s, chars=%s", manual_id, archivo.filename, len(texto))
    return jsonify({"manual_id": manual_id, "chars": len(texto), "nombre": archivo.filename})


@app.route("/api/manual/extraer/<int:manual_id>", methods=["POST"])
def manual_extraer(manual_id):
    """Llama a la IA para extraer la configuración de un manual ya subido."""
    body_m = request.get_json(silent=True) or {}
    motores = get_motores()
    modelo = _normalizar_modelo(body_m.get("modelo"), motores)
    if modelo not in motores:
        return jsonify({"error": f"Modelo no válido. Use uno de: {', '.join(motores.keys())}."}), 400

    texto = database.get_manual_texto(manual_id)
    if not texto:
        return jsonify({"error": "Manual no encontrado"}), 404

    try:
        cfg = _extraer_config_manual_ia(texto, modelo)
    except Exception as e:
        logger.exception("Error extrayendo config del manual id=%s", manual_id)
        return jsonify({"error": f"La IA no pudo extraer la configuración: {e}"}), 500

    tipos = cfg.get("tipos_contrato")
    if not isinstance(tipos, dict) or not tipos:
        chars_total = len(texto)
        return jsonify({
            "error": (
                "La IA analizó el manual pero no encontró la tabla de garantías con la estructura esperada. "
                f"El manual tiene {chars_total:,} caracteres en total. "
                "Intenta con el otro modelo (ChatGPT/OpenAI o Google Gemini). Si el manual usa imágenes o tablas escaneadas "
                "en lugar de texto, la extracción no es posible automáticamente."
            ),
            # Sugerir otro motor distinto al usado (el primero disponible).
            "sugerencia": next((c for c in motores if c != modelo), modelo),
        }), 422

    params_str = json.dumps(cfg, ensure_ascii=False, indent=2)
    database.actualizar_parametros_manual(manual_id, params_str)
    logger.info("Parámetros extraídos y guardados para manual id=%s (%s tipos)", manual_id, len(tipos))
    return jsonify({"ok": True, "parametros": cfg})


@app.route("/api/manual/activar/<int:manual_id>", methods=["POST"])
def manual_activar(manual_id):
    """Activa un manual como configuración vigente y recarga la cache."""
    params = database.get_manual_params(manual_id)
    if not params:
        return jsonify({"error": "Este manual aún no tiene parámetros extraídos. Extrae primero la configuración."}), 400
    ok = database.activar_manual(manual_id)
    if not ok:
        return jsonify({"error": "Error activando el manual"}), 500
    _invalidar_cache_manual()
    logger.info("Manual id=%s activado — cache invalidada", manual_id)
    return jsonify({"ok": True})


@app.route("/api/manual/params/<int:manual_id>", methods=["GET"])
def manual_params(manual_id):
    """Devuelve los parámetros JSON de un manual (para edición en UI)."""
    params = database.get_manual_params(manual_id)
    if params is None:
        return jsonify({"error": "Manual no encontrado"}), 404
    return jsonify({"parametros_json": params})


@app.route("/api/manual/eliminar/<int:manual_id>", methods=["DELETE"])
def manual_eliminar(manual_id):
    """Elimina un manual del historial. No permite eliminar el activo."""
    activo = database.get_manual_activo()
    if activo and activo.get("id") == manual_id:
        return jsonify({"error": "No puedes eliminar el manual activo. Activa otro primero."}), 400
    ok = database.eliminar_manual(manual_id)
    if not ok:
        return jsonify({"error": "Manual no encontrado"}), 404
    logger.info("Manual id=%s eliminado", manual_id)
    return jsonify({"ok": True})


@app.route("/api/manual/guardar-params/<int:manual_id>", methods=["POST"])
def manual_guardar_params(manual_id):
    """Guarda parámetros editados manualmente desde la UI."""
    body = request.get_json(silent=True) or {}
    params_str = body.get("parametros_json", "")
    if not params_str:
        return jsonify({"error": "No se recibieron parámetros"}), 400
    try:
        cfg = json.loads(params_str)
        if not isinstance(cfg.get("tipos_contrato"), dict):
            return jsonify({"error": "El JSON debe contener la clave 'tipos_contrato'"}), 400
    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON inválido: {e}"}), 400

    params_bonito = json.dumps(cfg, ensure_ascii=False, indent=2)
    database.actualizar_parametros_manual(manual_id, params_bonito)
    return jsonify({"ok": True})


# ── Panel de Claves APIs, Proveedores y Motores de IA (/admin/apis) ──
# Gestiona desde la app: los proveedores de API (tabla proveedores_ia), sus
# claves (cifradas en api_keys) y los motores/botones de IA (motores_ia).
# Así, si una clave falla o se quiere probar un modelo/proveedor nuevo,
# no hay que tocar código ni el .env.

_RE_CLAVE_MOTOR = re.compile(r"^[a-z0-9_-]{2,32}$")


def _slug(texto: str) -> str:
    """Convierte un nombre legible en clave interna: minúsculas, sin tildes, guiones."""
    s = "".join(
        ch for ch in unicodedata.normalize("NFD", (texto or "").lower())
        if unicodedata.category(ch) != "Mn"
    )
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:32]


def _nombres_de_keys_validos() -> set:
    """Nombres de API key aceptados: los declarados por los proveedores registrados."""
    return {p["api_key_nombre"] for p in get_proveedores().values()}


@app.route("/admin/apis")
def admin_apis():
    """Ruta '/admin/apis': panel para gestionar proveedores, API keys (cifradas) y motores de IA."""
    keys_guardadas = database.listar_api_keys()          # [{nombre, actualizado}] SIN valores
    nombres_guardados = {k["nombre"] for k in keys_guardadas}
    proveedores = list(get_proveedores().values())
    # Una entrada de clave por proveedor registrado, con su estado.
    keys_info = []
    for p in proveedores:
        nombre = p["api_key_nombre"]
        fila = next((k for k in keys_guardadas if k["nombre"] == nombre), None)
        keys_info.append({
            "nombre": nombre,
            "proveedor": p["clave"],
            "proveedor_etiqueta": p["etiqueta"],
            "en_bd": nombre in nombres_guardados,
            "actualizado": fila["actualizado"] if fila else None,
            "en_env": bool(os.environ.get(nombre, "")),   # respaldo en .env (solo informativo)
        })
    # Motores por proveedor (para impedir borrar proveedores en uso desde la UI).
    motores_todos = database.listar_motores(solo_activos=False)
    en_uso: dict[str, int] = {}
    for m in motores_todos:
        en_uso[m["proveedor"]] = en_uso.get(m["proveedor"], 0) + 1
    return render_template(
        "apis.html",
        keys=keys_info,
        motores=motores_todos,
        proveedores=proveedores,
        proveedores_en_uso=en_uso,
    )


@app.route("/api/apikeys/guardar", methods=["POST"])
def apikeys_guardar():
    """Cifra (Fernet) y guarda/actualiza una API key en la tabla api_keys. Aplica de inmediato."""
    body = request.get_json(silent=True) or {}
    nombre = (body.get("nombre") or "").strip()
    valor = (body.get("valor") or "").strip()
    if nombre not in _nombres_de_keys_validos():
        return jsonify({"error": "Nombre de clave no válido: no corresponde a ningún proveedor registrado."}), 400
    if not valor or len(valor) < 8:
        return jsonify({"error": "La clave está vacía o es demasiado corta."}), 400
    if len(valor) > 500:
        return jsonify({"error": "La clave supera el tamaño máximo (500 caracteres)."}), 400
    if not database.guardar_api_key(nombre, valor):
        return jsonify({"error": "No se pudo guardar la clave en la base de datos."}), 500
    logger.info("API key %s guardada/actualizada desde /admin/apis", nombre)
    return jsonify({"ok": True})


@app.route("/api/apikeys/eliminar/<nombre>", methods=["DELETE"])
def apikeys_eliminar(nombre):
    """Borra una API key de la BD. La app quedará sin ese proveedor (salvo respaldo en .env)."""
    if nombre not in _nombres_de_keys_validos():
        return jsonify({"error": "Nombre de clave no válido."}), 400
    if not database.eliminar_api_key(nombre):
        return jsonify({"error": "La clave no existe en la base de datos."}), 404
    logger.info("API key %s eliminada desde /admin/apis", nombre)
    return jsonify({"ok": True})


@app.route("/api/proveedores/guardar", methods=["POST"])
def proveedores_guardar():
    """
    Registra un proveedor de API nuevo o actualiza uno existente.

    Espera JSON: {id?, etiqueta, base_url?, api_key?}. Con `id` actualiza nombre y
    URL (útil si la URL quedó mal escrita); sin `id` crea uno nuevo de tipo
    'openai_compatible'. Si viene api_key, se guarda cifrada de una vez.
    """
    body = request.get_json(silent=True) or {}
    etiqueta = (body.get("etiqueta") or "").strip()
    base_url = (body.get("base_url") or "").strip()
    api_key = (body.get("api_key") or "").strip()
    prov_id = body.get("id")

    if not etiqueta or len(etiqueta) > 64:
        return jsonify({"error": "El nombre del proveedor es obligatorio (máx. 64 caracteres)."}), 400
    if base_url and not (base_url.startswith("https://") or base_url.startswith("http://")):
        return jsonify({"error": "La URL base debe empezar por https:// (o http:// para servidores locales)."}), 400
    if len(base_url) > 200:
        return jsonify({"error": "La URL base supera los 200 caracteres."}), 400

    # ── Modo edición: corrige nombre/URL de un proveedor existente ──
    if prov_id:
        prov = next((p for p in database.listar_proveedores() if p["id"] == int(prov_id)), None)
        if not prov:
            return jsonify({"error": "Proveedor no encontrado."}), 404
        if not database.actualizar_proveedor(int(prov_id), etiqueta, base_url):
            return jsonify({"error": "No se pudo actualizar el proveedor."}), 500
        if api_key:
            if len(api_key) < 8 or len(api_key) > 500:
                return jsonify({"error": "La API key tiene un tamaño inválido."}), 400
            database.guardar_api_key(prov["api_key_nombre"], api_key)
        logger.info("Proveedor '%s' actualizado desde /admin/apis (url=%s)", prov["clave"], base_url)
        return jsonify({"ok": True, "clave": prov["clave"]})

    clave = _slug(etiqueta)
    if not _RE_CLAVE_MOTOR.fullmatch(clave):
        return jsonify({"error": "El nombre del proveedor debe contener letras o números."}), 400
    if clave in get_proveedores():
        return jsonify({"error": f"Ya existe un proveedor '{clave}'. Usa otro nombre."}), 400

    api_key_nombre = clave.upper().replace("-", "_") + "_API_KEY"
    ok, msg = database.guardar_proveedor({
        "clave": clave, "etiqueta": etiqueta, "tipo": "openai_compatible",
        "base_url": base_url, "api_key_nombre": api_key_nombre,
    })
    if not ok:
        return jsonify({"error": msg or "No se pudo guardar el proveedor."}), 400

    # Si el usuario pegó la clave en el mismo formulario, se guarda cifrada ya.
    if api_key:
        if len(api_key) < 8 or len(api_key) > 500:
            return jsonify({"ok": True, "aviso": "Proveedor creado, pero la clave no se guardó (tamaño inválido). Guárdala en la sección de claves."})
        database.guardar_api_key(api_key_nombre, api_key)
        logger.info("Proveedor '%s' creado con su API key desde /admin/apis", clave)
    else:
        logger.info("Proveedor '%s' creado desde /admin/apis (sin clave aún)", clave)
    return jsonify({"ok": True, "clave": clave, "api_key_nombre": api_key_nombre})


@app.route("/api/proveedores/eliminar/<int:proveedor_id>", methods=["DELETE"])
def proveedores_eliminar(proveedor_id):
    """Borra un proveedor (y su API key cifrada) si ningún motor lo está usando."""
    prov = next((p for p in database.listar_proveedores() if p["id"] == proveedor_id), None)
    if not prov:
        return jsonify({"error": "Proveedor no encontrado."}), 404
    usados = [m for m in database.listar_motores(solo_activos=False) if m["proveedor"] == prov["clave"]]
    if usados:
        nombres = ", ".join(m["etiqueta"] for m in usados[:5])
        return jsonify({"error": f"No se puede eliminar: {len(usados)} motor(es) lo usan ({nombres}). Elimina o reasigna esos motores primero."}), 400
    database.eliminar_proveedor(proveedor_id)
    database.eliminar_api_key(prov["api_key_nombre"])   # limpia también su clave cifrada
    logger.info("Proveedor '%s' eliminado desde /admin/apis (con su API key)", prov["clave"])
    return jsonify({"ok": True})


@app.route("/api/motores/guardar", methods=["POST"])
def motores_guardar():
    """
    Crea o actualiza un motor de IA (botón de la app) con validación completa.

    Espera JSON: {id?, clave?, etiqueta, chip?, proveedor, model_id, max_tokens?, activo?}.
    La clave interna es opcional: si no viene, se genera sola a partir del nombre.
    """
    body = request.get_json(silent=True) or {}
    clave = (body.get("clave") or "").strip().lower()
    etiqueta = (body.get("etiqueta") or "").strip()
    chip = (body.get("chip") or "").strip()
    descripcion = (body.get("descripcion") or "").strip()
    proveedor = (body.get("proveedor") or "").strip().lower()
    model_id = (body.get("model_id") or "").strip()
    activo = 1 if body.get("activo", True) else 0

    # ── Validaciones ──
    if not etiqueta or len(etiqueta) > 64:
        return jsonify({"error": "El nombre del botón es obligatorio (máx. 64 caracteres)."}), 400
    if not clave:
        # Clave interna generada automáticamente desde el nombre del botón;
        # si ya existe, se le añade un sufijo numérico para hacerla única.
        clave = _slug(etiqueta)
        existentes = {m["clave"] for m in database.listar_motores(solo_activos=False)}
        base, n = clave, 2
        while clave in existentes:
            clave = f"{base}-{n}"[:32]
            n += 1
    if not _RE_CLAVE_MOTOR.fullmatch(clave):
        return jsonify({"error": "Clave interna inválida: use 2-32 caracteres (minúsculas, números, guion o guion bajo)."}), 400
    if len(chip) > 32 or len(descripcion) > 200:
        return jsonify({"error": "Chip máx. 32 caracteres; descripción máx. 200."}), 400
    if proveedor not in get_proveedores():
        return jsonify({"error": f"Proveedor no válido. Registrados: {', '.join(get_proveedores().keys())}."}), 400
    if not model_id or len(model_id) > 128:
        return jsonify({"error": "El ID del modelo es obligatorio (máx. 128 caracteres, p. ej. deepseek-ai/deepseek-v4-pro)."}), 400
    try:
        max_tokens = int(body.get("max_tokens") or 4096)
    except (TypeError, ValueError):
        return jsonify({"error": "max_tokens debe ser un número entero."}), 400
    if not (256 <= max_tokens <= 65536):
        return jsonify({"error": "max_tokens debe estar entre 256 y 65536."}), 400

    # No permitir desactivar/renombrar el ÚLTIMO motor activo (la app quedaría sin botones).
    motor_id = body.get("id")
    if motor_id and not activo:
        activos = [m for m in database.listar_motores(solo_activos=True)]
        if len(activos) == 1 and activos[0]["id"] == int(motor_id):
            return jsonify({"error": "No puedes desactivar el único motor activo. Activa otro primero."}), 400

    ok, msg = database.guardar_motor({
        "id": int(motor_id) if motor_id else None,
        "clave": clave, "etiqueta": etiqueta, "chip": chip,
        "descripcion": descripcion, "proveedor": proveedor,
        "model_id": model_id, "max_tokens": max_tokens, "activo": activo,
    })
    if not ok:
        return jsonify({"error": msg or "No se pudo guardar el motor."}), 400
    logger.info("Motor IA '%s' guardado desde /admin/apis (proveedor=%s, model=%s)", clave, proveedor, model_id)
    return jsonify({"ok": True})


@app.route("/api/motores/eliminar/<int:motor_id>", methods=["DELETE"])
def motores_eliminar(motor_id):
    """Borra un motor (su botón desaparece de la app). Nunca deja la app sin motores activos."""
    activos = database.listar_motores(solo_activos=True)
    if len(activos) == 1 and activos[0]["id"] == motor_id:
        return jsonify({"error": "No puedes eliminar el único motor activo. Crea o activa otro primero."}), 400
    if not database.eliminar_motor(motor_id):
        return jsonify({"error": "Motor no encontrado."}), 404
    logger.info("Motor IA id=%s eliminado desde /admin/apis", motor_id)
    return jsonify({"ok": True})


@app.route("/api/motores/probar/<clave>", methods=["POST"])
def motores_probar(clave):
    """
    Prueba de vida de un motor: hace una llamada mínima a la IA y reporta el resultado.

    Sirve para diagnosticar desde el panel si una API key falla o el model_id es
    incorrecto, sin tener que subir documentos.
    """
    todos = {m["clave"]: m for m in database.listar_motores(solo_activos=False)}
    motor = todos.get(clave) or get_motores().get(clave)
    if not motor:
        return jsonify({"error": "Motor no encontrado."}), 404

    prov_cfg = get_proveedores().get(motor["proveedor"])
    if not prov_cfg:
        return jsonify({"ok": False, "mensaje": f"El proveedor '{motor['proveedor']}' del motor ya no existe."})
    api_key = _api_key(prov_cfg["api_key_nombre"])
    if not api_key:
        return jsonify({"ok": False, "mensaje": f"No hay API key configurada para el proveedor '{prov_cfg['clave']}' ({prov_cfg['api_key_nombre']})."})

    try:
        pregunta = "Responde únicamente con la palabra: OK"
        if prov_cfg["tipo"] == "gemini":
            client_g = genai.Client(api_key=api_key)
            r = client_g.models.generate_content(
                model=motor["model_id"],
                contents=pregunta,
                config=genai.types.GenerateContentConfig(max_output_tokens=50),
            )
            texto = (r.text or "").strip()
        else:  # cualquier proveedor compatible con OpenAI
            cli = _cliente_openai_compat(prov_cfg)
            r = cli.chat.completions.create(
                model=motor["model_id"],
                messages=[{"role": "user", "content": pregunta}],
                max_completion_tokens=50,
            )
            texto = (r.choices[0].message.content or "").strip()
        logger.info("Prueba de motor '%s' OK — respuesta: %s", clave, texto[:60])
        return jsonify({"ok": True, "mensaje": f"El motor respondió: «{texto[:80] or '(respuesta vacía, pero la clave funciona)'}»"})
    except Exception as e:
        logger.warning("Prueba de motor '%s' FALLÓ: %s", clave, e)
        return jsonify({"ok": False, "mensaje": f"Falló: {str(e)[:300]}"})


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  COLVATEL — Agente Aprobación de Pólizas")
    print("="*55)
    print("  Abre tu navegador en:  http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=False, port=5000)
