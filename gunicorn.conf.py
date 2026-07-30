"""
Configuración de Gunicorn para Colvatel — Agente de Aprobación de Pólizas.

Arranque:
    gunicorn -c gunicorn.conf.py wsgi:app
"""
import multiprocessing

# Escucha solo en localhost: Nginx hace de proxy inverso por delante.
bind = "127.0.0.1:5000"

# Procesos worker. Regla habitual: (2 x núcleos) + 1.
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2

# El análisis con IA puede tardar (llamadas a Gemini/OpenAI/NVIDIA sobre
# documentos grandes); subimos el timeout muy por encima de los 30s por defecto.
timeout = 180
graceful_timeout = 30
keepalive = 5

# Reciclado de workers para mitigar fugas de memoria.
max_requests = 200
max_requests_jitter = 50

# Logs a stdout/stderr (los captura journald bajo systemd).
accesslog = "-"
errorlog = "-"
loglevel = "info"

proc_name = "colvatel-polizas"
