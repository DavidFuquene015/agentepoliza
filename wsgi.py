"""
Punto de entrada WSGI para servidores de producción (gunicorn / uwsgi).

Uso con gunicorn:
    gunicorn -c gunicorn.conf.py wsgi:app
"""
from app import app

if __name__ == "__main__":
    app.run()
