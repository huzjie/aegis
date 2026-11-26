"""HTTP server bootstrap."""

from http.server import HTTPServer

from aegis.api import Aegis
from aegis.gateway.handlers import make_handler


def serve(port: int = 8700, host: str = "127.0.0.1", engine: Aegis | None = None):
    engine = engine or Aegis()
    httpd = HTTPServer((host, port), make_handler(engine))
    print(f"aegis control plane listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
