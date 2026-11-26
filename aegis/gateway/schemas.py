"""Request/response helpers for the gateway."""

import json


def json_response(handler, obj, status: int = 200):
    body = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def read_json(handler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))
