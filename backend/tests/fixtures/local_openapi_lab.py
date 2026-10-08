#!/usr/bin/env python3
"""Small deterministic OpenAPI fixture for local Schemathesis validation."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

SCHEMA = {
    "openapi": "3.0.3",
    "info": {"title": "Local validation API", "version": "1.0.0"},
    "paths": {
        "/items/{item_id}": {
            "get": {
                "parameters": [
                    {
                        "name": "item_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1, "maximum": 10},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Item",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["id", "name"],
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        }
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/openapi.json":
            self.respond(200, SCHEMA)
            return
        if path.startswith("/items/"):
            try:
                item_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self.respond(400, {"error": "invalid item"})
                return
            self.respond(200, {"id": item_id, "name": f"item-{item_id}"})
            return
        self.respond(404, {"error": "not found"})

    def respond(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
