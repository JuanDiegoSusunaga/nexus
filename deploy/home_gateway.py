"""Pasarela HTTP acotada hacia cuatro backends fijos de NEXUS."""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
from home_transport import BoundedThreads, MAX_FRAME, read_frame, validate_frame


class Gateway(BoundedThreads, http.server.HTTPServer):
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, backends, genesis, binary):
        if len(backends) != 4:
            raise ValueError("Se requieren cuatro backends")
        self.backends = backends
        self.genesis = Path(genesis)
        self.genesis_bytes = self.genesis.read_bytes()
        if len(self.genesis_bytes) > 1024 * 1024:
            raise ValueError("Génesis demasiado grande")
        self.binary = binary
        self.downloads = {"home_connect.py": Path(__file__).with_name("home_connect.py"),
                          "home_transport.py": Path(__file__).with_name("home_transport.py"),
                          "nexus-linux-amd64": Path("/usr/local/bin/nexus")}
        self.download_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                               for name, path in self.downloads.items() if path.is_file()}
        self.cache = [None] * 4
        self.cache_locks = [threading.Lock() for _ in range(4)]
        self.set_capacity(8)
        super().__init__(address, Handler)

    def status(self, index):
        with self.cache_locks[index]:
            cached = self.cache[index]
            if cached and time.monotonic() - cached[0] < 1:
                return cached[1]
            host, port = self.backends[index]
            node = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            command = [self.binary, "testnet", "status", "--genesis", str(self.genesis), "--node", node]
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=13, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode or len(result.stdout) > 64 * 1024:
                raise RuntimeError("Nodo no disponible")
            value = json.loads(result.stdout)
            value["verified_by_local_cli"] = True
            self.cache[index] = (time.monotonic(), value)
            return value


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NEXUS-Gateway/1"

    def log_message(self, format, *args):
        # No se guardan cuerpos, transacciones ni rutas aportadas por el cliente.
        pass

    def send_body(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_GET(self):
        if self.path in {"/", "/health"}:
            value = {"network": "NEXUS testnet", "protocol": 4, "nodes": 4,
                     "scope": "Cuatro validadores Docker en una máquina; NXS de prueba",
                     "genesis": "/genesis.json", "rpc": [f"/rpc/{n}" for n in range(4)],
                     "status": [f"/status/{n}" for n in range(4)],
                     "client_downloads": {name: {"path": f"/client/{name}", "sha256": digest}
                                          for name, digest in self.server.download_hashes.items()}}
            self.send_body(200, json.dumps(value).encode())
        elif self.path == "/genesis.json":
            self.send_body(200, self.server.genesis_bytes)
        elif self.path.startswith("/client/") and self.path[8:] in self.server.download_hashes:
            self.send_body(200, self.server.downloads[self.path[8:]].read_bytes(), "application/octet-stream")
        elif match := re.fullmatch(r"/status/([0-3])", self.path):
            try:
                value = self.server.status(int(match[1]))
                self.send_body(200, json.dumps(value).encode())
            except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                print(f"Consulta de estado rechazada: {type(error).__name__}", flush=True)
                self.send_body(503, b'{"error":"node unavailable"}')
        else:
            self.send_body(404, b'{"error":"not found"}')

    def do_POST(self):
        match = re.fullmatch(r"/rpc/([0-3])", self.path)
        lengths = self.headers.get_all("Content-Length", [])
        if not match:
            self.send_body(404, b'{"error":"not found"}')
            return
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self.send_body(400, b'{"error":"content length required"}')
            return
        length = int(lengths[0])
        if not 13 <= length <= MAX_FRAME:
            self.send_body(413, b'{"error":"frame size limit"}')
            return
        if self.headers.get("Content-Encoding") or self.headers.get("Content-Type") != "application/octet-stream":
            self.send_body(415, b'{"error":"binary frame required"}')
            return
        try:
            frame = self.rfile.read(length)
            validate_frame(frame)
            with socket.create_connection(self.server.backends[int(match[1])], timeout=8) as connection:
                connection.sendall(frame)
                response = read_frame(connection.recv)
            self.send_body(200, response, "application/octet-stream")
        except (OSError, ValueError) as error:
            print(f"Trama rechazada: {type(error).__name__}", flush=True)
            self.send_body(400, b'{"error":"invalid frame or unavailable backend"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--backend", action="append", required=True)
    parser.add_argument("--binary", default="/usr/local/bin/nexus")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    backends = []
    for item in args.backend:
        host, port = item.rsplit(":", 1)
        backends.append((host, int(port)))
    with Gateway(("0.0.0.0", args.port), backends, args.genesis, args.binary) as server:
        print(json.dumps({"gateway_port": server.server_port, "nodes": len(backends)}), flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
