"""Adapta cuatro sockets locales de NEXUS a la pasarela HTTPS pública."""
import argparse
import json
import socketserver
import ssl
import threading
import urllib.request
from urllib.parse import urlsplit
from home_transport import BoundedThreads, MAX_FRAME, read_frame, validate_frame


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class Adapter(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, address, base_url, index, allow_http=False):
        url = urlsplit(base_url)
        if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
            raise ValueError("La URL debe ser el origen HTTPS de la pasarela")
        if url.scheme != "https" and not (allow_http and url.scheme == "http" and url.hostname == "127.0.0.1"):
            raise ValueError("Se requiere HTTPS; HTTP solo se admite en pruebas loopback explícitas")
        if not url.hostname or index not in range(4):
            raise ValueError("Origen o índice inválido")
        self.url = base_url.rstrip("/") + f"/rpc/{index}"
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self.set_capacity(4)
        super().__init__(address, AdapterHandler)


class AdapterHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            frame = read_frame(self.request.recv)
            request = urllib.request.Request(self.server.url, frame, headers={"Content-Type": "application/octet-stream"}, method="POST")
            with self.server.opener.open(request, timeout=12) as response:
                body = response.read(MAX_FRAME + 1)
                validate_frame(body)
            self.request.sendall(body)
        except (OSError, ValueError) as error:
            print(f"Intercambio fallido: {type(error).__name__}: {str(error)[:500]}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--base-port", type=int, default=19901)
    parser.add_argument("--allow-http-loopback", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.base_port <= 65532:
        parser.error("Rango de puertos inválido")
    servers, threads = [], []
    try:
        for index in range(4):
            servers.append(Adapter(("127.0.0.1", args.base_port + index), args.url, index, args.allow_http_loopback))
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        print(json.dumps({"local_endpoints": [f"127.0.0.1:{server.server_address[1]}" for server in servers]}), flush=True)
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers[:len(threads)]:
            server.shutdown()
        for server in servers:
            server.server_close()


if __name__ == "__main__":
    main()
