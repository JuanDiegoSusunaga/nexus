"""Contrastes de framing, destino fijo, rutas y transporte opaco de la pasarela."""
import http.client
import io
import socket
import socketserver
import struct
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from home_connect import Adapter
from home_gateway import Gateway
from home_transport import MAGIC, MAX_PAYLOAD, read_frame, validate_frame


def frame(body):
    return MAGIC + struct.pack("<I", len(body)) + body


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        packet = read_frame(self.request.recv)
        self.server.received.append(packet)
        self.request.sendall(frame(b"reply:" + packet[12:]))


class GatewayTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        genesis = self.root / "genesis.json"
        genesis.write_bytes(b'{"public":"genesis"}')
        (self.root / "validator.key").write_bytes(b"NUNCA PUBLICAR")
        self.backend = socketserver.TCPServer(("127.0.0.1", 0), Echo)
        self.backend.received = []
        self.gateway = Gateway(("127.0.0.1", 0), [self.backend.server_address] * 4, genesis, "unused-in-tests")
        self.threads = []
        for server in [self.backend, self.gateway]:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for server in [self.gateway, self.backend]:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def request(self, path, body=None, headers=None, method="POST"):
        connection = http.client.HTTPConnection(*self.gateway.server_address, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        value = response.status, response.read()
        connection.close()
        return value

    def test_valid_frame_and_response_keep_every_byte(self):
        packet = frame(b"\x00\xffsigned-envelope")
        code, body = self.request("/rpc/2", packet, {"Content-Type": "application/octet-stream"})
        self.assertEqual(code, 200)
        self.assertEqual(body, frame(b"reply:\x00\xffsigned-envelope"))
        self.assertEqual(self.backend.received, [packet])

    def test_corrupt_or_truncated_frames_never_reach_backend(self):
        for packet in [b"malformedxxxx", frame(b"valid") + b"suffix", frame(b"valid")[:-1]]:
            self.assertEqual(self.request("/rpc/0", packet, {"Content-Type": "application/octet-stream"})[0], 400)
        self.assertFalse(self.backend.received)

    def test_oversized_length_is_rejected_without_reading_body(self):
        code, _ = self.request("/rpc/0", b"", {"Content-Type": "application/octet-stream", "Content-Length": str(MAX_PAYLOAD + 13)})
        self.assertEqual(code, 413)
        self.assertFalse(self.backend.received)

    def test_only_public_genesis_and_allowlisted_client_files_can_be_read(self):
        self.assertEqual(self.request("/genesis.json", method="GET"), (200, b'{"public":"genesis"}'))
        code, source = self.request("/client/home_connect.py", method="GET")
        self.assertEqual(code, 200)
        self.assertIn(b"class Adapter", source)
        for path in ["/validator.key", "/../validator.key", "/keys/faucet.key", "/genesis.json?file=validator.key"]:
            self.assertEqual(self.request(path, method="GET")[0], 404)

    def test_url_or_invalid_node_cannot_select_another_backend(self):
        for path in ["http://127.0.0.1:22", "/rpc/4", "/rpc/-1", "/rpc/0/anything"]:
            self.assertEqual(self.request(path, frame(b"x"), {"Content-Type": "application/octet-stream"})[0], 404)
        self.assertFalse(self.backend.received)

    def test_transfer_encoding_or_nonbinary_body_is_rejected(self):
        self.assertEqual(self.request("/rpc/0", frame(b"x"), {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("/rpc/0", frame(b"x"), {"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"})[0], 400)
        self.assertFalse(self.backend.received)

    def test_local_adapter_roundtrip_preserves_the_frame(self):
        adapter = Adapter(("127.0.0.1", 0), f"http://127.0.0.1:{self.gateway.server_port}", 1, True)
        thread = threading.Thread(target=adapter.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(adapter.server_address, timeout=3) as connection:
                connection.sendall(frame(b"signed payload"))
                self.assertEqual(read_frame(connection.recv), frame(b"reply:signed payload"))
        finally:
            adapter.shutdown()
            adapter.server_close()
            thread.join(timeout=2)

    def test_adapter_requires_https_for_any_non_loopback_origin(self):
        for origin in ["http://example.com", "https://user:password@example.com", "https://example.com/?token=x"]:
            with self.assertRaises(ValueError):
                Adapter(("127.0.0.1", 0), origin, 0)

    def test_framing_rejects_oversized_header_before_payload_allocation(self):
        source = io.BytesIO(MAGIC + struct.pack("<I", MAX_PAYLOAD + 1))
        with self.assertRaises(ValueError):
            read_frame(source.read)
        for packet in [frame(b"x")[:-1], frame(b"x") + b"trailing"]:
            with self.assertRaises(ValueError):
                validate_frame(packet)


if __name__ == "__main__":
    unittest.main()
