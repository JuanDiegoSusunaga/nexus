"""Framing de NEXUS: transporte opaco, sin claves ni cambios de firma."""
import socketserver
import struct
import threading

MAGIC = b"NXSNET04"
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_FRAME = MAX_PAYLOAD + 12


def read_exact(read, length):
    parts = []
    while length:
        chunk = read(length)
        if not chunk:
            raise ValueError("Trama truncada")
        parts.append(chunk)
        length -= len(chunk)
    return b"".join(parts)


def read_frame(read):
    header = read_exact(read, 12)
    length = struct.unpack("<I", header[8:])[0]
    if header[:8] != MAGIC or not 0 < length <= MAX_PAYLOAD:
        raise ValueError("Cabecera o longitud de trama inválida")
    return header + read_exact(read, length)


def validate_frame(frame):
    if len(frame) < 13 or frame[:8] != MAGIC:
        raise ValueError("Trama inválida")
    length = struct.unpack("<I", frame[8:12])[0]
    if not 0 < length <= MAX_PAYLOAD or len(frame) != length + 12:
        raise ValueError("Longitud de trama inválida")
    return frame


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True

    def process_request(self, request, address):
        if not self.permits.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.permits.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.permits.release()

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(15)
        return request, address

    def set_capacity(self, capacity):
        self.permits = threading.BoundedSemaphore(capacity)
