#!/usr/bin/env python3
"""Tiny authoritative DNS fixture for isolated adapter validation."""

import socketserver
import struct
import threading

ZONE = "lab.security-platform.test"
ADDRESS = b"\xac\x11\x00\x02"
KNOWN = {ZONE, f"www.{ZONE}", f"api.{ZONE}"}


def question_name(packet: bytes) -> tuple[str, int]:
    labels = []
    offset = 12
    while offset < len(packet):
        size = packet[offset]
        offset += 1
        if size == 0:
            return ".".join(labels).lower(), offset
        labels.append(packet[offset : offset + size].decode("ascii"))
        offset += size
    raise ValueError("truncated DNS question")


def answer(packet: bytes) -> bytes:
    name, end = question_name(packet)
    question = packet[12 : end + 4]
    qtype, qclass = struct.unpack("!HH", packet[end : end + 4])
    include = name in KNOWN and qtype == 1 and qclass == 1
    header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, int(include), 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ADDRESS if include else b""
    return header + question + record


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, sock = self.request
        try:
            sock.sendto(answer(payload), self.client_address)
        except (UnicodeDecodeError, ValueError, struct.error):
            return


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        prefix = self.request.recv(2)
        if len(prefix) != 2:
            return
        size = struct.unpack("!H", prefix)[0]
        payload = self.request.recv(size)
        try:
            response = answer(payload)
        except (UnicodeDecodeError, ValueError, struct.error):
            return
        self.request.sendall(struct.pack("!H", len(response)) + response)


if __name__ == "__main__":
    udp = socketserver.ThreadingUDPServer(("0.0.0.0", 53), UDPHandler)
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", 53), TCPHandler)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    udp.serve_forever()
