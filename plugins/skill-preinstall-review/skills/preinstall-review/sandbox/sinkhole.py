"""Fake network inside the sandbox.

The container runs with --network none, so nothing can leave it. This module
answers DNS queries on 127.0.0.1:53 with 127.0.0.2 for every name, and listens
on a few common TCP ports. Every query and the first bytes of every
connection are logged, which is how the review learns which hosts a
candidate tried to reach and what it tried to send.
"""

import json
import socket
import struct
import threading
import time

SINK_IP = "127.0.0.2"
TCP_PORTS = (80, 443, 8080, 8443, 22, 25, 3000, 5000, 8000, 9000)
MAX_CAPTURE = 4096


class Sinkhole:
    def __init__(self, log_path):
        self._log_path = log_path
        self._lock = threading.Lock()
        self._sockets = []

    def _log(self, record):
        record["t"] = round(time.time(), 3)
        with self._lock:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")

    def start(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 53))
        self._sockets.append(udp)
        threading.Thread(target=self._dns_loop, args=(udp,), daemon=True).start()
        for port in TCP_PORTS:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.bind(("0.0.0.0", port))
            except OSError as exc:
                self._log({"kind": "sinkhole_error", "port": port, "error": str(exc)})
                continue
            srv.listen(16)
            self._sockets.append(srv)
            threading.Thread(target=self._tcp_loop, args=(srv, port), daemon=True).start()

    # DNS

    def _dns_loop(self, udp):
        while True:
            try:
                data, addr = udp.recvfrom(4096)
            except OSError:
                return
            try:
                name, qtype, end = _parse_query(data)
            except ValueError:
                self._log({"kind": "dns_malformed", "bytes": data[:256].hex()})
                continue
            self._log({"kind": "dns", "name": name, "qtype": qtype})
            udp.sendto(_dns_answer(data, qtype, end), addr)

    # TCP

    def _tcp_loop(self, srv, port):
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_tcp, args=(conn, port), daemon=True).start()

    def _handle_tcp(self, conn, port):
        conn.settimeout(2.0)
        chunks = []
        total = 0
        try:
            while total < MAX_CAPTURE:
                buf = conn.recv(MAX_CAPTURE - total)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                data = b"".join(chunks)
                if data[:1] != b"\x16" and b"\r\n\r\n" in data:
                    break
        except OSError:
            pass
        data = b"".join(chunks)
        record = {"kind": "tcp", "port": port, "bytes": len(data),
                  "payload": data.decode("latin-1")}
        if data[:1] == b"\x16":
            record["tls_sni"] = _parse_sni(data)
        elif data:
            first = data.split(b"\r\n", 1)[0].decode("latin-1")
            record["request_line"] = first
            for line in data.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    record["http_host"] = line[5:].strip().decode("latin-1")
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        self._log(record)
        conn.close()


def _parse_query(data):
    if len(data) < 12:
        raise ValueError("short")
    labels = []
    i = 12
    while True:
        if i >= len(data):
            raise ValueError("truncated")
        n = data[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise ValueError("compression in query")
        labels.append(data[i + 1:i + 1 + n].decode("latin-1"))
        i += 1 + n
    if i + 4 > len(data):
        raise ValueError("truncated")
    qtype = struct.unpack("!H", data[i:i + 2])[0]
    return ".".join(labels), qtype, i + 4


def _dns_answer(query, qtype, question_end):
    header = query[:2] + b"\x81\x80" + b"\x00\x01"
    question = query[12:question_end]
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(SINK_IP)
        return header + b"\x00\x01\x00\x00\x00\x00" + question + answer
    return header + b"\x00\x00\x00\x00\x00\x00" + question


def _parse_sni(data):
    """Return the server_name from a TLS ClientHello, or None."""
    try:
        i = 5 + 4 + 2 + 32
        sid_len = data[i]
        i += 1 + sid_len
        cs_len = struct.unpack("!H", data[i:i + 2])[0]
        i += 2 + cs_len
        comp_len = data[i]
        i += 1 + comp_len
        ext_total = struct.unpack("!H", data[i:i + 2])[0]
        i += 2
        end = i + ext_total
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", data[i:i + 4])
            i += 4
            if etype == 0:
                name_len = struct.unpack("!H", data[i + 3:i + 5])[0]
                return data[i + 5:i + 5 + name_len].decode("latin-1")
            i += elen
    except (IndexError, struct.error):
        return None
    return None
