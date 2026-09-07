#!/usr/bin/env python3
"""
I6 - CoAP Replay Tool
Real CoAP message assembly over UDP (CON/NON, token, blocks, options) with a
mocked loopback CoAP server for replay + injection testing. Standard-library only.
"""

import socket
import struct
import hashlib
import argparse
import sys
import os
import json
import threading
import time
import random
import re


VERSION = 1
TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
CODES = {
    0x01: "GET", 0x02: "POST", 0x03: "PUT", 0x04: "DELETE",
    0x41: "2.01 Created", 0x42: "2.02 Deleted", 0x43: "2.04 Changed",
    0x44: "2.05 Content", 0x45: "2.03 Not Modified",
    0x60: "4.00 Bad Request", 0x61: "4.01 Unauthorized",
    0x62: "4.02 Bad Option", 0x63: "4.03 Forbidden",
    0x64: "4.04 Not Found", 0x65: "4.05 Method Not Allowed",
    0x80: "5.00 Internal Server Error", 0x81: "5.01 Not Implemented",
    0x82: "5.02 Bad Gateway", 0x83: "5.03 Service Unavailable",
}
OPTION_NUMBERS = {
    1: "If-Match", 3: "Uri-Host", 4: "ETag", 5: "If-None-Match",
    7: "Uri-Port", 8: "Location-Path", 11: "Uri-Path", 12: "Content-Format",
    14: "Max-Age", 15: "Accept", 17: "Location-Query", 20: "Proxy-Uri",
    23: "Size1", 256: "Observe", 271: "Block2", 273: "Block1",
    308: "Size2", 65001: "No-Response",
}
METHODS = {0x01: "GET", 0x02: "POST", 0x03: "PUT", 0x04: "DELETE"}


def _decode_option_ext(ext, data, offset):
    if ext == 13:
        return 13 + data[offset], offset + 1
    elif ext == 14:
        return 269 + struct.unpack(">H", data[offset:offset + 2])[0], offset + 2
    return ext, offset


class CoAPMessage:
    def __init__(self, msg_type="CON", code="GET", token=None, payload=None):
        self.msg_type = TYPES.get(msg_type, msg_type)
        self.code_init = CODES.get(code, code) if isinstance(code, str) else code
        self.token = token if token is not None else b""
        self.message_id = random.randint(0, 0xFFFF)
        self.options = []
        self.payload = payload if payload is not None else b""
        self.content_format = None

    def is_request(self):
        return isinstance(self.code_init, int) and self.code_init < 0x40

    def type_int(self):
        for k, v in TYPES.items():
            if v == self.msg_type:
                return k
        return 0

    def code_int(self):
        for k, v in CODES.items():
            if v == self.code_init:
                return k
        if isinstance(self.code_init, int):
            return self.code_init
        return 0x01

    def add_option(self, opt_num, value):
        if isinstance(value, str):
            value = value.encode()
        if opt_num == 12 and self.content_format is None and isinstance(value, bytes):
            try:
                if len(value) == 1:
                    self.content_format = value[0]
                elif len(value) == 2:
                    self.content_format = struct.unpack(">H", value)[0]
            except (struct.error, IndexError):
                pass
        self.options.append((opt_num, value))

    def add_uri_path(self, path):
        for segment in path.strip("/").split("/"):
            if segment:
                self.add_option(11, segment)

    def add_observe(self, register=True):
        self.add_option(256, b"\x00" if register else b"\x01")

    def set_content_format(self, fmt):
        self.content_format = fmt
        self.add_option(12, struct.pack(">H", fmt))

    def encode(self):
        first_byte = (VERSION << 6) | (self.type_int() << 4) | len(self.token)
        code_byte = self.code_int()
        self.options.sort(key=lambda x: x[0])
        opts_encoded = b""
        prev_opt_num = 0
        for opt_num, opt_val in self.options:
            delta = opt_num - prev_opt_num
            length = len(opt_val)
            opts_encoded += self._encode_option_ext(delta, length) + opt_val
            prev_opt_num = opt_num
        header = struct.pack(">BBH", first_byte, code_byte, self.message_id)
        token_bytes = self.token[:8]
        out = header + token_bytes + opts_encoded
        if self.payload:
            out += struct.pack("B", 0xFF) + self.payload
        return out

    def _encode_option_ext(self, delta, length):
        d = delta & 0x0F
        l = length & 0x0F
        if 13 <= delta < 269:
            d = 13
        elif delta >= 269:
            d = 14
        if 13 <= length < 269:
            l = 13
        elif length >= 269:
            l = 14
        result = struct.pack("B", (d << 4) | l)
        if d == 13:
            result += struct.pack("B", delta - 13)
        elif d == 14:
            result += struct.pack(">H", delta - 269)
        if l == 13:
            result += struct.pack("B", length - 13)
        elif l == 14:
            result += struct.pack(">H", length - 269)
        return result

    @classmethod
    def decode(cls, data):
        if len(data) < 4:
            return None
        first_byte = data[0]
        version = (first_byte >> 6) & 0x03
        if version != 1:
            return None
        msg_type = (first_byte >> 4) & 0x03
        token_len = first_byte & 0x0F
        code_byte = data[1]
        msg_id = struct.unpack(">H", data[2:4])[0]
        token = data[4:4 + token_len]
        offset = 4 + token_len
        options = []
        prev_opt_num = 0
        while offset < len(data):
            b = data[offset]
            if b == 0xFF:
                offset += 1
                break
            delta_ext = (b >> 4) & 0x0F
            len_ext = b & 0x0F
            offset += 1
            delta, offset = _decode_option_ext(delta_ext, data, offset)
            length, offset = _decode_option_ext(len_ext, data, offset)
            opt_val = data[offset:offset + length]
            offset += length
            opt_num = prev_opt_num + delta
            options.append((opt_num, opt_val))
            prev_opt_num = opt_num
        payload = data[offset:]
        msg = cls()
        msg.msg_type = TYPES.get(msg_type, msg_type)
        msg.code_init = code_byte
        msg.token = token
        msg.message_id = msg_id
        msg.options = options
        msg.payload = payload
        return msg

    def get_option(self, opt_num):
        return [v for n, v in self.options if n == opt_num]

    def uri_path(self):
        parts = [v.decode(errors="ignore") for n, v in self.options if n == 11]
        return "/" + "/".join(parts)


class MockCoAPServer:
    """Loopback CoAP server over UDP that serves fixed resources."""

    RESOURCES = {
        "/time": b"23.450",
        "/temp": b"22.5",
        "/sensors": b"</sensors/temp>;rt=\"temperature\"",
        "/sensors/temp": b"22.5",
        "/actuators/led": b"OFF",
        "/.well-known/core": (
            b'</sensors/temp>;rt="temperature";ct=0,'
            b'</actuators/led>;rt="led";ct=0,'
            b'</time>;rt="time";ct=0'
        ),
    }

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        self.port = port
        self.sock = None
        self._thread = None
        self.running = False
        self.requests = []
        self.notify_count = 0

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                self._handle(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, data, addr):
        req = CoAPMessage.decode(data)
        if req is None:
            return
        self.requests.append(req)
        path = req.uri_path() or "/"
        self._send_response(req, addr, path)

    def _send_response(self, req, addr, path):
        resp = CoAPMessage("ACK", "2.05 Content", token=req.token)
        resp.message_id = req.message_id
        if path == "/actuators/led" and req.code_int() == 0x02:
            resp.code_init = 0x44
            resp.payload = b"OK"
        elif path in self.RESOURCES:
            resp.code_init = 0x44
            resp.payload = self.RESOURCES[path]
            if self._has_observe(req):
                self.notify_count += 1
        elif path == "/.well-known/core":
            resp.code_init = 0x44
            resp.payload = self.RESOURCES[path]
        else:
            resp.code_init = 0x64
            resp.payload = b"Not Found"
        # required: CoAP responses should not echo request path unless options needed
        self.sock.sendto(resp.encode(), addr)

    def _has_observe(self, req):
        return any(n == 256 for n, _ in req.options)


class CoAPClient:
    def __init__(self, host, port=5683, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout

    def send_receive(self, msg):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        data = msg.encode()
        sock.sendto(data, (self.host, self.port))
        try:
            resp_data, _ = sock.recvfrom(4096)
            return CoAPMessage.decode(resp_data)
        except socket.timeout:
            return None
        finally:
            sock.close()

    def get(self, path, observe=False):
        msg = CoAPMessage("CON", "GET", token=b"\xab\xcd")
        msg.add_uri_path(path)
        if observe:
            msg.add_observe(True)
        return self.send_receive(msg)

    def post(self, path, payload, content_format=0):
        msg = CoAPMessage("CON", "POST", token=b"\x01\x02")
        msg.add_uri_path(path)
        msg.set_content_format(content_format)
        msg.payload = payload.encode() if isinstance(payload, str) else payload
        return self.send_receive(msg)

    def put(self, path, payload, content_format=0):
        msg = CoAPMessage("CON", "PUT", token=b"\x03\x04")
        msg.add_uri_path(path)
        msg.set_content_format(content_format)
        msg.payload = payload.encode() if isinstance(payload, str) else payload
        return self.send_receive(msg)

    def delete(self, path):
        msg = CoAPMessage("CON", "DELETE", token=b"\x05\x06")
        msg.add_uri_path(path)
        return self.send_receive(msg)

    def replay(self, raw_packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.sendto(raw_packet, (self.host, self.port))
        try:
            resp_data, _ = sock.recvfrom(4096)
            return CoAPMessage.decode(resp_data)
        except socket.timeout:
            return None
        finally:
            sock.close()


def run_demo(host="127.0.0.1", report_dir="reports"):
    print("=== I6 - CoAP Replay Tool (Offline Demo) ===")
    server = MockCoAPServer(host, 0)
    server_port = server.start()
    print("[+] Mock CoAP server on 127.0.0.1:%d" % server_port)

    results = {"host": host, "port": server_port, "messages": [], "errors": []}
    client = CoAPClient(host, server_port, timeout=2)

    try:
        print("\n[*] GET /sensors/temp...")
        resp = client.get("/sensors/temp")
        if resp:
            print("[+] GET /sensors/temp -> %s (%d bytes): %s" % (
                resp_code_label(resp), len(resp.payload),
                resp.payload.decode(errors="ignore")))
            results["messages"].append({"method": "GET", "path": "/sensors/temp",
                                        "code": resp_code_label(resp),
                                        "payload": resp.payload.decode(errors="ignore")})
        else:
            results["messages"].append({"method": "GET", "path": "/sensors/temp", "code": "no-response"})

        print("\n[*] POST /actuators/led (injection)...")
        resp2 = client.post("/actuators/led", "ON")
        if resp2:
            print("[+] %s (%d bytes): %s" % (resp_code_label(resp2),
                                             len(resp2.payload), resp2.payload.decode(errors="ignore")))
            results["messages"].append({"method": "POST", "path": "/actuators/led",
                                        "code": resp_code_label(resp2)})

        print("\n[*] GET /.well-known/core (resource discovery)...")
        resp3 = client.get("/.well-known/core")
        if resp3:
            print("[+] %s -> %s" % (resp_code_label(resp3),
                                    resp3.payload.decode(errors="ignore")))
            results["messages"].append({"method": "GET", "path": "/.well-known/core",
                                        "code": resp_code_label(resp3)})

        print("\n[*] Replay captured packet (CON GET /time)...")
        captured = CoAPMessage("CON", "GET", token=b"\x99")
        captured.add_uri_path("/time")
        raw = captured.encode()
        print("[+] Captured %d bytes: %s" % (len(raw), raw.hex()))
        replay_resp = client.replay(raw)
        if replay_resp:
            print("[+] Replay -> %s: %s" % (resp_code_label(replay_resp),
                                            replay_resp.payload.decode(errors="ignore")))
            results["replay"] = {"raw": raw.hex(),
                                 "code": resp_code_label(replay_resp),
                                 "payload": replay_resp.payload.decode(errors="ignore")}

        print("\n[*] Observe registration (abuse check)...")
        msg = CoAPMessage("CON", "GET", token=b"\x70")
        msg.add_uri_path("/sensors/temp")
        msg.add_observe(True)
        obs_resp = client.send_receive(msg)
        results["observe"] = {"registered": server.notify_count > 0,
                              "server_observations": server.notify_count}
        if server.notify_count > 0:
            print("[+] Observe option reached server")

        print("\n[*] Block transfer check (CON GET /time with Block2)...")
        block_msg = CoAPMessage("CON", "GET", token=b"\x11")
        block_msg.add_uri_path("/time")
        block_msg.add_option(271, struct.pack(">B", 0x00))  # Block2 num=0 more=0 size=16
        block_response = client.send_receive(block_msg)
        if block_response:
            print("[+] Blocked GET -> %s" % resp_code_label(block_response))
            results["block"] = resp_code_label(block_response)

    except Exception as e:
        results["errors"].append(str(e))
        print("[-] Demo error: %s" % e)
    finally:
        server.stop()

    os.makedirs(report_dir, exist_ok=True)
    rpath = os.path.join(report_dir, "i6_demo_report.json")
    with open(rpath, "w") as f:
        json.dump(results, f, indent=2)
    print("\n[+] Report: %s" % rpath)
    print("[+] Demo complete — exit 0")
    return 0


def resp_code_label(resp):
    if resp is None:
        return "no-response"
    return CODES.get(resp.code_int(), "0x%02X" % resp.code_int())


class ObserveAbuser:
    def __init__(self, client):
        self.client = client
        self.captured = []

    def register_observers(self, path, count=5):
        for i in range(count):
            resp = self.client.get(path, observe=True)
            if resp:
                self.captured.append(resp.token.hex())
        return self.captured

    def forge_notification(self, observer_msg, new_payload):
        forged = CoAPMessage("CON", "2.05 Content", token=observer_msg.token)
        forged.add_option(256, b"\x01")
        forged.set_content_format(0)
        forged.payload = new_payload.encode()
        return forged


class ResourceEnumerator:
    COMMON_PATHS = [
        "/", "/.well-known/core", "/sensors", "/actuators",
        "/temperature", "/humidity", "/light", "/led",
        "/config", "/status", "/info", "/version",
        "/ota", "/firmware", "/update",
    ]

    def __init__(self, client):
        self.client = client

    def discover(self, base_path=".well-known/core"):
        resp = self.client.get(base_path)
        if resp and resp.payload:
            return self._parse_link_format(resp.payload.decode(errors="ignore"))
        return []

    def brute_paths(self, paths=None):
        paths = paths or self.COMMON_PATHS
        found = []
        for path in paths:
            resp = self.client.get(path)
            if resp and resp.code_int() < 0x60:
                found.append(path)
        return found

    def _parse_link_format(self, data):
        resources = []
        entries = []
        current = ""
        in_quotes = False
        for ch in data:
            if ch == '"':
                in_quotes = not in_quotes
            if ch == "," and not in_quotes:
                entries.append(current)
                current = ""
            else:
                current += ch
        if current.strip():
            entries.append(current)
        for e in entries:
            m = re.match(r"<([^>]+)>(.*)", e.strip())
            if m:
                resources.append({"path": m.group(1), "attrs": m.group(2)})
        return resources


def main():
    parser = argparse.ArgumentParser(
        description="I6 - CoAP Replay Tool (educational, authorized use only)",
        epilog="Example: python3 coap_replay.py 127.0.0.1 -p 5683 --get /sensors/temp",
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo with loopback mock CoAP server")
    parser.add_argument("host", nargs="?", default="127.0.0.1",
                        help="Target CoAP server (default 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=5683,
                        help="CoAP port (default 5683)")
    parser.add_argument("-t", "--timeout", type=int, default=3,
                        help="Timeout seconds")
    parser.add_argument("--get", help="GET request to path")
    parser.add_argument("--post", nargs=2, metavar=("PATH", "DATA"),
                        help="POST data to path")
    parser.add_argument("--put", nargs=2, metavar=("PATH", "DATA"),
                        help="PUT data to path")
    parser.add_argument("--delete", help="DELETE path")
    parser.add_argument("--observe", action="store_true",
                        help="Register observe on --get path")
    parser.add_argument("--abuse-observe", nargs=2, metavar=("PATH", "COUNT"),
                        help="Register multiple observers")
    parser.add_argument("--enumerate", action="store_true",
                        help="Enumerate resources via .well-known/core")
    parser.add_argument("--brute", action="store_true",
                        help="Brute-force common paths")
    parser.add_argument("--replay", nargs="+", metavar="HEX",
                        help="Replay raw CoAP packets (hex-encoded)")
    parser.add_argument("--craft", nargs=3, metavar=("TYPE", "CODE", "PATH"),
                        help="Craft a raw packet")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("--json", action="store_true",
                        help="Write JSON report to reports/")
    parser.add_argument("--report-dir", default="reports",
                        help="Report output directory (default reports/)")
    args = parser.parse_args()

    if args.demo:
        sys.exit(run_demo(report_dir=args.report_dir))

    if not any([args.get, args.post, args.put, args.delete, args.abuse_observe,
                args.enumerate, args.brute, args.replay, args.craft]):
        parser.print_help()
        sys.exit(0)

    client = CoAPClient(args.host, args.port, args.timeout)
    results = {"host": args.host, "port": args.port, "messages": []}

    if args.get:
        resp = client.get(args.get, observe=args.observe)
        if resp:
            print("[GET %s] %s" % (args.get, resp_code_label(resp)))
            if resp.payload:
                print("Payload (%d bytes): %s" % (
                    len(resp.payload), resp.payload.decode(errors="ignore")[:500]))
            if args.verbose:
                print("  Token: %s" % resp.token.hex())
                print("  Type: %s, MID: %d" % (resp.msg_type, resp.message_id))
            results["messages"].append({"method": "GET", "path": args.get,
                                        "code": resp_code_label(resp)})
        else:
            print("No response")

    if args.post:
        path, data = args.post
        resp = client.post(path, data)
        if resp:
            print("[POST %s] %s" % (path, resp_code_label(resp)))
            if resp.payload:
                print("Payload: %s" % resp.payload.decode(errors="ignore")[:500])
            results["messages"].append({"method": "POST", "path": path,
                                        "code": resp_code_label(resp)})

    if args.put:
        path, data = args.put
        resp = client.put(path, data)
        if resp:
            print("[PUT %s] %s" % (path, resp_code_label(resp)))
            if resp.payload:
                print("Payload: %s" % resp.payload.decode(errors="ignore")[:500])

    if args.delete:
        resp = client.delete(args.delete)
        if resp:
            print("[DELETE %s] %s" % (args.delete, resp_code_label(resp)))

    if args.abuse_observe:
        path, count = args.abuse_observe
        abuser = ObserveAbuser(client)
        tokens = abuser.register_observers(path, int(count))
        print("[*] Registered %d observer(s), tokens: %s" % (len(tokens), tokens))

    if args.enumerate:
        enumerator = ResourceEnumerator(client)
        resources = enumerator.discover()
        print("[*] Discovered %d resource(s):" % len(resources))
        for r in resources:
            print("    %s" % r)
        results["resources"] = resources

    if args.brute:
        enumerator = ResourceEnumerator(client)
        found = enumerator.brute_paths()
        print("[*] Brute-force found %d accessible path(s):" % len(found))
        for p in found:
            print("    [+] %s" % p)

    if args.replay:
        packets = [bytes.fromhex(h) for h in args.replay]
        print("[*] Replaying %d captured packet(s)" % len(packets))
        for i, pkt in enumerate(packets):
            resp = client.replay(pkt)
            if resp:
                print("  Replay %d: %s (%d bytes)" % (i + 1, resp_code_label(resp),
                                                      len(resp.payload)))
            else:
                print("  Replay %d: no response" % (i + 1))

    if args.craft:
        msg_type, code, path = args.craft
        msg = CoAPMessage(msg_type, code)
        msg.add_uri_path(path)
        raw = msg.encode()
        print("Crafted packet (%d bytes): %s" % (len(raw), raw.hex()))
        resp = client.replay(raw)
        if resp:
            print("Response: %s" % resp_code_label(resp))
            if resp.payload:
                print("Payload: %s" % resp.payload.decode(errors="ignore")[:500])

    if args.json:
        os.makedirs(args.report_dir, exist_ok=True)
        rpath = os.path.join(args.report_dir, "i6_report.json")
        with open(rpath, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print("\n[+] Report: %s" % rpath)

    sys.exit(0)


if __name__ == "__main__":
    main()