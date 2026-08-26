#!/usr/bin/env python3
"""CoAP Replay Tool - Packet crafting, GET/POST/PUT replay, observe abuse, resource enumeration."""

import socket
import struct
import hashlib
import argparse
import sys
import time
import random


class CoAPMessage:
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

    def __init__(self, msg_type="CON", code="GET", token=None, payload=None):
        self.msg_type = self.TYPES.get(msg_type, msg_type) if isinstance(msg_type, str) else msg_type
        self.code = self.CODES.get(code, code) if isinstance(code, str) else code
        self.token = token or random.randbytes(random.randint(0, 8))
        self.message_id = random.randint(0, 0xFFFF)
        self.options = []
        self.payload = payload or b""
        self.content_format = None

    @property
    def type_int(self):
        for k, v in self.TYPES.items():
            if v == self.msg_type:
                return k
        return 0

    @property
    def code_int(self):
        for k, v in self.CODES.items():
            if v == self.code:
                return k
        if isinstance(self.code, int):
            return self.code
        return 0x01

    def add_option(self, opt_num, value):
        if isinstance(value, str):
            value = value.encode()
        if opt_num == 12 and self.content_format is None:
            self.content_format = value
        self.options.append((opt_num, value))

    def add_uri_path(self, path):
        for segment in path.strip("/").split("/"):
            self.add_option(11, segment)

    def add_uri_host(self, host):
        self.add_option(3, host)

    def add_observe(self, register=True):
        val = b"\x00" if register else b"\x01"
        self.add_option(256, val)

    def set_content_format(self, fmt):
        self.content_format = fmt
        self.add_option(12, struct.pack(">H", fmt) if isinstance(fmt, int) else fmt)

    def encode(self):
        first_byte = (self.VERSION << 6) | (self.type_int << 4) | len(self.token)
        code_byte = self.code_int
        self.options.sort(key=lambda x: x[0])
        opts_encoded = b""
        prev_opt_num = 0
        for opt_num, opt_val in self.options:
            delta = opt_num - prev_opt_num
            length = len(opt_val)
            opts_encoded += self._encode_option_ext(delta, length) + opt_val
            prev_opt_num = opt_num
        marker = 0xFF
        header = struct.pack(">BBH", first_byte, code_byte, self.message_id)
        token_bytes = self.token[:8]
        return header + token_bytes + opts_encoded + (b"" if not self.payload else struct.pack("B", marker) + self.payload)

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
        header = (d << 4) | l
        result = struct.pack("B", header)
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
            if delta_ext == 13:
                delta = 13 + data[offset]; offset += 1
            elif delta_ext == 14:
                delta = 269 + struct.unpack(">H", data[offset:offset + 2])[0]; offset += 2
            else:
                delta = delta_ext
            if len_ext == 13:
                length = 13 + data[offset]; offset += 1
            elif len_ext == 14:
                length = 269 + struct.unpack(">H", data[offset:offset + 2])[0]; offset += 2
            else:
                length = len_ext
            opt_val = data[offset:offset + length]
            offset += length
            opt_num = prev_opt_num + delta
            options.append((opt_num, opt_val))
            prev_opt_num = opt_num
        payload = data[offset:] if offset < len(data) else b""
        msg = cls()
        msg.msg_type = cls.TYPES.get(msg_type, msg_type)
        msg.code_int = code_byte
        msg.token = token
        msg.message_id = msg_id
        msg.options = options
        msg.payload = payload
        return msg


class CoAPClient:
    def __init__(self, host, port=5683, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_receive(self, msg):
        self.connect()
        data = msg.encode()
        self.sock.sendto(data, (self.host, self.port))
        try:
            resp_data, addr = self.sock.recvfrom(4096)
            self.close()
            return CoAPMessage.decode(resp_data), addr
        except socket.timeout:
            self.close()
            return None, None

    def get(self, path, observe=False):
        msg = CoAPMessage("CON", "GET")
        msg.add_uri_path(path)
        if observe:
            msg.add_observe(True)
        return self.send_receive(msg)

    def post(self, path, payload, content_format=0):
        msg = CoAPMessage("CON", "POST")
        msg.add_uri_path(path)
        msg.set_content_format(content_format)
        msg.payload = payload.encode() if isinstance(payload, str) else payload
        return self.send_receive(msg)

    def put(self, path, payload, content_format=0):
        msg = CoAPMessage("CON", "PUT")
        msg.add_uri_path(path)
        msg.set_content_format(content_format)
        msg.payload = payload.encode() if isinstance(payload, str) else payload
        return self.send_receive(msg)

    def delete(self, path):
        msg = CoAPMessage("CON", "DELETE")
        msg.add_uri_path(path)
        return self.send_receive(msg)

    def replay(self, raw_packet):
        self.connect()
        self.sock.sendto(raw_packet, (self.host, self.port))
        try:
            resp_data, addr = self.sock.recvfrom(4096)
            self.close()
            return CoAPMessage.decode(resp_data), addr
        except socket.timeout:
            self.close()
            return None, None


class ObserveAbuser:
    def __init__(self, client):
        self.client = client
        self.captured = []

    def register_observers(self, path, count=5):
        print(f"[*] Registering {count} observers on {path}")
        for i in range(count):
            resp, addr = self.client.get(path, observe=True)
            if resp:
                token_hex = resp.token.hex()
                print(f"  Observer {i + 1}: token={token_hex}, type={resp.msg_type}")
                self.captured.append(resp)
            else:
                print(f"  Observer {i + 1}: no response")
            time.sleep(0.2)

    def forge_notification(self, observer_msg, new_payload):
        forged = CoAPMessage("CON", "2.05 Content")
        forged.token = observer_msg.token
        forged.message_id = random.randint(0, 0xFFFF)
        forged.add_option(256, b"\x01")
        forged.set_content_format(0)
        forged.payload = new_payload.encode() if isinstance(new_payload, str) else new_payload
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
        print(f"[*] Discovering resources via {base_path}")
        resp, _ = self.client.get(base_path)
        if resp and resp.payload:
            resources = self._parse_link_format(resp.payload.decode(errors="ignore"))
            print(f"  Found {len(resources)} resource(s):")
            for r in resources:
                print(f"    {r}")
            return resources
        print("  No resources found via core link format")
        return []

    def brute_paths(self, paths=None):
        paths = paths or self.COMMON_PATHS
        print(f"[*] Brute-forcing {len(paths)} paths...")
        found = []
        for path in paths:
            resp, _ = self.client.get(path)
            if resp and not resp.is_error():
                status = resp.code_int
                label = CoAPMessage.CODES.get(status, str(status))
                print(f"  [+] {path} -> {label} ({len(resp.payload)} bytes)")
                found.append((path, resp))
            else:
                print(f"  [-] {path} -> no response")
            time.sleep(0.1)
        return found

    def _parse_link_format(self, data):
        resources = []
        for match in __import__("re").finditer(r'<([^>]+)>((?:;[^>]+)*)', data):
            path = match.group(1)
            attrs = match.group(2)
            resources.append({"path": path, "attrs": attrs})
        return resources

    def _is_error(self):
        return self.code_int >= 0x60


def replay_captures(client, packets):
    print(f"[*] Replaying {len(packets)} captured packet(s)")
    for i, pkt in enumerate(packets):
        resp, addr = client.replay(pkt)
        if resp:
            code = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"  Replay {i + 1}: {code} ({len(resp.payload)} bytes)")
        else:
            print(f"  Replay {i + 1}: no response")


def main():
    parser = argparse.ArgumentParser(description="CoAP Replay Tool")
    parser.add_argument("host", nargs="?", help="Target CoAP server")
    parser.add_argument("-p", "--port", type=int, default=5683, help="CoAP port (default 5683)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds")
    parser.add_argument("--get", help="GET request to path")
    parser.add_argument("--post", nargs=2, metavar=("PATH", "DATA"), help="POST data to path")
    parser.add_argument("--put", nargs=2, metavar=("PATH", "DATA"), help="PUT data to path")
    parser.add_argument("--delete", help="DELETE path")
    parser.add_argument("--observe", action="store_true", help="Register observe on --get path")
    parser.add_argument("--abuse-observe", nargs=2, metavar=("PATH", "COUNT"), help="Register multiple observers")
    parser.add_argument("--enumerate", action="store_true", help="Enumerate resources")
    parser.add_argument("--brute", action="store_true", help="Brute-force common paths")
    parser.add_argument("--replay", nargs="+", metavar="HEX", help="Replay raw CoAP packets (hex-encoded)")
    parser.add_argument("--craft", nargs=3, metavar=("TYPE", "CODE", "PATH"), help="Craft a raw packet")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not args.host:
        parser.print_help()
        return

    client = CoAPClient(args.host, args.port, args.timeout)

    if args.get:
        resp, addr = client.get(args.get, observe=args.observe)
        if resp:
            code = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"[GET {args.get}] {code}")
            if resp.payload:
                print(f"Payload ({len(resp.payload)} bytes): {resp.payload.decode(errors='ignore')[:500]}")
            if args.verbose:
                print(f"  Token: {resp.token.hex()}")
                print(f"  Type: {resp.msg_type}, MID: {resp.message_id}")
        else:
            print("No response")

    if args.post:
        path, data = args.post
        resp, _ = client.post(path, data)
        if resp:
            code = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"[POST {path}] {code}")
            if resp.payload:
                print(f"Payload: {resp.payload.decode(errors='ignore')[:500]}")

    if args.put:
        path, data = args.put
        resp, _ = client.put(path, data)
        if resp:
            code = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"[PUT {path}] {code}")
            if resp.payload:
                print(f"Payload: {resp.payload.decode(errors='ignore')[:500]}")

    if args.delete:
        resp, _ = client.delete(args.delete)
        if resp:
            code = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"[DELETE {args.delete}] {code}")

    if args.abuse_observe:
        path, count = args.abuse_observe
        abuser = ObserveAbuser(client)
        abuser.register_observers(path, int(count))

    if args.enumerate:
        enumerator = ResourceEnumerator(client)
        enumerator.discover()

    if args.brute:
        enumerator = ResourceEnumerator(client)
        enumerator.brute_paths()

    if args.replay:
        packets = [bytes.fromhex(h) for h in args.replay]
        replay_captures(client, packets)

    if args.craft:
        msg_type, code, path = args.craft
        msg = CoAPMessage(msg_type, code)
        msg.add_uri_path(path)
        raw = msg.encode()
        print(f"Crafted packet ({len(raw)} bytes): {raw.hex()}")
        resp, _ = client.replay(raw)
        if resp:
            rcode = CoAPMessage.CODES.get(resp.code_int, f"0x{resp.code_int:02X}")
            print(f"Response: {rcode}")
            if resp.payload:
                print(f"Payload: {resp.payload.decode(errors='ignore')[:500]}")

    if not any([args.get, args.post, args.put, args.delete, args.abuse_observe, args.enumerate, args.brute, args.replay, args.craft]):
        parser.print_help()


if __name__ == "__main__":
    main()
