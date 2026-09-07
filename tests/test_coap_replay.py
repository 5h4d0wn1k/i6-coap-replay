#!/usr/bin/env python3
"""Deterministic offline tests for I6 - CoAP replay tool (loopback UDP mock)."""

import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import coap_replay as i6
from coap_replay import (
    CoAPMessage, CoAPClient, MockCoAPServer, ResourceEnumerator,
    run_demo,
)


class TestMessageEncodeDecode(unittest.TestCase):
    def test_roundtrip_confirmable_get(self):
        msg = CoAPMessage("CON", "GET", token=b"\xaa\xbb")
        msg.add_uri_path("/sensors/temp")
        msg.message_id = 0x1234
        raw = msg.encode()
        decoded = CoAPMessage.decode(raw)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.msg_type, "CON")
        self.assertEqual(decoded.code_int(), 0x01)  # GET
        self.assertEqual(decoded.message_id, 0x1234)
        self.assertEqual(decoded.token, b"\xaa\xbb")
        self.assertEqual(decoded.uri_path(), "/sensors/temp")

    def test_header_version_and_type_bits(self):
        """First byte: ver=01 type=00(con) tkl=2 -> 0x42."""
        msg = CoAPMessage("CON", "GET", token=b"\x01\x02")
        raw = msg.encode()
        self.assertEqual(raw[0] >> 6, 1)
        self.assertEqual((raw[0] >> 4) & 0x03, 0)
        self.assertEqual(raw[0] & 0x0F, 2)

    def test_non_confirmable_type(self):
        msg = CoAPMessage("NON", "POST")
        self.assertEqual(msg.type_int(), 1)
        raw = msg.encode()
        self.assertEqual((raw[0] >> 4) & 0x03, 1)

    def test_payload_marker(self):
        msg = CoAPMessage("CON", "POST", payload=b"hello")
        raw = msg.encode()
        self.assertEqual(raw[4:], b"\xffhello")

    def test_option_extended_delta(self):
        """Observe (option 256) needs extended delta encoding."""
        msg = CoAPMessage("CON", "GET")
        msg.add_uri_path("/x")
        msg.add_observe(True)
        raw = msg.encode()
        decoded = CoAPMessage.decode(raw)
        self.assertIsNotNone(decoded)
        observe_opts = decoded.get_option(256)
        self.assertEqual(len(observe_opts), 1)
        self.assertEqual(observe_opts[0], b"\x00")


class TestResourcePaths(unittest.TestCase):
    def test_uri_path_encoding(self):
        msg = CoAPMessage("CON", "GET")
        msg.add_uri_path("/a/b/c")
        raw = msg.encode()
        decoded = CoAPMessage.decode(raw)
        self.assertEqual(decoded.uri_path(), "/a/b/c")

    def test_empty_path(self):
        msg = CoAPMessage("CON", "GET")
        raw = msg.encode()
        decoded = CoAPMessage.decode(raw)
        self.assertEqual(decoded.uri_path(), "/")


class TestBlockOption(unittest.TestCase):
    def test_block1_option_encodes(self):
        """Block1 num=0 more=0 size=16 -> option 273, value 0x00."""
        msg = CoAPMessage("CON", "POST")
        msg.add_uri_path("/big")
        msg.add_option(273, struct.pack(">B", 0x00))
        raw = msg.encode()
        decoded = CoAPMessage.decode(raw)
        blocks = decoded.get_option(273)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0][0], 0)

    def test_block2_szx(self):
        msg = CoAPMessage("CON", "GET")
        msg.add_option(271, struct.pack(">B", 0x20))  # szx=2 (16 bytes), num=0
        decoded = CoAPMessage.decode(msg.encode())
        self.assertEqual(decoded.get_option(271)[0], b"\x20")


class TestMockServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockCoAPServer("127.0.0.1", 0)
        cls.port = cls.server.start()
        cls.client = CoAPClient("127.0.0.1", cls.port, timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_get_resource(self):
        resp = self.client.get("/time")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code_int(), 0x44)  # 2.05 Content
        self.assertEqual(resp.payload, b"23.450")

    def test_get_not_found(self):
        resp = self.client.get("/nonexistent")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code_int(), 0x64)  # 4.04 Not Found

    def test_post_injection(self):
        resp = self.client.post("/actuators/led", "ON")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code_int(), 0x44)  # 2.05 Content
        self.assertEqual(resp.payload, b"OK")

    def test_response_matches_request_token(self):
        resp = self.client.get("/temp")
        self.assertEqual(resp.token, b"\xab\xcd")  # client.get token

    def test_observe_reaches_server(self):
        before = self.server.notify_count
        msg = CoAPMessage("CON", "GET", token=b"\x70")
        msg.add_uri_path("/sensors/temp")
        msg.add_observe(True)
        resp = self.client.send_receive(msg)
        self.assertIsNotNone(resp)
        self.assertGreater(self.server.notify_count, before)

    def test_resource_enumeration(self):
        en = ResourceEnumerator(self.client)
        resources = en.discover()
        self.assertGreaterEqual(len(resources), 3)

    def test_brute_paths(self):
        en = ResourceEnumerator(self.client)
        found = en.brute_paths()
        self.assertIn("/sensors", found)
        self.assertIn("/.well-known/core", found)


class TestReplayAndInjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = MockCoAPServer("127.0.0.1", 0)
        cls.port = cls.server.start()
        cls.client = CoAPClient("127.0.0.1", cls.port, timeout=2)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_replay_captured_packet(self):
        captured = CoAPMessage("CON", "GET", token=b"\x99")
        captured.add_uri_path("/time")
        original = captured.encode()
        resp = self.client.replay(original)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code_int(), 0x44)
        self.assertEqual(resp.payload, b"23.450")

    def test_inject_forged_get(self):
        forged = CoAPMessage("CON", "GET", token=b"\x77")
        forged.add_uri_path("/temp")
        raw = forged.encode()
        resp = self.client.replay(raw)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.payload, b"22.5")

    def test_crafted_delete(self):
        forged = CoAPMessage("CON", "DELETE", token=b"\x66")
        forged.add_uri_path("/actuators/led")
        resp = self.client.replay(forged.encode())
        self.assertIsNotNone(resp)


class TestDemo(unittest.TestCase):
    def test_demo_exits_zero_with_report(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            rc = run_demo(report_dir=os.path.join(tmp, "reports"))
            self.assertEqual(rc, 0)
            rpath = os.path.join(tmp, "reports", "i6_demo_report.json")
            self.assertTrue(os.path.exists(rpath))
            with open(rpath) as f:
                data = json.load(f)
            self.assertGreaterEqual(len(data["messages"]), 1)
            self.assertTrue(data.get("replay"))
            self.assertEqual(data["replay"]["payload"], "23.450")


if __name__ == "__main__":
    unittest.main()