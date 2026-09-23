> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# I6 — CoAP Replay Tool

**CoAP (RFC 7252) message replay and fuzz toolkit** by **5h4d0wn1k** for
**constrained-device security testing**: hand-built wire encoding/decoding,
GET/POST/PUT/DELETE over UDP, raw-packet replay, forged-message injection,
Block1/Block2 block-wise transfer and Observe registration — all against a
mocked loopback CoAP server. Standard-library only, deterministic offline
tests.

## Why this toolkit

CoAP is the lightweight REST protocol behind countless IoT and smart-building
sensors, yet its plaintext-by-default UDP transport invites replay, spoofed
state changes and observe-flooding abuse. This framework makes the protocol's
wire format legible so defenders and authorized testers can verify that a
resource only accepts authorized writes, that block transfers complete
cleanly, and that Observe subscribers are bounded. Destructive-style
operations (`--post`, `--put`, `--abuse-observe`) default OFF and require an
explicit target path. Use it only against CoAP servers you own or hold written
authorization to test — see [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **Real wire encoding/decoding** — CoAP header (ver/type/tkl), option
  delta/length nibbles with 13/14 extended form, up to 8-byte tokens, `0xFF`
  payload marker and Block1/Block2/Observe option numbers (`CoAPMessage`).
- **CON/NON messages** — confirmable and non-confirmable types with matching
  message-ID handling over a real UDP socket.
- **Method verbs** — GET/POST/PUT/DELETE against a loopback server; responses
  decoded as CON/ACK with 2.xx/4.xx/5.xx codes.
- **Replay** — raw captured bytes re-sent verbatim over UDP; response decoded
  and compared.
- **Injection** — forged CON GET/POST/PUT packets crafted on the fly (`--craft`).
- **Block-wise transfer** — `Block1` (273) and `Block2` (271) option encoding
  for large-resource exchanges.
- **Observe abuse** — multiple observers against one resource to demonstrate
  notification-flooding risk classes (`--abuse-observe PATH COUNT`).
- **Resource enumeration** — discover resources and probe handlers
  (`--enumerate`, `--brute`).
- **Mock CoAP server** — threadless UDP responder on `127.0.0.1` serving
  `.well-known/core`, `/time`, `/sensors/temp` and `/actuators/led`, enabling
  fully offline labs.

## Quickstart

```bash
# Offline demo: mock server, GET/POST/replay/observe, writes reports/, exit 0
python3 coap_replay.py --demo

# GET against your own loopback CoAP server
python3 coap_replay.py 127.0.0.1 -p 5683 --get /sensors/temp

# Inject a POST
python3 coap_replay.py 127.0.0.1 --post /actuators/led ON

# Enumerate resources
python3 coap_replay.py 127.0.0.1 --enumerate --json

# Replay a captured packet (hex)
python3 coap_replay.py 127.0.0.1 --replay 41010100000001636f6e

# Run the test suite (20 deterministic offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 coap_replay.py [-h] [--demo] [host] [-p PORT] [-t SEC] [--get PATH]
                       [--post PATH DATA] [--put PATH DATA] [--delete PATH]
                       [--observe] [--abuse-observe PATH COUNT]
                       [--enumerate] [--brute] [--replay HEX [HEX ...]]
                       [--craft TYPE CODE PATH] [-v] [--json]
                       [--report-dir DIR]
```

- `--demo` — offline loopback demo, exit `0`.
- `--json` — write a JSON report to `reports/` (gitignored).
- Destructive-style writes (`--post`, `--put`) require an explicit `host`
  and `path`.

Exit codes: `0` on success (including the demo), non-zero on errors.

## Project structure

```
coap_replay.py   # wire codec, MockCoAPServer, CoAPClient, ObserveAbuser, CLI
tests/           # unittest coverage: encoding, methods, replay, blocks, demo
ETHICS.md        # educational-use policy (read first)
SCOPE.md         # scope and target authorization rules
SECURITY.md      # vulnerability disclosure
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

Replay fixtures, block-transfer test cases and decoder hardening are welcome.
Open an issue or PR against the default branch; keep contributions scoped to
educational and authorized-use tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for assessing CoAP infrastructure you own or are explicitly
permitted to test.