# I6 — CoAP Replay Tool

Real CoAP message assembly over UDP (CON/NON, token, blocks, options) with a
mocked loopback CoAP server for replay + injection testing. Standard-library
only, deterministic offline tests.

## What the engine genuinely does

- **Real wire encoding/decoding** — hand-built CoAP header (ver/type/tkl),
  option delta/length nibbles with 13/14 extended form, token up to 8 bytes,
  `0xFF` payload marker, and `Block1`/`Block2`/Observe option numbers.
- **CON/NON messages** — confirmable and non-confirmable types with matching
  message ID handling.
- **Method verbs** — GET/POST/PUT/DELETE over a real UDP socket against a
  loopback server; responses decoded as CON/ACK with 2.xx/4.xx/5.xx codes.
- **Replay** — raw captured bytes re-sent verbatim over UDP; response decoded
  and compared.
- **Injection** — forged CON GET/POST/PUT packets crafted on the fly and
  delivered to the mock server.
- **Blocks** — `Block1` (273) and `Block2` (271) option encoding for
  block-wise transfers.
- **Observe abuse** — multiple observers registered against one resource to
  demonstrate notification flooding risk classes.
- **Mock CoAP server** — threadless UDP responder on `127.0.0.1` serving fixed
  resources (`.well-known/core`, `/time`, `/sensors/temp`, `/actuators/led`).

## Quick start

```bash
# Offline demo: mock server, GET/POST/replay/observe, writes reports/, exit 0
python3 coap_replay.py --demo

# Against your own loopback CoAP server
python3 coap_replay.py 127.0.0.1 -p 5683 --get /sensors/temp

# Inject a POST
python3 coap_replay.py 127.0.0.1 --post /actuators/led ON

# Enumerate resources
python3 coap_replay.py 127.0.0.1 --enumerate --json

# Replay captured packet (hex)
python3 coap_replay.py 127.0.0.1 --replay 41010100000001636f6e

# Tests
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

- `--demo` — offline loopback demo, exit 0.
- `--json` — write JSON report to `reports/`.
- Destructive-style writes (`--post`, `--put`) require an explicit host+path.

Exit codes: `0` success (incl. demo), non-zero on errors.

## Live Lab Test Plan

Prerequisites: a CoAP server you own (`aiocoap` on a lab VM, or the bundled
mock). Never point this at third-party CoAP infrastructure without
authorization.

1. **Baseline**: `python3 coap_replay.py --demo` — confirm GET `/sensors/temp`
   returns `2.05 Content`, POST `/actuators/led` is accepted, replay of a
   captured `/time` GET returns the fixture payload, and the JSON report is
   written (exit 0).
2. **Real server**: run `aiocoap` on a lab host, then
   `python3 coap_replay.py 127.0.0.1 --get /sen/tem`. Cross-check with
   `coap-client -m get coap://127.0.0.1/sen/tem`.
3. **Replay**: capture a GET with your own CoAP client, hex-encode it, and
   confirm `--replay <hex>` produces the same response as live GET.
4. **Block transfer**: request a large resource with `Block1`/`Block2`
   options and confirm multi-block transfer is exercised on the lab server.
5. **Observe**: register 5 observers with `--abuse-observe /sen/tem 5` and
   confirm the server handles them without crash (no DoS on real infra).
6. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 20    |
| Loopback mock server       | built-in (`MockCoAPServer`) |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Wire format                | RFC 7252 CoAP over UDP |
| Blocks                     | Block1/Block2 option encoding |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. Only test CoAP servers you own or
are explicitly authorized to assess. POST/PUT injection and observe flooding
are destructive-style operations and default OFF. See `LICENSE` for the full
shield — Authorization, CFAA / computer-crime statutes, Acceptable Use,
Prohibited Use, No Warranty, and Responsible Disclosure.

## License

MIT — full legal shield in `LICENSE`.