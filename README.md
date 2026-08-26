# I6 — CoAP Replay Tool

CoAP packet crafting, GET/POST/PUT replay, observe abuse, and resource enumeration tool.

## Overview

This project implements a CoAP protocol exploitation tool that:
- Crafts and decodes CoAP messages
- Sends GET, POST, PUT, DELETE requests
- Replays captured CoAP packets
- Abuses Observe option for notification flooding
- Enumerates resources via link-format and path brute-forcing

## Features

- **Packet Crafting**: Build custom CoAP messages with options
- **Request Replay**: Replay captured CoAP packets
- **Observe Abuse**: Register multiple observers for DoS
- **Resource Discovery**: Parse .well-known/core and brute-force paths
- **Message Decoding**: Full CoAP packet parsing

## Installation

```bash
# No external dependencies - uses Python standard library only
# Requires Python 3.6+
```

## Usage

```bash
# Discover resources via .well-known/core
python3 coap_replay.py 192.168.1.100 --enumerate

# GET request to path
python3 coap_replay.py 192.168.1.100 --get /sensors/temperature

# POST data to resource
python3 coap_replay.py 192.168.1.100 --post /actuators/led "on"

# PUT data to resource
python3 coap_replay.py 192.168.1.100 --put /config/mode "manual"

# Register multiple observers (observe abuse)
python3 coap_replay.py 192.168.1.100 --abuse-observe /sensors/temp 10

# Brute-force common paths
python3 coap_replay.py 192.168.1.100 --brute

# Replay raw packet (hex-encoded)
python3 coap_replay.py 192.168.1.100 --replay 6045010000000001

# Craft and send custom packet
python3 coap_replay.py 192.168.1.100 --craft CON GET /sensors
```

## Example Output

```
[*] Discovering resources via .well-known/core
  Found 3 resource(s):
    {'path': '/sensors/temperature', 'attrs': ';rt="temperature";ct=0'}
    {'path': '/sensors/humidity', 'attrs': ';rt="humidity";ct=0'}
    {'path': '/actuators/led', 'attrs': ';rt="led";ct=0'}

[GET /sensors/temperature] 2.05 Content
Payload (8 bytes): 23.45
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
