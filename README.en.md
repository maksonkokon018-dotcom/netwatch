# Network Scanner

[🇺🇦 Українська](README.md) · 🇬🇧 English

A lightweight home-network dashboard with a web interface. It shows which devices are connected to your Wi-Fi, collects the information they expose, and bundles a set of simple network tools.

> ⚠️ **Use only on your own network or with the owner's permission.** Scanning networks you don't have permission to test may be illegal.

This is not a replacement for [nmap](https://nmap.org) or Fing. It is a simple home tool: a friendly UI, device history and all the basic utilities in one place. Pure Python; the only dependency is Flask.

<!-- Add screenshots here (blank out MAC addresses and device names first):
![Main](docs/main.png)
![Tools](docs/tools.png)
-->

## Features

- **/24 network scan**: ping + ARP, IP, MAC, hostname, vendor lookup by MAC, open ports.
- **Device type guess** (printer, camera, PC, router...) from open ports and vendor. It is a heuristic and can be wrong.
- **A page per device** with details and a link to its web interface.
- **Custom device names** ("Alex's phone").
- **Device history** (`history.json`): online/offline, first/last seen, and a **NEW** badge for new connections.
- **Export** to CSV (opens in Excel) and JSON.
- **16 tools**: Ping, Traceroute, network health check, DNS, Whois, port scanner, service banners, HTTP info, NetBIOS, UPnP/SSDP, Wake-on-LAN, MAC vendor lookup, ARP table, subnet calculator, my PC info, speed test.

## Installation

Requires Python 3.9+.

```
git clone https://github.com/YOUR_NAME/network-scanner.git
cd network-scanner
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

Works on Windows, Linux and macOS. Traceroute on Linux/macOS needs the `traceroute` command installed.

## Usage

1. Run `python app.py`. A scan starts immediately (1–2 minutes); the page refreshes by itself.
2. Click a device IP to see its details and run tools against it.
3. The **Tools** tab has standalone utilities for any address.
4. The **History** tab lists every device ever seen. New devices get a **NEW** badge.
5. **Scan again** repeats the scan.

## Tools

| Tool | What it does |
|------|--------------|
| Ping | Min/avg/max latency, packet loss % |
| Traceroute | Route to a host |
| Network health check | Router + internet + DNS in one click |
| DNS lookup | IPv4/IPv6 and reverse DNS |
| Whois | Owner of a domain or IP |
| Port scanner | Custom port range (up to 5000), local network only |
| Service banners | What SSH/FTP/HTTP services reply with |
| HTTP info | Title, server, auth type of a device's web UI |
| NetBIOS | Windows computer name |
| UPnP / SSDP | Smart TVs, media servers, printers |
| Wake-on-LAN | Power on a PC by MAC |
| MAC vendor | NIC manufacturer |
| ARP table | Neighbours known to your system |
| Subnet calculator | Mask, broadcast, host range |
| My computer | Local/public IP, gateway |
| Speed test | Download speed via Cloudflare |

## Project structure

| File | Purpose |
|------|---------|
| `app.py` | Flask web server and routes |
| `scanner.py` | Scanning and device history |
| `tools.py` | All tools (the `TOOLS` registry) |
| `templates.py` | HTML pages |
| `requirements.txt` | Dependencies |

### Adding your own tool

Write a function in `tools.py` and add an entry to the `TOOLS` list at the bottom. It automatically appears on `/tools` and gets a `POST /api/<id>` endpoint.

## Security

- The server listens on `127.0.0.1` only; requests from other hosts and from other websites are rejected.
- The port scanner, banner grabber, HTTP info and NetBIOS tools only accept local-network addresses.
- The app has no authentication, so **do not expose it to the internet** and do not change `host` to `0.0.0.0`.
- `history.json` contains MAC addresses and names of your devices, so it is listed in `.gitignore`.

## Limitations

- Only the /24 subnet of your computer is scanned.
- Some devices don't answer ping and may not show up.
- Device type detection is approximate.
- Vendor lookup uses api.macvendors.com (internet required, about 1 request/second).
- An open port does not mean the device is accessible.

## License

[MIT](LICENSE)

---

Built with the help of [Claude](https://claude.ai).
