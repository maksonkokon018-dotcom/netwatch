"""Додаткові мережеві інструменти. Тільки стандартна бібліотека Python.

Щоб додати новий інструмент: напиши функцію і додай запис у список TOOLS внизу —
він автоматично з'явиться на сторінці /tools і отримає API /api/<id>.
"""
import ipaddress
import platform
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import scanner

IS_WINDOWS = platform.system() == "Windows"
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")
COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,554,1883,3389,5900,8080,8443,9100"


class ToolError(Exception):
    """Помилка, текст якої показується користувачу."""


# ---------- допоміжні функції ----------

def _int(value, default, lo, hi):
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def clean_host(host):
    host = (host or "").strip()
    if not host or len(host) > 253 or not HOST_RE.match(host):
        raise ToolError("Невірна адреса або домен")
    return host


def require_private(host):
    """Сканування дозволено лише для адрес локальної мережі."""
    host = clean_host(host)
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except OSError:
        raise ToolError("Не вдалося визначити IP-адресу")
    if not (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ToolError("Цей інструмент працює лише з адресами локальної мережі")
    return str(ip)


def _run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=timeout)
    except FileNotFoundError:
        raise ToolError("Команда '%s' не знайдена в системі" % cmd[0])
    except subprocess.TimeoutExpired:
        raise ToolError("Час очікування вичерпано")
    except (subprocess.SubprocessError, OSError) as e:
        raise ToolError(str(e))


def _norm_mac(mac):
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(digits) != 12:
        raise ToolError("Невірна MAC-адреса (потрібно 12 шістнадцяткових символів)")
    digits = digits.upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def parse_ports(spec):
    ports = set()
    try:
        for part in (spec or "").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
                ports.update(range(min(a, b), max(a, b) + 1))
            else:
                ports.add(int(part))
    except ValueError:
        raise ToolError("Невірний список портів. Приклад: 22,80,443 або 1-1024")
    if not ports:
        raise ToolError("Порожній список портів")
    if min(ports) < 1 or max(ports) > 65535:
        raise ToolError("Порти мають бути в діапазоні 1–65535")
    if len(ports) > 5000:
        raise ToolError("Забагато портів за раз (максимум 5000)")
    return sorted(ports)


def _service(port):
    if port in scanner.PORTS:
        return scanner.PORTS[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return ""


def _open_ports(ip, ports):
    with ThreadPoolExecutor(max_workers=200) as ex:
        results = list(ex.map(lambda p: (p, scanner.check_port(ip, p, 0.5)), ports))
    return [p for p, ok in results if ok]


def get_gateway():
    try:
        if IS_WINDOWS:
            out = _run(["route", "print", "-4", "0.0.0.0"], 10).stdout
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        else:
            out = _run(["ip", "route", "show", "default"], 10).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if not m:
                out = _run(["route", "-n", "get", "default"], 10).stdout
                m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else ""
    except ToolError:
        return ""


# ---------- інструменти ----------

def ping_stats(host, count=4):
    host = clean_host(host)
    count = _int(count, 4, 1, 20)
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "1500", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    out = _run(cmd, count * 3 + 5).stdout

    times = [float(m.group(1)) for m in re.finditer(r"time[=<]\s*(\d+(?:\.\d+)?)", out, re.I)]
    if not times:  # локалізований Windows ("час=1мс TTL=64")
        times = [float(m.group(1).replace(",", "."))
                 for m in re.finditer(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*\S{0,3}\s+TTL=", out, re.I)]
    times = times[:count]
    received = len(times)
    return {
        "host": host,
        "sent": count,
        "received": received,
        "loss_percent": round((count - received) / count * 100),
        "min_ms": min(times) if times else None,
        "avg_ms": round(sum(times) / received, 2) if times else None,
        "max_ms": max(times) if times else None,
        "times_ms": times,
    }


def traceroute(host):
    host = clean_host(host)
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", "20", "-w", "800", host]
    else:
        cmd = ["traceroute", "-n", "-m", "20", "-w", "1", host]
    return {"host": host, "output": _run(cmd, 120).stdout.strip()}


def health_check():
    checks = []

    def add(name, ok, detail):
        checks.append({"check": name, "ok": ok, "detail": detail})

    def ping_check(name, target):
        p = ping_stats(target, 2)
        ok = p["received"] > 0
        add(name, ok, "%s мс" % p["avg_ms"] if ok else "немає відповіді")

    gw = get_gateway()
    if gw:
        ping_check("Роутер (%s)" % gw, gw)
    else:
        add("Роутер", False, "шлюз не знайдено")
    ping_check("Інтернет (1.1.1.1)", "1.1.1.1")
    t = time.time()
    try:
        socket.gethostbyname("example.com")
        add("DNS (example.com)", True, "%d мс" % ((time.time() - t) * 1000))
    except OSError:
        add("DNS (example.com)", False, "не вдалося визначити адресу")
    return {"checks": checks}


def dns_lookup(name):
    name = clean_host(name)
    out = {"query": name}
    try:
        canonical, aliases, ips = socket.gethostbyname_ex(name)
        out.update(canonical=canonical, aliases=aliases, ipv4=ips)
        out["reverse"] = {}
        for ip in ips:
            try:
                out["reverse"][ip] = socket.gethostbyaddr(ip)[0]
            except OSError:
                out["reverse"][ip] = "—"
    except OSError:
        out["error_ipv4"] = "не знайдено"
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET6)
        out["ipv6"] = sorted({i[4][0] for i in infos})
    except OSError:
        out["ipv6"] = []
    return out


def _whois_query(server, query):
    try:
        with socket.create_connection((server, 43), timeout=8) as s:
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "ignore")
    except OSError as e:
        raise ToolError("Whois недоступний: %s" % e)


def whois(query):
    query = clean_host(query)
    server = "whois.iana.org"
    text = _whois_query(server, query)
    m = re.search(r"^refer:\s*(\S+)", text, re.M | re.I)
    if m:
        server = m.group(1)
        text = _whois_query(server, query)
    return {"query": query, "server": server, "output": text.strip()[:6000]}


def port_scan(host, spec):
    ip = require_private(host)
    ports = parse_ports(spec or "1-1024")
    start = time.time()
    open_ports = _open_ports(ip, ports)
    return {
        "host": ip,
        "scanned_ports": len(ports),
        "seconds": round(time.time() - start, 1),
        "open": [{"port": p, "service": _service(p)} for p in open_ports],
    }


def _grab(ip, port):
    if port in (443, 8443):
        return "(TLS — використай «HTTP-інфо»)"
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.settimeout(2)
            if port in (80, 8000, 8080, 8888):
                s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
            data = s.recv(512)
        text = re.sub(r"[^\x20-\x7e\n\r\t]", "?", data.decode("utf-8", "ignore")).strip()
        return text[:300] or "(порожньо)"
    except socket.timeout:
        return "(сервіс не надсилає банер)"
    except OSError as e:
        return "(помилка: %s)" % e


def banners(host, spec):
    ip = require_private(host)
    ports = parse_ports(spec or COMMON_PORTS)
    result = [{"port": p, "service": _service(p), "banner": _grab(ip, p)}
              for p in _open_ports(ip, ports)]
    return {"host": ip, "services": result}


def http_info(host):
    ip = require_private(host)
    ctx = ssl._create_unverified_context()
    pages = []
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("https", 8443)):
        url = "%s://%s:%d/" % (scheme, ip, port)
        req = urllib.request.Request(url, headers={"User-Agent": "network-scanner"})
        try:
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                status, headers = r.status, r.headers
                body = r.read(20000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, e.headers, ""
        except Exception:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        pages.append({
            "url": url,
            "status": status,
            "title": re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else "",
            "server": headers.get("Server", ""),
            "powered_by": headers.get("X-Powered-By", ""),
            "auth": headers.get("WWW-Authenticate", ""),
        })
    return {"host": ip, "pages": pages or "веб-інтерфейс не знайдено"}


def netbios(host):
    """NetBIOS node status — імена Windows/Samba-пристроїв."""
    ip = require_private(host)
    encoded = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)]) for b in b"*" + b"\x00" * 15)
    packet = (struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
              + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x21, 1))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(packet, (ip, 137))
        data, _ = s.recvfrom(1024)
    except socket.timeout:
        return {"host": ip, "names": "немає відповіді (NetBIOS вимкнено або не Windows)"}
    except OSError as e:
        raise ToolError(str(e))
    finally:
        s.close()
    try:
        pos = 12
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        pos += 10
        count = data[pos]
        pos += 1
        names = []
        for _ in range(count):
            raw = data[pos:pos + 18]
            names.append({
                "name": raw[:15].decode("ascii", "ignore").strip(),
                "suffix": "0x%02X" % raw[15],
                "group": bool(struct.unpack(">H", raw[16:18])[0] & 0x8000),
            })
            pos += 18
        mac = ":".join("%02X" % b for b in data[pos:pos + 6])
        return {"host": ip, "names": names, "mac": mac}
    except (IndexError, struct.error):
        return {"host": ip, "names": "не вдалося розібрати відповідь"}


def _describe_ssdp(entry):
    entry["types"] = sorted(entry["types"])[:5]
    try:
        u = urlparse(entry["location"])
        if u.scheme != "http" or u.hostname != entry["ip"]:
            return entry
        with urllib.request.urlopen(entry["location"], timeout=2) as r:
            xml = r.read(60000).decode("utf-8", "ignore")
        for tag, key in (("friendlyName", "name"), ("manufacturer", "manufacturer"),
                         ("modelName", "model")):
            m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), xml, re.S)
            if m:
                entry[key] = m.group(1).strip()[:100]
    except Exception:
        pass
    return entry


def ssdp_discover(timeout):
    """Пошук UPnP-пристроїв (смарт-ТВ, медіасервери, роутери, принтери)."""
    timeout = _int(timeout, 4, 1, 10)
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.5)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    found = {}
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65507)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode("utf-8", "ignore").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            entry = found.setdefault(addr[0], {"ip": addr[0], "server": "", "location": "", "types": set()})
            entry["server"] = entry["server"] or headers.get("server", "")
            entry["location"] = entry["location"] or headers.get("location", "")
            if headers.get("st"):
                entry["types"].add(headers["st"])
    except OSError as e:
        raise ToolError("SSDP недоступний: %s" % e)
    finally:
        sock.close()
    with ThreadPoolExecutor(max_workers=8) as ex:
        devices = list(ex.map(_describe_ssdp, found.values()))
    return {"found": len(devices), "devices": devices or "UPnP-пристроїв не знайдено"}


def wake_on_lan(mac):
    mac = _norm_mac(mac)
    packet = bytes.fromhex("FF" * 6 + mac.replace(":", "") * 16)
    net = ipaddress.ip_network(scanner.get_local_ip() + "/24", strict=False)
    targets = ["255.255.255.255", str(net.broadcast_address)]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        for t in targets:
            s.sendto(packet, (t, 9))
    except OSError as e:
        raise ToolError(str(e))
    finally:
        s.close()
    return {"mac": mac, "sent_to": targets,
            "note": "Пакет надіслано. Пристрій має підтримувати Wake-on-LAN і бути ввімкнений у BIOS/налаштуваннях."}


def vendor_lookup(mac):
    mac = _norm_mac(mac)
    return {"mac": mac, "vendor": scanner.lookup_vendor(mac) or "не знайдено"}


def arp_table():
    table = scanner.read_arp_table()
    ordered = sorted(table.items(), key=lambda kv: ipaddress.ip_address(kv[0]))
    return {"entries": [{"ip": ip, "mac": mac} for ip, mac in ordered]}


def subnet_calc(cidr):
    try:
        net = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError:
        raise ToolError("Невірний формат. Приклад: 192.168.1.0/24")
    if net.version != 4:
        raise ToolError("Підтримується лише IPv4")
    many = net.num_addresses > 2
    return {
        "network": str(net.network_address),
        "prefix": "/%d" % net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": str(net.broadcast_address),
        "first_host": str(net.network_address + 1) if many else str(net.network_address),
        "last_host": str(net.broadcast_address - 1) if many else str(net.broadcast_address),
        "hosts": net.num_addresses - 2 if many else net.num_addresses,
        "private": net.is_private,
    }


def my_info():
    info = {
        "hostname": socket.gethostname(),
        "local_ip": scanner.get_local_ip(),
        "gateway": get_gateway() or "невідомо",
        "os": platform.platform(),
        "python": platform.python_version(),
    }
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            info["public_ip"] = r.read().decode().strip()
    except Exception:
        info["public_ip"] = "немає з'єднання з інтернетом"
    return info


def speed_test(size_mb):
    size = _int(size_mb, 10, 1, 50)
    out = {}
    t = time.time()
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=3).close()
        out["latency_ms"] = round((time.time() - t) * 1000, 1)
    except OSError:
        out["latency_ms"] = None
    url = "https://speed.cloudflare.com/__down?bytes=%d" % (size * 1_000_000)
    req = urllib.request.Request(url, headers={"User-Agent": "network-scanner"})
    total = 0
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            while True:
                chunk = r.read(65536)
                if not chunk or time.time() - start > 25:
                    break
                total += len(chunk)
    except OSError as e:
        raise ToolError("Не вдалося виконати тест: %s" % e)
    dur = max(time.time() - start, 0.001)
    out.update(downloaded_mb=round(total / 1e6, 2), seconds=round(dur, 2),
               speed_mbit_s=round(total * 8 / 1e6 / dur, 2))
    return out


# ---------- реєстр інструментів (для сторінки /tools та /api/<id>) ----------

def F(name, label, default=""):
    return {"name": name, "label": label, "default": default}


TOOLS = [
    {"id": "ping", "title": "Ping зі статистикою",
     "desc": "Мін/середня/макс затримка та відсоток втрат пакетів.",
     "fields": [F("host", "Адреса", "192.168.1.1"), F("count", "Кількість пакетів", "4")],
     "run": lambda a: ping_stats(a.get("host"), a.get("count"))},
    {"id": "traceroute", "title": "Traceroute",
     "desc": "Маршрут пакетів до вузла (може тривати до хвилини).",
     "fields": [F("host", "Адреса або домен", "8.8.8.8")],
     "run": lambda a: traceroute(a.get("host"))},
    {"id": "health", "title": "Діагностика мережі",
     "desc": "Перевіряє роутер, інтернет і DNS одним кліком.",
     "fields": [],
     "run": lambda a: health_check()},
    {"id": "dns", "title": "DNS-пошук",
     "desc": "IPv4/IPv6 адреси домену та зворотний DNS.",
     "fields": [F("name", "Домен або IP", "example.com")],
     "run": lambda a: dns_lookup(a.get("name"))},
    {"id": "whois", "title": "Whois",
     "desc": "Хто власник домену або публічної IP-адреси.",
     "fields": [F("query", "Домен або IP", "example.com")],
     "run": lambda a: whois(a.get("query"))},
    {"id": "portscan", "title": "Сканер портів",
     "desc": "Власний діапазон портів (лише локальна мережа, до 5000 портів).",
     "fields": [F("host", "IP пристрою", "192.168.1.1"), F("ports", "Порти", "1-1024")],
     "run": lambda a: port_scan(a.get("host"), a.get("ports"))},
    {"id": "banners", "title": "Банери сервісів",
     "desc": "Що відповідають відкриті порти (SSH, FTP, HTTP...). Лише локальна мережа.",
     "fields": [F("host", "IP пристрою", "192.168.1.1"), F("ports", "Порти", COMMON_PORTS)],
     "run": lambda a: banners(a.get("host"), a.get("ports"))},
    {"id": "httpinfo", "title": "HTTP-інфо",
     "desc": "Заголовок сторінки, сервер і тип авторизації веб-інтерфейсу пристрою.",
     "fields": [F("host", "IP пристрою", "192.168.1.1")],
     "run": lambda a: http_info(a.get("host"))},
    {"id": "netbios", "title": "NetBIOS-імена",
     "desc": "Ім'я комп'ютера Windows/Samba за IP.",
     "fields": [F("host", "IP пристрою", "192.168.1.10")],
     "run": lambda a: netbios(a.get("host"))},
    {"id": "ssdp", "title": "UPnP / SSDP пошук",
     "desc": "Знаходить смарт-ТВ, медіасервери, роутери, принтери.",
     "fields": [F("timeout", "Секунд очікування", "4")],
     "run": lambda a: ssdp_discover(a.get("timeout"))},
    {"id": "wol", "title": "Wake-on-LAN",
     "desc": "Вмикає комп'ютер у мережі за MAC-адресою.",
     "fields": [F("mac", "MAC-адреса", "AA:BB:CC:DD:EE:FF")],
     "run": lambda a: wake_on_lan(a.get("mac"))},
    {"id": "vendor", "title": "Виробник за MAC",
     "desc": "Визначає виробника мережевої карти.",
     "fields": [F("mac", "MAC-адреса", "")],
     "run": lambda a: vendor_lookup(a.get("mac"))},
    {"id": "arp", "title": "ARP-таблиця",
     "desc": "Що система вже знає про сусідів у мережі.",
     "fields": [],
     "run": lambda a: arp_table()},
    {"id": "subnet", "title": "Калькулятор підмереж",
     "desc": "Маска, broadcast, діапазон хостів за CIDR.",
     "fields": [F("cidr", "Мережа (CIDR)", "192.168.1.0/24")],
     "run": lambda a: subnet_calc(a.get("cidr"))},
    {"id": "myinfo", "title": "Мій комп'ютер",
     "desc": "Локальний і публічний IP, шлюз, система.",
     "fields": [],
     "run": lambda a: my_info()},
    {"id": "speed", "title": "Тест швидкості",
     "desc": "Швидкість завантаження через Cloudflare та затримка.",
     "fields": [F("size", "Розмір, МБ (1–50)", "10")],
     "run": lambda a: speed_test(a.get("size"))},
]

TOOLS_BY_ID = {t["id"]: t for t in TOOLS}
