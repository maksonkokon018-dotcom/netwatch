"""Логіка сканування локальної мережі: ping, ARP, hostname, порти, виробник."""
import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB (файли Windows)",
    554: "RTSP (камери)",
    3389: "RDP (віддалений стіл)",
    8080: "HTTP (альтернативний)",
    9100: "Друк (JetDirect)",
}

IS_WINDOWS = platform.system() == "Windows"


class ScanState:
    """Спільний стан між веб-сервером і потоком сканування."""

    def __init__(self):
        self.lock = threading.Lock()
        self.devices = {}          # ip -> dict
        self.scanning = False
        self.stage = ""
        self.last_scan = None
        self.network = ""
        self.local_ip = ""

    def sorted_devices(self):
        with self.lock:
            items = list(self.devices.values())
        return sorted(items, key=lambda d: ipaddress.ip_address(d["ip"]))

    def get(self, ip):
        with self.lock:
            return self.devices.get(ip)


state = ScanState()
_vendor_cache = {}

# ---------- історія пристроїв (history.json поруч зі скриптом) ----------
HISTORY_FILE = Path(__file__).with_name("history.json")
_history_lock = threading.Lock()


def _load_history():
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_history = _load_history()


def _save_history():
    try:
        tmp = HISTORY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(_history, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(HISTORY_FILE)
    except OSError:
        pass


def device_key(dev):
    """Унікальний ключ пристрою: MAC (або ім'я цього комп'ютера)."""
    return dev["mac"] if dev["mac"] != "—" else "self-" + socket.gethostname()


def update_history(devices):
    """Оновлює історію та позначає нові пристрої. Викликати під state.lock."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _history_lock:
        first_run = not _history
        for dev in devices:
            entry = _history.get(device_key(dev))
            dev["new"] = entry is None and not first_run
            if entry is None:
                entry = _history[device_key(dev)] = {"first_seen": now, "label": ""}
            entry.update(last_seen=now, ip=dev["ip"], hostname=dev["hostname"],
                         vendor=dev["vendor"], type=dev["type"])
            dev["first_seen"] = entry["first_seen"]
            dev["label"] = entry.get("label", "")
        _save_history()


def set_label(ip, label):
    dev = state.get(ip)
    if dev is None:
        return False
    label = label.strip()[:60]
    with _history_lock:
        entry = _history.setdefault(
            device_key(dev),
            {"first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        entry["label"] = label
        _save_history()
    with state.lock:
        dev["label"] = label
    return True


def history_rows():
    online = {device_key(d) for d in state.sorted_devices()}
    with _history_lock:
        rows = [dict(key=k, online=k in online, **v) for k, v in _history.items()]
    rows.sort(key=lambda r: r.get("last_seen", ""), reverse=True)
    rows.sort(key=lambda r: not r["online"])
    return rows


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ping(ip):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=4)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def normalize_mac(mac):
    return mac.replace("-", ":").upper()


def read_arp_table():
    """Повертає {ip: mac} з системної ARP-таблиці (Windows/Linux/macOS)."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             errors="ignore", timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        return {}
    table = {}
    for line in out.splitlines():
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac_m = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ip_m and mac_m:
            parts = re.split(r"[:-]", mac_m.group(1))
            mac = ":".join(p.zfill(2) for p in parts).upper()
            table[ip_m.group(1)] = mac
    return table


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def check_port(ip, port, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def scan_ports(ip):
    with ThreadPoolExecutor(max_workers=len(PORTS)) as ex:
        results = list(ex.map(lambda p: (p, check_port(ip, p)), PORTS))
    return [{"port": p, "service": PORTS[p]} for p, ok in results if ok]


def lookup_vendor(mac):
    """Виробник за MAC через api.macvendors.com (безкоштовний ліміт ~1 запит/сек)."""
    if not mac or mac == "—":
        return ""
    prefix = mac[:8]
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    vendor = ""
    try:
        req = urllib.request.Request(
            "https://api.macvendors.com/" + mac,
            headers={"User-Agent": "network-scanner"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            vendor = resp.read().decode("utf-8", "ignore").strip()
        time.sleep(1.1)  # щоб не впертись у ліміт API
    except Exception:
        vendor = ""
    _vendor_cache[prefix] = vendor
    return vendor


def guess_type(device):
    ports = {p["port"] for p in device["ports"]}
    vendor = device["vendor"].lower()
    if 9100 in ports:
        return "Принтер"
    if 554 in ports:
        return "IP-камера"
    if 3389 in ports or 445 in ports:
        return "Комп'ютер Windows"
    if 22 in ports and not ports & {3389, 445}:
        return "Linux / сервер / роутер"
    if any(v in vendor for v in ("apple", "samsung", "xiaomi", "huawei", "oneplus")):
        return "Телефон / планшет"
    if any(v in vendor for v in ("tp-link", "zyxel", "mikrotik", "d-link", "asus", "netgear", "ubiquiti")):
        return "Роутер / мережеве обладнання"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "Пристрій з веб-інтерфейсом"
    return "Невідомо"


def scan_network():
    """Повне сканування /24 мережі. Викликається в окремому потоці."""
    with state.lock:
        if state.scanning:
            return
        state.scanning = True
        state.stage = "Пінг мережі..."

    try:
        local_ip = get_local_ip()
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        with state.lock:
            state.local_ip = local_ip
            state.network = str(net)

        # 1) ping усіх адрес, щоб наповнити ARP-таблицю
        hosts = [str(h) for h in net.hosts()]
        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(ping, hosts))

        # 2) читаємо ARP
        with state.lock:
            state.stage = "Читаю ARP-таблицю..."
        arp = read_arp_table()
        found = {}
        for ip, mac in arp.items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr not in net or addr == net.broadcast_address or mac == "FF:FF:FF:FF:FF:FF":
                continue
            found[ip] = mac
        found.setdefault(local_ip, "—")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_devices = {}
        for ip, mac in found.items():
            old = state.get(ip) or {}
            new_devices[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": old.get("hostname", ""),
                "vendor": old.get("vendor", ""),
                "ports": old.get("ports", []),
                "type": old.get("type", "Невідомо"),
                "is_self": ip == local_ip,
                "seen": now,
                "label": old.get("label", ""),
                "new": old.get("new", False),
                "first_seen": old.get("first_seen", now),
            }
        with state.lock:
            state.devices = new_devices

        # 3) hostname + порти паралельно
        with state.lock:
            state.stage = "Hostname і відкриті порти..."

        def enrich(ip):
            host = get_hostname(ip)
            ports = scan_ports(ip)
            with state.lock:
                dev = state.devices.get(ip)
                if dev:
                    dev["hostname"] = host
                    dev["ports"] = ports

        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(enrich, list(new_devices)))

        # 4) виробник (послідовно через ліміт API)
        with state.lock:
            state.stage = "Визначаю виробників..."
        for ip in list(new_devices):
            dev = state.get(ip)
            vendor = lookup_vendor(dev["mac"])
            with state.lock:
                dev["vendor"] = vendor
                dev["type"] = guess_type(dev)

        with state.lock:
            update_history(list(state.devices.values()))
            state.last_scan = datetime.now().strftime("%H:%M:%S")
    finally:
        with state.lock:
            state.scanning = False
            state.stage = ""
