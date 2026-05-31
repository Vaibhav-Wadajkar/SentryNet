from flask import Flask, render_template, jsonify, request, Response
import subprocess
import re
import socket
import json
import os
import platform
import csv
import io
from datetime import datetime
import numpy as np

# Try to import sklearn for anomaly detection
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[!] scikit-learn not installed. AI anomaly detection disabled.")

app = Flask(__name__)

# ----------------------------
# File paths
# ----------------------------
HISTORY_FILE = "device_history.json"
NOTES_FILE = "device_notes.json"
SCAN_HISTORY_FILE = "scan_history.json"
MAX_SCAN_HISTORY = 10

# ----------------------------
# 1. Platform-independent ARP table parser
# ----------------------------
def get_arp_table():
    """Run arp -a on Windows/WSL/Linux/macOS and return raw output."""
    output = ""
    system_plat = platform.system().lower()

    # Windows native
    if "windows" in system_plat:
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5, shell=True
            )
            output = result.stdout
        except Exception as e:
            print(f"[!] Native Windows arp -a failed: {e}")

    # WSL path
    if not output:
        cmd_path = "/mnt/c/Windows/System32/cmd.exe"
        if os.path.exists(cmd_path):
            try:
                result = subprocess.run(
                    [cmd_path, "/c", "arp", "-a"],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout
            except Exception as e:
                print(f"[!] WSL cmd.exe arp -a failed: {e}")

    # Linux / macOS fallback
    if not output:
        try:
            result = subprocess.run(
                ["arp", "-an"], capture_output=True, text=True, timeout=5
            )
            output = result.stdout
        except Exception as e:
            print(f"[!] Standard Unix arp failed: {e}")

    if not output:
        return []

    devices = []
    current_interface = None
    lines = output.splitlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Windows interface header
        if line.startswith("Interface:"):
            match = re.search(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                current_interface = match.group(1)
            continue

        parts = line.split()

        # Windows ARP format: IP  MAC  Type
        if len(parts) >= 3:
            ip = parts[0]
            raw_mac = parts[1]
            entry_type = parts[2].lower() if len(parts) > 2 else ""

            # Normalize MAC separators
            mac = raw_mac.replace('-', ':').lower()

            # Validate IP format
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                continue
            # Validate MAC format (accept xx:xx:xx:xx:xx:xx)
            if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                continue
            # Skip multicast/broadcast MACs
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue

            # Windows: only dynamic entries
            if "windows" in system_plat or os.path.exists("/mnt/c/Windows/System32/cmd.exe"):
                if "dynamic" not in entry_type:
                    continue

            # Linux arp -an format: ? (IP) at MAC [ether] on iface
            # parts[0] = '?', parts[1] = '(IP)', parts[3] = MAC
            if parts[0] == '?' and len(parts) >= 4:
                ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", parts[1])
                if ip_match:
                    ip = ip_match.group(1)
                mac = parts[3].replace('-', ':').lower()
                if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                    continue
                if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "<incomplete>"):
                    continue

            # Deduplicate by MAC
            if not any(d['mac'] == mac for d in devices):
                devices.append({"ip": ip, "mac": mac, "is_mock": False})

    return devices

# ----------------------------
# 2. Mock Device Generator
# ----------------------------
def get_mock_devices():
    return [
        {"ip": "192.168.1.1",  "mac": "b8:b7:db:84:c7:f4", "vendor": "Netgear",                   "hostname": "Gateway-Router",        "type": "🌐 Router",     "is_mock": True},
        {"ip": "192.168.1.10", "mac": "00:11:32:11:22:33", "vendor": "Synology",                   "hostname": "NAS-Storage",           "type": "💾 Server",     "is_mock": True},
        {"ip": "192.168.1.12", "mac": "e4:70:a8:aa:bb:cc", "vendor": "Samsung Electronics",        "hostname": "LivingRoom-SmartTV",    "type": "📺 Smart TV",   "is_mock": True},
        {"ip": "192.168.1.20", "mac": "00:26:ab:11:22:33", "vendor": "Hewlett-Packard",             "hostname": "HP-LaserJet-Office",    "type": "🖨️ Printer",   "is_mock": True},
        {"ip": "192.168.1.25", "mac": "f0:9f:c2:aa:bb:cc", "vendor": "Apple Inc.",                 "hostname": "Vaibhavs-iPhone",       "type": "📱 Mobile",     "is_mock": True},
        {"ip": "192.168.1.34", "mac": "18:74:2e:dd:ee:ff", "vendor": "Nest Labs",                  "hostname": "LivingRoom-Thermostat", "type": "🌡️ Smart Home", "is_mock": True},
        {"ip": "192.168.1.49", "mac": "b6:62:79:a0:94:97", "vendor": "Dell Inc.",                  "hostname": "Dell-Latitude-7420",    "type": "💻 Computer",   "is_mock": True},
        {"ip": "192.168.1.51", "mac": "02:62:65:14:b1:a2", "vendor": "Unknown",                    "hostname": "IoT-Lightbulb",         "type": "🌡️ Smart Home", "is_mock": True},
        {"ip": "192.168.1.80", "mac": "00:d9:d1:dd:ee:ff", "vendor": "Sony Interactive Entertainment", "hostname": "PlayStation-5",    "type": "🎮 Console",    "is_mock": True},
        {"ip": "192.168.1.99", "mac": "00:0c:29:43:82:12", "vendor": "VMware",                     "hostname": "Unrecognized-VM",       "type": "🔌 Unknown",    "is_mock": True},
    ]

# ----------------------------
# 3. MAC vendor lookup
# ----------------------------
try:
    from manuf import manuf
    manuf_parser = manuf.MacParser()
    VENDOR_LOOKUP = True
except ImportError:
    VENDOR_LOOKUP = False
    print("[!] manuf not installed. Vendor lookup fallback active.")

VENDOR_PREFIXES = {
    "b8:b7:db": "Netgear",
    "f0:9f:c2": "Apple",
    "b6:62:79": "Dell",
    "00:11:32": "Synology",
    "18:74:2e": "Google/Nest",
    "00:0c:29": "VMware",
    "e4:70:a8": "Samsung",
    "00:26:ab": "Hewlett-Packard",
    "00:d9:d1": "Sony",
    "02:62:65": "Generic IoT",
    "ac:de:48": "Apple",
    "3c:22:fb": "Apple",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
}

def get_vendor(mac):
    if VENDOR_LOOKUP:
        try:
            vendor = manuf_parser.get_manuf(mac)
            return vendor if vendor else "Unknown"
        except:
            pass
    prefix3 = mac[:8]
    return VENDOR_PREFIXES.get(prefix3, "Unknown")

# ----------------------------
# 4. Hostname resolver (with timeout)
# ----------------------------
def get_hostname(ip):
    try:
        socket.setdefaulttimeout(1.5)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        if ip.endswith(".1"):
            return "gateway.local"
        return "Unknown"
    finally:
        socket.setdefaulttimeout(None)

# ----------------------------
# 5. Device History
# ----------------------------
def load_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            print(f"[!] Corrupted file {path}, resetting.")
    return default

def save_json_file(path, data):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to write {path}: {e}")

def load_history():
    return load_json_file(HISTORY_FILE, {})

def save_history(history):
    save_json_file(HISTORY_FILE, history)

# ----------------------------
# 6. Scan History
# ----------------------------
def load_scan_history():
    return load_json_file(SCAN_HISTORY_FILE, [])

def save_scan_snapshot(devices):
    history = load_scan_history()
    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "devices": [
            {"ip": d["ip"], "mac": d["mac"], "hostname": d["hostname"],
             "vendor": d["vendor"], "type": d["type"], "anomaly": d["anomaly"]}
            for d in devices
        ]
    }
    history.append(snapshot)
    # Keep only last MAX_SCAN_HISTORY snapshots
    if len(history) > MAX_SCAN_HISTORY:
        history = history[-MAX_SCAN_HISTORY:]
    save_json_file(SCAN_HISTORY_FILE, history)

# ----------------------------
# 7. Anomaly Detection (fixed first-scan false positives)
# ----------------------------
def train_anomaly_model(history):
    if not SKLEARN_AVAILABLE or len(history) < 3:
        return None, None
    features, macs = [], []
    for mac, data in history.items():
        # Only train on devices seen more than once (reduces first-scan noise)
        if data.get('appearance_count', 1) < 2:
            continue
        try:
            first_seen = datetime.fromisoformat(data['first_seen'])
        except:
            continue
        days_since_first = max(0, (datetime.now() - first_seen).days)
        appearance_count = data.get('appearance_count', 1)
        ip_change_count = len(data.get('ips_seen', []))
        features.append([days_since_first, appearance_count, ip_change_count])
        macs.append(mac)
    if len(features) < 3:
        return None, None
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(np.array(features))
    return model, macs

def predict_anomaly(model, macs, current_mac, history):
    """
    Returns (is_suspicious: bool, reason: str)
    Fixed: new devices on first scan are NOT immediately flagged as suspicious.
    """
    data = history.get(current_mac, {})
    appearance_count = data.get('appearance_count', 0)

    # Brand new device — flag as new but not necessarily suspicious
    if current_mac not in history or appearance_count <= 1:
        return False, "New device — monitoring"

    ips_seen = data.get('ips_seen', [])

    # Rule: multiple IPs (possible spoofing / unusual roaming)
    if len(ips_seen) > 3:
        return True, f"Multiple IP addresses detected ({len(ips_seen)} IPs)"

    # ML model scoring
    if SKLEARN_AVAILABLE and model is not None and macs is not None:
        if current_mac in macs:
            try:
                first_seen = datetime.fromisoformat(data['first_seen'])
                days = max(0, (datetime.now() - first_seen).days)
                feat = np.array([[days, appearance_count, len(ips_seen)]])
                pred = model.predict(feat)[0]
                if pred == -1:
                    return True, "Unusual behavior pattern detected by AI model"
            except:
                pass

    return False, "Consistent behavior — trusted"

# ----------------------------
# 8. Device type categorizer
# ----------------------------
def categorize_device(vendor, hostname, ip):
    v = vendor.lower()
    h = hostname.lower()
    if ip.endswith('.1') or ip.endswith('.254') or any(k in h for k in ["router", "gateway"]) or any(k in v for k in ["netgear", "linksys", "asus", "tplink", "tp-link", "dlink", "d-link", "ubiquiti", "mikrotik", "openwrt"]):
        return "🌐 Router"
    if any(k in h for k in ["iphone", "android", "phone", "ipad", "galaxy", "pixel", "oneplus", "mobile", "huawei", "xiaomi"]):
        return "📱 Mobile"
    if any(k in h for k in ["tv", "television", "chromecast", "firestick", "roku", "appletv", "apple-tv"]) or any(k in v for k in ["sony", "samsung", "lg", "panasonic", "toshiba", "vizio", "hisense"]):
        return "📺 Smart TV"
    if any(k in h for k in ["nest", "light", "bulb", "plug", "alexa", "echo", "sonos", "speaker", "camera", "ring", "thermostat", "iot", "shelly", "tasmota"]) or any(k in v for k in ["espressif", "tuya", "philips", "lifx", "tp-link", "google", "amazon", "belkin"]):
        return "🌡️ Smart Home"
    if any(k in h for k in ["pc", "laptop", "desktop", "macbook", "workstation", "latitude", "thinkpad", "pavilion", "inspiron"]) or any(k in v for k in ["apple", "dell", "lenovo", "hp", "asus", "intel", "acer", "msi", "gigabyte"]):
        return "💻 Computer"
    if any(k in h for k in ["xbox", "playstation", "nintendo", "switch", "ps4", "ps5"]) or any(k in v for k in ["microsoft", "sony interactive", "nintendo"]):
        return "🎮 Console"
    if any(k in h for k in ["nas", "server", "synology", "qnap", "freenas", "truenas"]):
        return "💾 Server"
    if any(k in h for k in ["printer", "deskjet", "laserjet", "officejet", "epson", "canon", "brother"]) or any(k in v for k in ["hp", "canon", "epson", "brother", "xerox"]):
        return "🖨️ Printer"
    if any(k in v for k in ["raspberry", "arduino", "espressif"]):
        return "🔧 Dev Board"
    return "🔌 Unknown"

# ----------------------------
# 9. Ping latency
# ----------------------------
def ping_device(ip):
    """Ping a device and return latency in ms, or None if unreachable."""
    try:
        system_plat = platform.system().lower()
        if "windows" in system_plat:
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        output = result.stdout

        # Parse time from ping output
        # Windows: "time=Xms" or "time<Xms"
        # Linux/macOS: "time=X.X ms"
        match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output, re.IGNORECASE)
        if match:
            return round(float(match.group(1)), 1)
        return None
    except Exception:
        return None

# ----------------------------
# 10. Main scan controller
# ----------------------------
def get_devices_with_details(force_mock=False):
    raw_devices = []

    if not force_mock:
        raw_devices = get_arp_table()

    is_mock_active = False
    if not raw_devices:
        raw_devices = get_mock_devices()
        is_mock_active = True

    history = load_history()
    notes = load_json_file(NOTES_FILE, {})
    now_iso = datetime.now().isoformat()

    # Track which MACs were NEW before this scan
    known_macs_before = set(history.keys())

    devices = []
    for d in raw_devices:
        ip = d['ip']
        mac = d['mac']

        vendor = d.get('vendor') or get_vendor(mac)
        hostname = d.get('hostname') or get_hostname(ip)

        # Update history
        is_new_device = mac not in history
        if is_new_device:
            history[mac] = {
                'first_seen': now_iso,
                'last_seen': now_iso,
                'appearance_count': 1,
                'ips_seen': [ip]
            }
        else:
            history[mac]['last_seen'] = now_iso
            history[mac]['appearance_count'] = history[mac].get('appearance_count', 0) + 1
            ips = history[mac].get('ips_seen', [])
            if ip not in ips:
                ips.append(ip)
            history[mac]['ips_seen'] = ips

        # Device type
        device_type = d.get('type') or categorize_device(vendor, hostname, ip)

        devices.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname,
            'type': device_type,
            'status': 'Active',
            'first_seen': history[mac]['first_seen'],
            'last_seen': history[mac]['last_seen'],
            'appearance_count': history[mac]['appearance_count'],
            'ips_seen': history[mac]['ips_seen'],
            'is_mock': is_mock_active,
            'is_new': is_new_device,
            'note': notes.get(mac, '')
        })

    # Anomaly detection
    model, trained_macs = train_anomaly_model(history)
    for d in devices:
        is_suspicious, reason = predict_anomaly(model, trained_macs, d['mac'], history)
        d['anomaly'] = '⚠️ Suspicious' if is_suspicious else '✅ Normal'
        d['anomaly_reason'] = reason

    save_history(history)
    save_scan_snapshot(devices)
    return devices

# ----------------------------
# 11. Flask routes
# ----------------------------
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/scan')
def scan():
    use_mock = request.args.get('mock', 'false').lower() == 'true'
    devices = get_devices_with_details(force_mock=use_mock)
    return jsonify(devices)

@app.route('/router')
def router_info():
    use_mock = request.args.get('mock', 'false').lower() == 'true'
    system_plat = platform.system()

    if use_mock:
        return jsonify({
            'router_ip': '192.168.1.1',
            'interface': 'Mock Wireless Interface (demo)',
            'network': '192.168.1.0/24'
        })

    arp_table = get_arp_table()
    router_ip = "192.168.1.1"
    for d in arp_table:
        if d['ip'].endswith('.1') or d['ip'].endswith('.254'):
            router_ip = d['ip']
            break

    return jsonify({
        'router_ip': router_ip,
        'interface': f'Native {system_plat} ARP Scanner',
        'network': f'{".".join(router_ip.split(".")[:3])}.0/24'
    })

@app.route('/ping/<ip>')
def ping(ip):
    # Basic IP validation to prevent injection
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        return jsonify({'error': 'Invalid IP'}), 400
    latency = ping_device(ip)
    return jsonify({'ip': ip, 'latency_ms': latency})

@app.route('/notes', methods=['GET'])
def get_notes():
    notes = load_json_file(NOTES_FILE, {})
    return jsonify(notes)

@app.route('/notes', methods=['POST'])
def save_note():
    data = request.get_json()
    if not data or 'mac' not in data:
        return jsonify({'error': 'Missing mac'}), 400
    mac = data['mac'].lower()
    note = str(data.get('note', ''))[:200]  # Cap note length
    notes = load_json_file(NOTES_FILE, {})
    notes[mac] = note
    save_json_file(NOTES_FILE, notes)
    return jsonify({'status': 'saved', 'mac': mac, 'note': note})

@app.route('/history/latest')
def history_latest():
    scan_history = load_scan_history()
    if not scan_history:
        return jsonify(None)
    return jsonify(scan_history[-1])

@app.route('/history/previous')
def history_previous():
    scan_history = load_scan_history()
    if len(scan_history) < 2:
        return jsonify(None)
    return jsonify(scan_history[-2])

@app.route('/export')
def export_csv():
    scan_history = load_scan_history()
    if not scan_history:
        return jsonify({'error': 'No scan data available'}), 404

    latest = scan_history[-1]
    devices = latest.get('devices', [])

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['ip', 'mac', 'hostname', 'vendor', 'type', 'anomaly'])
    writer.writeheader()
    for d in devices:
        writer.writerow({k: d.get(k, '') for k in ['ip', 'mac', 'hostname', 'vendor', 'type', 'anomaly']})

    timestamp = latest.get('timestamp', datetime.now().isoformat())[:10]
    filename = f"sentrynet_scan_{timestamp}.csv"

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)