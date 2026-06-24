#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import secrets
import string
import threading
import subprocess
import ipaddress
from datetime import datetime

# === CEK DEPENDENSI ===
try:
    from flask import Flask, render_template_string, jsonify, request, session
    from flask_socketio import SocketIO, emit
except ImportError:
    print("Instal: pip3 install flask flask-socketio")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, getmacbyip
except ImportError:
    print("Instal: pip3 install scapy")
    sys.exit(1)

try:
    import netifaces
except ImportError:
    print("Instal: pip3 install netifaces")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Instal: pip3 install requests")
    sys.exit(1)

# Import modul deauth (file kedua)
try:
    from wifi_deauth import send_deauth, hard_block, block_mac as deauth_block
except ImportError:
    print("File wifi_deauth.py tidak ditemukan. Buat file tersebut atau disable fitur deauth.")
    # Buat fungsi dummy agar tidak error
    def send_deauth(*args, **kwargs): return False
    def hard_block(*args, **kwargs): return False

# =========================================
#  AUTO DETEKSI KONFIGURASI
# =========================================
def get_gateway():
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if match:
            return match.group(1)
    except:
        pass
    gws = netifaces.gateways()
    default = gws.get('default', {})
    for af, (gw, iface) in default.items():
        return gw
    return None

def get_interface():
    gws = netifaces.gateways()
    default = gws.get('default', {})
    for af, (gw, iface) in default.items():
        return iface
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            if ip.startswith(("192.168.", "10.", "172.")):
                return iface
    return "wlan0"

def get_subnet():
    iface = get_interface()
    addrs = netifaces.ifaddresses(iface)
    inet = addrs[netifaces.AF_INET][0]
    ip = inet['addr']
    netmask = inet['netmask']
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(net)

def get_gateway_mac():
    # Dapatkan MAC dari gateway via ARP
    gw_ip = get_gateway()
    if gw_ip:
        mac = getmacbyip(gw_ip)
        if mac:
            return mac.upper()
    return None

ROUTER_IP = get_gateway()
INTERFACE = get_interface()
SUBNET = get_subnet()
AP_MAC = get_gateway_mac() or "00:00:00:00:00:00"

# =========================================
#  GENERATE RANDOM KEY
# =========================================
def generate_key(length=6):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

ACCESS_KEY = generate_key()
print("\n" + "="*50)
print(f"🔑 KEY AKSES: {ACCESS_KEY}")
print("="*50)
print("Simpan key ini. Tanpa key, dashboard tidak bisa diakses.\n")
print(f"[*] Gateway IP: {ROUTER_IP}")
print(f"[*] Interface: {INTERFACE}")
print(f"[*] AP MAC: {AP_MAC}")

# =========================================
#  SCANNER + BLOKIR (core)
# =========================================
def lookup_vendor(oui):
    db = {
        "B827EB": "Raspberry Pi", "F4F951": "Xiaomi", "AC84C6": "Samsung",
        "B0F1EC": "iPhone", "E0553D": "TP-Link", "001A2B": "Intel",
        "C0EEFB": "Huawei", "0C84DC": "Sony", "F0D1A9": "Google",
        "A4C138": "Xiaomi", "F8E43B": "Samsung", "B89CFF": "Apple"
    }
    return db.get(oui, "Unknown")

def scan_devices():
    arp = ARP(pdst=SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, recv in result:
        oui = recv.hwsrc[:8].upper().replace(":", "")
        vendor = lookup_vendor(oui)
        devices.append({
            "ip": recv.psrc,
            "mac": recv.hwsrc.upper(),
            "vendor": vendor
        })
    return devices

def block_mac(mac):
    try:
        subprocess.run(f"ebtables -A FORWARD -s {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"ebtables -A INPUT -s {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"iptables -A FORWARD -m mac --mac-source {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP", shell=True, check=True)
        return True
    except:
        return False

def unblock_mac(mac):
    try:
        subprocess.run(f"ebtables -D FORWARD -s {mac} -j DROP", shell=True)
        subprocess.run(f"ebtables -D INPUT -s {mac} -j DROP", shell=True)
        subprocess.run(f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
        subprocess.run(f"iptables -D INPUT -m mac --mac-source {mac} -j DROP", shell=True)
        return True
    except:
        return False

def get_blocked_macs():
    macs = []
    try:
        out = subprocess.check_output("ebtables -L FORWARD", shell=True, text=True)
        for line in out.splitlines():
            if '-s' in line and 'DROP' in line:
                parts = line.split()
                idx = parts.index('-s')
                if idx + 1 < len(parts):
                    macs.append(parts[idx+1].upper())
    except:
        pass
    return macs

def throttle_mac(mac, rate="1mbit", burst="32kbit"):
    try:
        subprocess.run(f"tc qdisc del dev {INTERFACE} root", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"tc qdisc add dev {INTERFACE} root handle 1: htb default 30", shell=True)
        subprocess.run(f"tc class add dev {INTERFACE} parent 1: classid 1:1 htb rate {rate} ceil {rate} burst {burst}", shell=True)
        subprocess.run(f"iptables -t mangle -A FORWARD -m mac --mac-source {mac} -j MARK --set-mark 1", shell=True)
        subprocess.run(f"tc filter add dev {INTERFACE} parent 1:0 prio 1 handle 1 fw flowid 1:1", shell=True)
        return True
    except:
        return False

def remove_all_throttle():
    try:
        subprocess.run(f"tc qdisc del dev {INTERFACE} root", shell=True)
        subprocess.run("iptables -t mangle -D FORWARD -m mac --mac-source -j MARK --set-mark 1 2>/dev/null", shell=True)
        return True
    except:
        return False

# =========================================
#  ADMIN ROUTER (SEDERHANA)
# =========================================
from requests.auth import HTTPBasicAuth

def change_ssid(new_ssid):
    try:
        url = f"http://{ROUTER_IP}/userRpm/WlanBasicRpm.htm"
        params = {"ssid": new_ssid, "Save": "Save"}
        r = requests.get(url, params=params, auth=HTTPBasicAuth('admin','admin'), timeout=5)
        return r.status_code == 200
    except:
        return False

def change_password(new_pass):
    try:
        url = f"http://{ROUTER_IP}/userRpm/WlanSecurityRpm.htm"
        params = {"wpaPsk": new_pass, "Save": "Save"}
        r = requests.get(url, params=params, auth=HTTPBasicAuth('admin','admin'), timeout=5)
        return r.status_code == 200
    except:
        return False

# =========================================
#  AUTO DEAUTH UNKNOWN (custom)
# =========================================
def auto_deauth_unknown(trusted_macs):
    devices = scan_devices()
    for dev in devices:
        if dev['mac'] not in trusted_macs:
            send_deauth(dev['mac'], AP_MAC, INTERFACE, count=30)
            time.sleep(0.3)
    return True

# =========================================
#  FLASK APP
# =========================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

device_list = []
scanner_active = True

def background_scanner():
    global device_list, scanner_active
    while True:
        try:
            device_list = scan_devices()
            blocked = get_blocked_macs()
            for dev in device_list:
                dev['blocked'] = dev['mac'] in blocked
            socketio.emit('update_devices', device_list)
            scanner_active = True
        except Exception as e:
            scanner_active = False
            print(f"[!] Scanner error: {e}")
        time.sleep(5)

threading.Thread(target=background_scanner, daemon=True).start()

# =========================================
#  HTML LOGIN + DASHBOARD (HITAM PUTIH MODERN)
# =========================================
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Router Secure</title>
    <style>
        body { background: #000; color: #fff; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #111; padding: 40px; border: 1px solid #333; border-radius: 8px; width: 340px; text-align: center; }
        .login-box h2 { color: #eee; letter-spacing: 2px; }
        .login-box input { width: 100%; padding: 12px; margin: 12px 0; background: #222; border: 1px solid #444; color: #fff; border-radius: 4px; font-size: 16px; }
        .login-box button { width: 100%; padding: 12px; background: #333; border: 1px solid #555; color: #fff; font-size: 16px; border-radius: 4px; cursor: pointer; }
        .login-box button:hover { background: #444; }
        .error { color: #ff4444; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 ROUTER SECURE</h2>
        <p style="color:#888;">Masukkan key akses</p>
        <form method="POST">
            <input type="text" name="key" placeholder="Key..." autofocus>
            <button type="submit">MASUK</button>
        </form>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Router Control</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #ddd; font-family: 'Courier New', monospace; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; padding: 10px 20px; background: #111; border-bottom: 1px solid #333; }
        .status { padding: 6px 16px; border-radius: 20px; font-size: 14px; font-weight: bold; }
        .active { background: #1a3a1a; color: #4f4; border: 1px solid #4f4; }
        .notactive { background: #3a1a1a; color: #f44; border: 1px solid #f44; }
        .container { max-width: 1400px; margin: 20px auto; }
        .row { display: flex; gap: 20px; flex-wrap: wrap; }
        .col-8 { flex: 2; min-width: 400px; }
        .col-4 { flex: 1; min-width: 280px; }
        .card { background: #111; border: 1px solid #2a2a2a; border-radius: 6px; padding: 16px; margin-bottom: 20px; }
        .card-title { color: #aaa; font-size: 14px; letter-spacing: 1px; border-bottom: 1px solid #222; padding-bottom: 8px; margin-bottom: 12px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; color: #666; padding: 8px 4px; border-bottom: 1px solid #222; }
        td { padding: 6px 4px; border-bottom: 1px solid #1a1a1a; }
        .btn { padding: 4px 10px; border: 1px solid #444; background: #1a1a1a; color: #ddd; border-radius: 3px; cursor: pointer; font-size: 11px; font-family: monospace; }
        .btn:hover { background: #2a2a2a; }
        .btn-danger { border-color: #844; color: #f66; }
        .btn-danger:hover { background: #2a1a1a; }
        .btn-success { border-color: #484; color: #6f6; }
        .btn-success:hover { background: #1a2a1a; }
        .btn-info { border-color: #448; color: #66f; }
        .btn-info:hover { background: #1a1a2a; }
        .btn-warning { border-color: #884; color: #ff6; }
        .btn-warning:hover { background: #2a2a1a; }
        .btn-hard { border-color: #a44; color: #f88; background: #1a0a0a; }
        .btn-hard:hover { background: #2a0a0a; }
        .input-control { width: 100%; padding: 8px; background: #1a1a1a; border: 1px solid #333; color: #ddd; border-radius: 4px; margin: 4px 0; font-family: monospace; }
        .terminal { background: #000; color: #0f0; padding: 10px; border-radius: 4px; height: 200px; overflow-y: auto; font-size: 12px; border: 1px solid #222; }
        .terminal .log-line { border-bottom: 1px solid #0a0a0a; padding: 2px 0; }
        .flex { display: flex; gap: 8px; flex-wrap: wrap; }
        .mt-2 { margin-top: 10px; }
        .w-100 { width: 100%; }
        .text-center { text-align: center; }
        .badge { background: #222; padding: 2px 10px; border-radius: 12px; font-size: 11px; color: #888; }
        @media (max-width: 700px) { .col-8, .col-4 { min-width: 100%; } }
    </style>
</head>
<body>
    <div class="header">
        <div style="display:flex;align-items:center;gap:12px;">
            <span style="font-size:20px;">🛜</span>
            <span style="font-weight:bold;letter-spacing:2px;">ROUTER ULTIMATE</span>
            <span class="badge">v2.0</span>
        </div>
        <div>
            <span id="statusIndicator" class="status active">● Active</span>
        </div>
    </div>

    <div class="container">
        <div class="row">
            <div class="col-8">
                <div class="card">
                    <div class="card-title">📡 PERANGKAT TERHUBUNG</div>
                    <div style="overflow-x:auto;">
                        <table>
                            <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Status</th><th>Aksi</th></tr></thead>
                            <tbody id="deviceTable"></tbody>
                        </table>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">💻 TERMINAL LOG</div>
                    <div class="terminal" id="logArea">
                        <div class="log-line">> Ready. Menunggu aksi...</div>
                    </div>
                </div>
            </div>
            <div class="col-4">
                <div class="card">
                    <div class="card-title">⚡ KONTROL</div>
                    <button id="blockAllBtn" class="btn btn-danger w-100" style="padding:8px;">🚫 Block Semua Asing</button>
                    <button id="autoDeauthBtn" class="btn btn-hard w-100 mt-2" style="padding:8px;">📡 Auto Deauth Asing</button>
                    <hr style="border-color:#222;">
                    <label style="color:#888;">SSID Baru</label>
                    <input id="newSSID" class="input-control" placeholder="Nama WiFi">
                    <button id="changeSSIDBtn" class="btn w-100 mt-2">Ganti SSID</button>
                    <hr style="border-color:#222;">
                    <label style="color:#888;">Password Baru</label>
                    <input id="newPass" class="input-control" placeholder="Password WiFi">
                    <button id="changePassBtn" class="btn w-100 mt-2">Ganti Password</button>
                    <hr style="border-color:#222;">
                    <button id="throttleAllBtn" class="btn btn-info w-100">⏱ Throttle All (1mbit)</button>
                    <button id="removeThrottleBtn" class="btn w-100 mt-2">⏹ Hapus Throttle</button>
                </div>
                <div class="card">
                    <div class="card-title">📊 INFO</div>
                    <div style="font-size:13px;color:#888;">
                        <div>Gateway: <span style="color:#ddd;">{{ router_ip }}</span></div>
                        <div>Interface: <span style="color:#ddd;">{{ interface }}</span></div>
                        <div>AP MAC: <span style="color:#ddd;">{{ ap_mac }}</span></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        var socket = io();
        var trustedMacs = [];
        var logCount = 0;

        socket.on('update_devices', function(devices) {
            var html = '';
            var activeCount = 0;
            devices.forEach(function(d) {
                var status = d.blocked ? '🚫 Blocked' : '✅ Active';
                if (!d.blocked) activeCount++;
                var actions = '';
                if (!d.blocked) {
                    actions += `<button onclick="blockMac('${d.mac}')" class="btn btn-danger">Block</button>`;
                    actions += `<button onclick="throttleMac('${d.mac}')" class="btn btn-info">Throttle</button>`;
                    actions += `<button onclick="hardBlock('${d.mac}')" class="btn btn-hard">Hard</button>`;
                } else {
                    actions += `<button onclick="unblockMac('${d.mac}')" class="btn btn-success">Unblock</button>`;
                }
                html += `<tr><td>${d.ip}</td><td>${d.mac}</td><td>${d.vendor}</td><td>${status}</td><td>${actions}</td></tr>`;
            });
            document.getElementById('deviceTable').innerHTML = html;

            var indicator = document.getElementById('statusIndicator');
            if (activeCount > 0) {
                indicator.className = 'status active';
                indicator.textContent = '● Active';
            } else {
                indicator.className = 'status notactive';
                indicator.textContent = '● Not Active';
            }
        });

        function blockMac(mac) {
            fetch('/api/block', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mac:mac}) })
            .then(res=>res.json()).then(data=>{ if(data.status=='blocked') log('Blocked: '+mac); });
        }
        function unblockMac(mac) {
            fetch('/api/unblock', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mac:mac}) })
            .then(res=>res.json()).then(data=>{ if(data.status=='unblocked') log('Unblocked: '+mac); });
        }
        function throttleMac(mac) {
            var rate = prompt('Rate (contoh: 1mbit, 512kbit):', '1mbit');
            if(rate) {
                fetch('/api/throttle', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mac:mac, rate:rate}) })
                .then(res=>res.json()).then(data=>{ if(data.status=='throttled') log('Throttled: '+mac+' rate '+rate); });
            }
        }
        function hardBlock(mac) {
            if(confirm('Hard Block akan mengirim deauth + block permanen. Lanjutkan?')) {
                fetch('/api/hard_block', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mac:mac}) })
                .then(res=>res.json()).then(data=>{ if(data.status=='hard_blocked') log('Hard Block: '+mac); });
            }
        }

        document.getElementById('blockAllBtn').addEventListener('click', function(){
            var macs = [];
            document.querySelectorAll('#deviceTable tr').forEach(row => {
                var cells = row.querySelectorAll('td');
                if(cells.length > 1) {
                    var mac = cells[1].innerText.trim();
                    if(mac && !trustedMacs.includes(mac)) macs.push(mac);
                }
            });
            macs.forEach(mac => blockMac(mac));
            log('Block all asing diterapkan.');
        });

        document.getElementById('autoDeauthBtn').addEventListener('click', function(){
            if(confirm('Auto Deauth akan mengirim deauth ke semua perangkat asing. Lanjutkan?')) {
                fetch('/api/auto_deauth', { method:'POST' })
                .then(res=>res.json()).then(data=>{ log('Auto Deauth selesai.'); });
            }
        });

        document.getElementById('changeSSIDBtn').addEventListener('click', function(){
            var ssid = document.getElementById('newSSID').value;
            if(ssid) {
                fetch('/api/ssid', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ssid:ssid}) })
                .then(res=>res.json()).then(data=>{ log('Ganti SSID: '+(data.status=='success'?'sukses':'gagal')); });
            }
        });

        document.getElementById('changePassBtn').addEventListener('click', function(){
            var pass = document.getElementById('newPass').value;
            if(pass) {
                fetch('/api/password', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pass}) })
                .then(res=>res.json()).then(data=>{ log('Ganti Password: '+(data.status=='success'?'sukses':'gagal')); });
            }
        });

        document.getElementById('removeThrottleBtn').addEventListener('click', function(){
            fetch('/api/remove_throttle', { method:'POST' })
            .then(res=>res.json()).then(data=>{ log('Throttle dihapus'); });
        });

        function log(msg) {
            var area = document.getElementById('logArea');
            var time = new Date().toLocaleTimeString();
            area.innerHTML += `<div class="log-line">[${time}] ${msg}</div>`;
            area.scrollTop = area.scrollHeight;
        }

        // Trusted MAC: tambahkan MAC perangkat utama untuk menghindari block
        // trustedMacs.push('AA:BB:CC:DD:EE:FF');
    </script>
</body>
</html>
"""

# =========================================
#  ROUTES
# =========================================
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        key = request.form.get('key', '').strip().upper()
        if key == ACCESS_KEY:
            session['authenticated'] = True
            return render_template_string(DASHBOARD_HTML,
                router_ip=ROUTER_IP, interface=INTERFACE, ap_mac=AP_MAC)
        else:
            return render_template_string(LOGIN_HTML, error='Key salah!')
    if session.get('authenticated'):
        return render_template_string(DASHBOARD_HTML,
            router_ip=ROUTER_IP, interface=INTERFACE, ap_mac=AP_MAC)
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return "Logged out"

# =========================================
#  API ENDPOINTS
# =========================================
@app.route('/api/block', methods=['POST'])
def api_block():
    mac = request.json.get('mac')
    if mac and block_mac(mac):
        return jsonify({'status': 'blocked'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    mac = request.json.get('mac')
    if mac and unblock_mac(mac):
        return jsonify({'status': 'unblocked'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/throttle', methods=['POST'])
def api_throttle():
    mac = request.json.get('mac')
    rate = request.json.get('rate', '1mbit')
    if mac and throttle_mac(mac, rate):
        return jsonify({'status': 'throttled'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/remove_throttle', methods=['POST'])
def api_remove_throttle():
    if remove_all_throttle():
        return jsonify({'status': 'removed'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/ssid', methods=['POST'])
def api_ssid():
    ssid = request.json.get('ssid')
    if ssid and change_ssid(ssid):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'failed'}), 400

@app.route('/api/password', methods=['POST'])
def api_password():
    pw = request.json.get('password')
    if pw and change_password(pw):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'failed'}), 400

@app.route('/api/hard_block', methods=['POST'])
def api_hard_block():
    mac = request.json.get('mac')
    if mac:
        hard_block(mac, AP_MAC, INTERFACE, count=100)
        return jsonify({'status': 'hard_blocked'})
    return jsonify({'status': 'error'}), 400

@app.route('/api/auto_deauth', methods=['POST'])
def api_auto_deauth():
    trusted = request.json.get('trusted', []) if request.json else []
    # Gabungkan trusted dari request dengan trustedMacs di JS (belum dikirim), kita pake default kosong
    # Di sini kita panggil auto_deauth_unknown dengan daftar trusted dari parameter atau kosong
    # Kita akan gunakan trusted dari list yang dikirim, tapi kita juga bisa hardcode
    # Karena JS tidak kirim trusted, kita gunakan list kosong (semua perangkat dianggap asing)
    auto_deauth_unknown(trusted)
    return jsonify({'status': 'auto_deauth_done'})

# =========================================
#  MAIN
# =========================================
if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Jalankan dengan ROOT: sudo python3 router_ultimate_secure.py")
        sys.exit(1)
    print("[*] Server jalan di http://localhost:5000")
    print("[*] Tekan Ctrl+C untuk berhenti.")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
