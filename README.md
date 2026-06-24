# 🛜 Router Control Ultimate — Full Suite

**Single‑file web dashboard + deauth module** untuk mengelola jaringan WiFi dengan kekuatan penuh.  
Dirancang untuk analisis jaringan, forensik, dan administrasi — bukan untuk penggunaan ilegal.

---

## ✨ Fitur

- 🔑 **Key Authentication** — akses web dilindungi key acak yang muncul di terminal.
- 📡 **Real‑time Device Scan** — daftar perangkat terhubung diperbarui otomatis tiap 5 detik (WebSocket).
- 🚫 **Block / Unblock** — blokir perangkat berdasarkan MAC (ebtables + iptables double layer).
- ⏱ **Throttle** — batasi bandwidth per MAC menggunakan `tc` + `iptables` mark.
- 💀 **Hard Block** — blokir + spam deauth packet (memutus koneksi Wi-Fi secara paksa).
- 📡 **Auto Deauth** — kirim deauth ke semua perangkat asing dalam satu klik.
- 🔄 **Ganti SSID / Password** — dukungan endpoint TPLINK (bisa disesuaikan).
- 🖥️ **UI Hitam Putih** — dashboard minimalis modern, responsif.
- 📜 **Live Terminal Log** — semua aksi tercatat real‑time.
- 🌐 **Akses dari mana saja** — cukup buka `http://<IP>:5000` di jaringan.

---

## 📦 Persyaratan

- **Linux** (dengan kernel mendukung `ebtables`, `iptables`, `tc`)
- **Root privileges** (karena manipulasi jaringan)
- **Python 3.8+**
- **Aircrack‑ng** (untuk monitor interface, opsional tapi disarankan)

---

## 🔧 Instalasi

```bash
# Clone repository
git clone https://github.com/yourusername/router-ultimate.git
cd router-ultimate

# Install dependensi sistem
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng ebtables iptables

# Install Python packages
pip3 install flask flask-socketio scapy netifaces requests
