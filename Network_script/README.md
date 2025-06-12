# 🌐 Network Tools

This directory contains basic Python-based network utilities developed for educational and ethical testing purposes.

> ⚠️ **Disclaimer:** These tools are intended for use in controlled environments only. Unauthorized use on public or private networks without explicit permission is strictly prohibited.

---

## 📁 Tools Included

### 🔎 1. `port_scanner.py`

A raw socket packet sniffer that captures and decodes IP headers from incoming packets.

#### ✅ Features:
- Fast scanning using threads
- Customizable port ranges
- Simple and portable code


#### 🚀 Usage:
```bash
python3 port_scanner.py <target_ip> --start <start_port> --end <end_port>
```


#### 🔎 2. `sniffer.py`

A simple multi-threaded TCP port scanner that checks for open ports on a target host.

#### ✅ Features:
- Captures raw network packets
- Extracts and prints the protocol, source, and destination IPs
- Cross-platform support (Linux, Windows)

#### ⚠️ Requirements:
- Must be run with root/admin privileges.
- On Windows, it enables promiscuous mode automatically.

#### 🚀 Usage:
```bash
sudo python3 sniffer.py --host <host_ip>
```
If you leave --host blank, it will sniff on all available interfaces.

