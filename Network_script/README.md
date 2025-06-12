# 🌐 Network Tools

This directory contains Python-based tools for basic network tasks such as port scanning and packet sniffing. These tools are designed for **educational and internal testing purposes only**.

> ⚠️ Running these tools on networks you don't own or without explicit permission is **illegal and unethical**. Use responsibly.

---

## 🔍 Tools Included

### 1. `port_scanner.py`

A multi-threaded TCP port scanner that checks for open ports on a target host.

- ✅ Uses `socket` and `threading` libraries.
- ✅ Scans a range of ports quickly using parallel threads.

**Usage**

```bash
**Usage of post_scanner:**

python3 port_scanner.py 192.168.1.10 --start 20 --end 100


**Usage of sniffer:**

sudo python3 sniffer.py --host 192.168.1.5




