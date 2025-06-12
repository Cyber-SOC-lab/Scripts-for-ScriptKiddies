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


### 🔎 3. 'ICMP Host Discovery (udp_icmp_scanner.py)'

A stealthy ICMP-based network scanner that uses UDP packets and listens for ICMP Type 3 Code 3 responses to detect live hosts within a subnet.

#### 📦 Features:
- Sends crafted UDP packets with a "magic message"
- Sniffs ICMP replies to detect live hosts
- Works cross-platform (Windows & Linux)
- Useful for environments where ping (ICMP Echo) is blocked

#### ⚠️ Requirements:
- Run as administrator/root
- Python 3.6+
- Python package: netaddr

#### 🚀 Usage:
```bash
python3 icmp_host_discovery.py --ip <your_host_ip> --subnet <target_subnet> [--magic <custom_magic_message>]
```

#### 🔧 Example:
- python3 icmp_host_discovery.py --ip 192.168.1.100 --subnet 192.168.1.0/24
