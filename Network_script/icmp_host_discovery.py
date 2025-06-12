import threading
import socket
import time
import struct
import os
import argparse
from ctypes import *
from netaddr import IPNetwork, IPAddress

# Define ICMP header class
class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(cls, socket_buffer):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

# Define IP header class
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id",  c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("!I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("!I", self.dst))
        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))

# Send UDP packets to stimulate ICMP responses
def udp_sender(subnet, magic_message):
    time.sleep(2)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message.encode(), (str(ip), 65212))
        except Exception as e:
            print(f"[!] Error sending packet to {ip}: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="ICMP Host Discovery Tool using UDP and Sniffing")
    parser.add_argument("--ip", required=True, help="Host IP address to bind the sniffer")
    parser.add_argument("--subnet", required=True, help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--magic", default="PYTHONRULES!", help="Magic message to include in UDP packets")
    args = parser.parse_args()

    host = args.ip
    subnet = args.subnet
    magic_message = args.magic

    # Launch UDP sender thread
    thread = threading.Thread(target=udp_sender, args=(subnet, magic_message))
    thread.start()

    try:
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("[*] Sniffer started. Waiting for ICMP replies... Press Ctrl+C to stop.")

        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            if len(raw_buffer) < 32:
                continue

            ip_header = IP(raw_buffer[:32])
            if ip_header.protocol == "ICMP":
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + sizeof(ICMP)]

                if len(buf) < sizeof(ICMP):
                    continue

                icmp_header = ICMP(buf)

                if icmp_header.type == 3 and icmp_header.code == 3:
                    if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                        if raw_buffer.endswith(magic_message.encode()):
                            print(f"[+] Host Up: {ip_header.src_address}")

    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting...")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except Exception as e:
        print(f"[!] Runtime Error: {e}")

if __name__ == "__main__":
    main()
