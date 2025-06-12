import os
import socket
import struct
import argparse
from ctypes import *

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

def main(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[+] Sniffing started on {host or 'all interfaces'}... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            if len(raw_buffer) >= 32:
                ip_header = IP(raw_buffer[:32])
                print(f"[{ip_header.protocol}] {ip_header.src_address} -> {ip_header.dst_address}")
            else:
                print("[-] Packet too small to parse.")
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\n[+] Sniffing stopped. Exiting.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("--host", default="", help="Host IP to bind (default: all interfaces)")
    args = parser.parse_args()

    main(args.host)
