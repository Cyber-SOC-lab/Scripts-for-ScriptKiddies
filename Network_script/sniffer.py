import os
import socket
import struct
from ctypes import *

# host to listen (optional - can be left blank for all interfaces)
host = input("Enter your host IP addr: ") or "" 

# IP header
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

        # Human-readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("!I" , self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("!I", self.dst))

        # Human-readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num) 

# Create a raw socket and bind it 
if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

# Bind to the specified host (or all interfaces if host is empty)
sniffer.bind((host, 0)) 

# We want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# If you are using Windows, enable promiscuous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        # Read in a single packet
        raw_buffer = sniffer.recvfrom(65535)[0] 

        packet_size = len(raw_buffer)
        print(f"Recieved packet of size: {packet_size} bytes")

        if packet_size >= 32:
        
             # Create IP header from first 32 bytes of buffer
            ip_header = IP(raw_buffer[:32])
               # Print the detected protocol and the hosts
            print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
        else:
            print("Packet too small to parse IP header")

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    print("\nExiting...")
