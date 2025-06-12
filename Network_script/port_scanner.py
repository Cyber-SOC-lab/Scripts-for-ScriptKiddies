## Port Scanner Script ##
import socket
import threading

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port {port} is open on {ip}, ready to fuck it up.")
    sock.close()

def scan_range(ip, start_port, end_port):
    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    target ="Enter your target ip address"  # Replace with your target
    scan_range(target, 1, 1000)
## End Port Scanner Script ##
