import psutil
import socket
from datetime import datetime

SUSPICIOUS_PORTS = {21, 23, 445, 3389}
LOG_FILE = "pulse_guard_security.log"

def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

def check_open_ports():
    connections = psutil.net_connections(kind='inet')
    open_ports = set()

    for conn in connections:
        if conn.status == "LISTEN" and conn.laddr:
            open_ports.add(conn.laddr.port)

    return open_ports

def detect_suspicious_ports(open_ports):
    flagged = open_ports.intersection(SUSPICIOUS_PORTS)
    return flagged

def monitor_network():
    print("Pulse Guard - Network Security Mode Activated 🔐")
    print("-" * 50)

    open_ports = check_open_ports()
    print(f"Open Ports: {sorted(open_ports)}")

    suspicious = detect_suspicious_ports(open_ports)

    if suspicious:
        for port in suspicious:
            alert = f"⚠ Suspicious Port Open: {port}"
            print(alert)
            log_event(alert)
    else:
        print("✅ No suspicious ports detected.")

    print("-" * 50)

if __name__ == "__main__":
    monitor_network()
