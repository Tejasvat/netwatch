

import socket
import time
import argparse
import random

def port_scan(host="127.0.0.1", start=1, end=300, delay=0.005):
    """Open connections to many ports and HOLD THEM OPEN."""
    print(f"[Trigger] Port scan: Knocking on {end} ports and holding...")
    sockets = []
    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((host, port))
            sockets.append(s) # Hold the socket open!
        except Exception:
            pass
        time.sleep(delay)
    
    print(f"[Trigger] Holding {len(sockets)} ports open for 5 seconds so agent catches it...")
    time.sleep(5)
    for s in sockets:
        try: s.close()
        except: pass
    print("[Trigger] Port scan complete")

def syn_flood(host="127.0.0.1", port=80, count=250, delay=0.005):
    """Open many connections rapidly to a single port and HOLD."""
    print(f"[Trigger] SYN flood: {count} connections to {host}:{port}")
    sockets = []
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((host, port))
            sockets.append(s)
        except Exception:
            pass
        time.sleep(delay)
        
    print(f"[Trigger] Holding {len(sockets)} connections for 5s…")
    time.sleep(5)
    for s in sockets:
        try: s.close()
        except: pass
    print("[Trigger] SYN flood complete")

def connection_spike(host="127.0.0.1", count=1000):
    
    print(f"[Trigger] Connection spike: {count} simultaneous connections")
    sockets = []
    ports = [80, 443, 8080, 8000, 3000, 5432, 3306, 6379, 9200, 27017]
    for i in range(count):
        port = random.choice(ports)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((host, port))
            sockets.append(s)
        except Exception:
            pass
            
    print(f"[Trigger] Holding {len(sockets)} connections for 5s…")
    time.sleep(5)
    for s in sockets:
        try: s.close()
        except: pass
    print("[Trigger] Connection spike complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["port_scan", "syn_flood", "conn_spike"], default="port_scan")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if args.mode == "port_scan": port_scan(args.host)
    elif args.mode == "syn_flood": syn_flood(args.host)
    elif args.mode == "conn_spike": connection_spike(args.host)