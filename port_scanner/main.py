#!/usr/bin/env python3
"""
Port Scanner
"""

import socket
import sys
import time
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


# Service fingerprinting
def guess_service(port, banner):
    if banner:
        b = banner.lower()
        if "ssh" in b:
            return "ssh"
        if "mysql" in b:
            return "mysql"
        if "redis" in b:
            return "redis"
        if "http" in b or "<html" in b:
            return "http"
    common = {
        22: "ssh",
        80: "http",
        443: "https",
        3306: "mysql",
        6379: "redis",
        8888: "http",
        5000: "http",
        5001: "http",
        2222: "ssh",
    }
    return common.get(port, "unknown")


def is_httpish_port(port: int) -> bool:
    return port in (80, 443, 8000, 8080, 5000, 5001, 8888)


def grab_banner_tcp(sock: socket.socket, port: int) -> str:
    """
    Best-effort banner grabbing:
    - Try to read immediately (SSH often sends a banner)
    - For HTTP-ish ports, send a HEAD request to coax headers
    """
    # 1) Immediate read
    try:
        sock.settimeout(0.5)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").strip()
    except Exception:
        pass

    # 2) HTTP probe
    if is_httpish_port(port):
        try:
            sock.settimeout(0.5)
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            data = sock.recv(2048)
            if data:
                return data.decode(errors="ignore").strip()
        except Exception:
            pass

    return ""


# TCP connect scan
def scan_port_tcp(target, port, timeout):
    start = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        banner = grab_banner_tcp(sock, port)
        rtt = (time.time() - start) * 1000

        return {
            "host": target,
            "port": port,
            "proto": "tcp",
            "state": "open",
            "rtt_ms": round(rtt, 1),
            "service": guess_service(port, banner),
            "banner": banner
        }

    except socket.timeout:
        rtt = (time.time() - start) * 1000
        return {
            "host": target,
            "port": port,
            "proto": "tcp",
            "state": "filtered",
            "rtt_ms": round(rtt, 1),
            "service": "unknown",
            "banner": ""
        }

    except (ConnectionRefusedError, OSError):
        rtt = (time.time() - start) * 1000
        return {
            "host": target,
            "port": port,
            "proto": "tcp",
            "state": "closed",
            "rtt_ms": round(rtt, 1),
            "service": "unknown",
            "banner": ""
        }

    finally:
        if sock:
            sock.close()


# UDP scan
def scan_port_udp(target, port, timeout):
    start = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (target, port))

        # If we get a UDP payload back, call it open
        sock.recvfrom(1024)

        rtt = (time.time() - start) * 1000
        return {
            "host": target,
            "port": port,
            "proto": "udp",
            "state": "open",
            "rtt_ms": round(rtt, 1),
            "service": "unknown",
            "banner": ""
        }

    except socket.timeout:
        # No response is ambiguous for UDP
        rtt = (time.time() - start) * 1000
        return {
            "host": target,
            "port": port,
            "proto": "udp",
            "state": "open|filtered",
            "rtt_ms": round(rtt, 1),
            "service": "unknown",
            "banner": ""
        }

    except OSError:
        # Often indicates ICMP port unreachable => closed
        rtt = (time.time() - start) * 1000
        return {
            "host": target,
            "port": port,
            "proto": "udp",
            "state": "closed",
            "rtt_ms": round(rtt, 1),
            "service": "unknown",
            "banner": ""
        }

    finally:
        if sock:
            sock.close()


# Scan range with threading
def scan_range(targets, start_port, end_port, scan_type, threads, timeout):
    results = []
    ports = range(start_port, end_port + 1)
    total = len(targets) * len(ports)
    done = 0

    def worker(host, port):
        if scan_type == "udp":
            return scan_port_udp(host, port, timeout)
        return scan_port_tcp(host, port, timeout)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for host in targets:
            for port in ports:
                futures.append(executor.submit(worker, host, port))

        for f in as_completed(futures):
            done += 1
            if done % 200 == 0 or done == total:
                print(f"[*] Progress: {done}/{total}")
            results.append(f.result())

    return results


# Main
def main():
    if len(sys.argv) < 5:
        print("Usage:")
        print("  python3 main.py <target|CIDR> <start_port> <end_port> <tcp|udp> [show_closed]")
        print("Examples:")
        print("  python3 main.py 172.20.0.21 1 10000 tcp")
        print("  python3 main.py 172.20.0.0/24 8888 8888 tcp")
        print("  python3 main.py 172.20.0.22 6379 6385 udp show_closed")
        sys.exit(1)

    target_input = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    scan_type = sys.argv[4].lower()
    show_closed = (len(sys.argv) >= 6 and sys.argv[5].lower() == "show_closed")

    if scan_type not in ("tcp", "udp"):
        print("Scan type must be 'tcp' or 'udp'")
        sys.exit(1)

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Port range must be valid and within 1-65535")
        sys.exit(1)

    timeout = 0.5
    threads = 200

    # CIDR support
    if "/" in target_input:
        targets = [str(ip) for ip in ipaddress.ip_network(target_input, strict=False).hosts()]
    else:
        targets = [target_input]

    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Ports: {start_port}-{end_port}")
    print(f"[*] Scan type: {scan_type}")

    results = scan_range(targets, start_port, end_port, scan_type, threads, timeout)

    # Summary
    open_results = [r for r in results if r["state"] == "open"]
    closed_results = [r for r in results if r["state"] == "closed"]
    filtered_results = [r for r in results if r["state"] == "filtered"]
    ambiguous_results = [r for r in results if r["state"] == "open|filtered"]

    print("\n[+] Results:")
    print(f"    open: {len(open_results)}")
    print(f"    closed: {len(closed_results)}")
    if scan_type == "tcp":
        print(f"    filtered: {len(filtered_results)}")
    else:
        print(f"    open|filtered: {len(ambiguous_results)}")

    # Output
    print("\n[+] Ports:")
    for r in results:
        if not show_closed and r["state"] == "closed":
            continue
        svc = r["service"]
        banner = r.get("banner", "")
        # Keep banner short in terminal
        banner_short = (banner[:100] + ("..." if len(banner) > 100 else "")) if banner else ""
        line = f"{r['host']}:{r['port']}/{r['proto']}  {r['state']:12s}  {svc:8s}  {r['rtt_ms']}ms"
        if banner_short:
            line += f"  | {banner_short}"
        print(line)

    # JSON/CSV output
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n[+] Results saved to scan_results.json")

    with open("scan_results.csv", "w") as f:
        f.write("host,port,proto,state,service,rtt_ms,banner\n")
        for r in results:
            banner = (r.get("banner", "") or "").replace('"', '""').replace("\n", "\\n").replace("\r", "")
            f.write(f'{r["host"]},{r["port"]},{r["proto"]},{r["state"]},{r["service"]},{r["rtt_ms"]},"{banner}"\n')
    print("[+] Results saved to scan_results.csv")


if __name__ == "__main__":
    main()