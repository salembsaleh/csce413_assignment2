#!/usr/bin/env python3
"""Port knocking server."""

import argparse
import logging
import socket
import time
import subprocess

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0

# Extra: Add timing constraints (sequence must complete within 30 seconds)
DEFAULT_ALLOW_SECONDS = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port, src_ip):
    """Open the protected port using firewall rules."""
    subprocess.run(
        [
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "-s",
            src_ip,
            "--dport",
            str(protected_port),
            "-j",
            "ACCEPT",
        ],
        check=False,
    )
    logging.info("Opening port %s for %s", protected_port, src_ip)


def close_protected_port(protected_port, src_ip):
    """Close the protected port using firewall rules."""
    subprocess.run(
        [
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "-s",
            src_ip,
            "--dport",
            str(protected_port),
            "-j",
            "ACCEPT",
        ],
        check=False,
    )
    logging.info("Closing port %s for %s", protected_port, src_ip)


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # Default deny (insert DROP only if it doesn't already exist)
    drop_rule = [
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        str(protected_port),
        "-j",
        "DROP",
    ]

    exists = subprocess.run(["iptables", "-C"] + drop_rule, check=False).returncode == 0
    if not exists:
        subprocess.run(["iptables", "-I"] + drop_rule, check=False)

    sockets = {}
    for port in sequence:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        sockets[port] = s

    progress = {}
    open_until = {}

    while True:
        now = time.time()

        # Close expired ports
        for ip, expiry in list(open_until.items()):
            if now >= expiry:
                close_protected_port(protected_port, ip)
                del open_until[ip]

        for port, sock in sockets.items():
            sock.settimeout(0.5)
            try:
                _, (src_ip, _) = sock.recvfrom(1024)
            except socket.timeout:
                continue

            if src_ip in open_until:
                continue

            if src_ip not in progress:
                if port == sequence[0]:
                    progress[src_ip] = (1, now)
                    logger.info("Sequence started for %s", src_ip)
                continue

            idx, start = progress[src_ip]

            if now - start > window_seconds:
                logger.info("Sequence timed out for %s", src_ip)
                del progress[src_ip]
                continue

            if port == sequence[idx]:
                idx += 1
                if idx == len(sequence):
                    logger.info("Sequence complete for %s", src_ip)
                    open_protected_port(protected_port, src_ip)
                    open_until[src_ip] = now + DEFAULT_ALLOW_SECONDS
                    del progress[src_ip]
                else:
                    progress[src_ip] = (idx, start)
            else:
                logger.info("Wrong knock from %s, resetting", src_ip)
                del progress[src_ip]


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
