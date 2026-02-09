#!/usr/bin/env python3
"""Honeypot Assignment"""

import os
import socket
import threading
import time

import paramiko

from logger import alert, create_logger, log_event

HOST = "0.0.0.0"
PORT = 2222

# Generate a host key at startup
HOST_KEY = paramiko.RSAKey.generate(2048)

# Convincing banner
SERVER_VERSION = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

# How many failed attempts before they enter honeypot
MAX_FAILS_BEFORE_FAKE_SUCCESS = 2

# Known attack paterns (bonus)
SUSPICIOUS_SUBSTRINGS = [
    "curl",
    "nc ",
]


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, logger):
        self.client_ip = client_ip
        self.client_port = client_port
        self.logger = logger

        self.username = None
        self._fails = 0
        self._allow_shell = threading.Event()

        # Track session start for duration
        self.start_ts = time.time()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.username = username
        self._fails += 1

        log_event(
            {
                "event": "auth_attempt",
                "client_ip": self.client_ip,
                "client_port": self.client_port,
                "username": username,
                "password": password,
                "attempt": self._fails,
            }
        )

        # Alert on multiple failed attempts (bonus)
        if self._fails >= 3:
            alert(
                self.logger,
                "multiple_failed_logins",
                client_ip=self.client_ip,
                username=username,
                fails=self._fails,
            )

        # Fake success after N failures
        if self._fails > MAX_FAILS_BEFORE_FAKE_SUCCESS:
            log_event(
                {
                    "event": "auth_result",
                    "client_ip": self.client_ip,
                    "client_port": self.client_port,
                    "username": username,
                    "result": "fake_success",
                }
            )
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self._allow_shell.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # Logs: ssh user@host
        cmd = command.decode(errors="ignore")
        log_event(
            {
                "event": "command_exec",
                "client_ip": self.client_ip,
                "client_port": self.client_port,
                "username": self.username or "unknown",
                "command": cmd,
            }
        )

        lower = cmd.lower()
        if any(x in lower for x in SUSPICIOUS_SUBSTRINGS):
            alert(
                self.logger,
                "suspicious_command",
                client_ip=self.client_ip,
                username=self.username or "unknown",
                command=cmd,
            )

        # Send a realistic response
        channel.send(f"{cmd}: command not found\n")
        channel.send_exit_status(127)
        return True


def fake_shell(chan: paramiko.Channel, server: HoneypotServer):
    """Very small fake shell that logs commands typed interactively."""
    user = server.username or "user"
    prompt = f"{user}@ubuntu:~$ "

    chan.send(
        "\r\nWelcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-xx-generic x86_64)\r\n"
    )
    chan.send("Last login: Mon Feb  9 06:00:00 2026 from 10.0.0.5\r\n\r\n")

    while True:
        chan.send(prompt)
        data = chan.recv(4096)
        if not data:
            return

        cmd = data.decode(errors="ignore").strip()
        if not cmd:
            continue
        log_event(
            {
                "event": "command",
                "client_ip": server.client_ip,
                "client_port": server.client_port,
                "username": user,
                "command": cmd,
            }
        )

        lower = cmd.lower()
        if any(x in lower for x in SUSPICIOUS_SUBSTRINGS):
            alert(
                server.logger,
                "suspicious_command",
                client_ip=server.client_ip,
                username=user,
                command=cmd,
            )

        if lower in ("exit", "logout", "quit"):
            chan.send("logout\r\n")
            return
        elif lower == "whoami":
            chan.send(f"{user}\r\n")
        elif lower == "pwd":
            chan.send(f"/home/{user}\r\n")
        elif lower == "ls":
            chan.send("Documents  Downloads  .ssh  notes.txt\r\n")
        elif lower.startswith("cat "):
            chan.send("Permission denied\r\n")
        elif lower == "uname -a":
            chan.send(
                "Linux ubuntu 5.15.0-xx-generic #xx-Ubuntu SMP x86_64 GNU/Linux\r\n"
            )
        else:
            chan.send(f"{cmd}: command not found\r\n")


def handle_client(sock: socket.socket, addr, logger):
    client_ip, client_port = addr[0], addr[1]
    start = time.time()

    log_event(
        {"event": "connection", "client_ip": client_ip, "client_port": client_port}
    )

    transport = paramiko.Transport(sock)
    transport.add_server_key(HOST_KEY)
    transport.local_version = SERVER_VERSION

    server = HoneypotServer(client_ip, client_port, logger)

    try:
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            return

        # If they request a shell, serve the fake shell
        if server._allow_shell.wait(10):
            fake_shell(chan, server)

    except Exception:
        pass
    finally:
        duration = round(time.time() - start, 3)
        log_event(
            {
                "event": "disconnect",
                "client_ip": client_ip,
                "client_port": client_port,
                "duration_seconds": duration,
            }
        )
        try:
            transport.close()
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass


def run_honeypot():
    logger = create_logger()
    logger.info("SSH honeypot listening on %s:%s", HOST, PORT)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(100)

    while True:
        client, addr = s.accept()
        t = threading.Thread(
            target=handle_client, args=(client, addr, logger), daemon=True
        )
        t.start()


if __name__ == "__main__":
    run_honeypot()
