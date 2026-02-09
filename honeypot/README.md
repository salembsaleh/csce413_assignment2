## SSH Honeypot Implementation

This honeypot simulates a fake SSH service designed to attract and log unauthorized access attempts. The goal is to observe attacker behavior without exposing any real system or credentials.

### Design Overview

The honeypot runs a fake SSH server implemented using Python and the `paramiko` library. It listens on port 2222 and presents itself as a legitimate OpenSSH server running on Ubuntu.

Authentication is intentionally designed to fail a few times before allowing a fake login. This helps capture both brute-force attempts and post-login attacker behavior.

### Features Implemented

#### Required Features

- Fake SSH service with a realistic OpenSSH banner
- Logging of all connections, including source IP, port, and session duration
- Authentication attempt logging, capturing attempted usernames and passwords
- Fake interactive shell to capture attacker commands
- Command logging, including common reconnaissance commands
- Readable log output in `honeypot.log`
- Structured event logging using `events.jsonl` for easy analysis

#### Bonus Features

- Alerting on multiple failed login attempts
- Suspicious command detection
- Webhook-based alerts that send notifications to a Discord channel

### Logging Structure

- `honeypot.log`: High-level events and alerts
- `events.jsonl`: Detailed structured logs for connections, authentication attempts, commands, and disconnects
