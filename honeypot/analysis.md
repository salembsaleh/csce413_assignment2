# Honeypot Analysis

## Summary of Observed Attacks

- During testing, the SSH honeypot successfully captured multiple unauthorized access attempts. All activity originated from the Docker bridge network IP `172.20.0.1`, simulating an attacker connecting from another container or host.

- The attacker attempted to authenticate as user `sshuser` using several common weak passwords such as `admin`, `password`, and `123456`. After multiple failed login attempts, the honeypot triggered an alert and then intentionally allowed a fake login to capture post-authentication behavior.

- Once inside the fake shell, the attacker executed several reconnaissance-style commands including `whoami`, `pwd`, `ls`, `uname -a`, and multiple `cat` attempts on files and directories. These commands are consistent with typical attacker behavior after gaining initial access.

- The session lasted approximately 145 seconds before the attacker exited.


## Notable Patterns

- **Brute-force behavior:** Multiple password guesses were attempted in quick succession, triggering the `multiple_failed_logins` alert.
- **Post-compromise reconnaissance:** Commands like `whoami`, `pwd`, `ls`, and `uname -a` indicate the attacker was trying to understand the system environment.
- **File probing:** Repeated attempts to access files and directories (`cat notes.txt`, `cat .ssh`) suggest interest in sensitive data.
- **No advanced exploitation observed:** No malware download or privilege escalation commands were detected during this session.


## Recommendations

- Continue monitoring for repeated brute-force attempts from the same IP addresses and consider automatically blacklisting them.
- Expand suspicious command detection to include additional attack patterns.
- Add more realistic fake filesystem content to further observe attacker behavior.
- Deploy alerting mechanisms (email or webhook) to notify administrators in real time when suspicious activity is detected.