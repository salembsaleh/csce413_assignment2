# Honeypot Analysis

## Summary of Observed Attacks
- During testing, the SSH honeypot successfully captured multiple unauthorized access attempts. All activity was from from the IP `172.20.0.1`.
- The attacker attempted to authenticate as user `sshuser` using several common weak passwords such as `admin`, `password`, and `123456`. After multiple failed login attempts, the honeypot triggered an alert and then allowed a fake login.
- Once inside the fake shell, the attacker executed several reconnaissance-style commands including `whoami`, `pwd`, `ls`, and multiple `cat` attempts on files and directories.


## Notable Patterns
- Multiple password guesses were attempted in quick succession, triggering the `multiple_failed_logins` alert.
- Commands like `whoami`, `pwd`, `ls`, and `uname -a` indicate the attacker was trying to understand the system environment.
- Repeated attempts to access files and directories (`cat notes.txt`, `cat .ssh`) which shows the user was trying to access sensitive data.

## Recommendations
- Continue monitoring for repeated brute-force attempts from the same IP addresses and consider automatically blacklisting them.
- Expand suspicious command detection to include additional attack patterns.
- Add more realistic fake filesystem content to further observe attacker behavior.