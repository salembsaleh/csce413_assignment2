## Port Knocking

### Required Functionality
- A client that sends a sequence of UDP packets (knocks) to specific ports
- A server that listens for these knocks
- The SSH port (2222) is blocked by default
- The protected port is only open after the correct sequence is received in order

### Implementation Details

#### Port Knocking Client
- The client sends UDP packets to each port in the knock sequence
- A small delay is added between knocks to avoid packet loss
- After sending the full sequence, the client optionally checks whether the protected port is open

#### Port Knocking Server
- The server listens on all knock ports using UDP sockets
- Each source IP is tracked individually and must complete the sequence in order
- If the sequence is incorrect or takes too long, progress is reset
- Once the correct sequence is completed:
  - An iptables rule is added to allow TCP access to port 2222 only for that source IP
- After a fixed timeout, the firewall rule is automatically removed


### Firewall Behavior
- Port 2222 is blocked by default using iptables
- Access is granted dynamically and temporarily
- This prevents unauthorized scanning or brute-force attempts on the SSH service


### Extra Features
- Per-IP tracking so multiple clients can attempt knocking independently
- Time window enforcement (the full sequence must be completed within a set number of seconds)
- Automatic port re-locking after a successful connection window expires
- Timeouts in the demo script to prevent hanging when ports are filtered

