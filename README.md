# SDN Security Controller (Ryu) with Embedded Web API

## What this is
This package contains:
- controller.py: your Ryu controller updated to expose a Web API and serve the dashboard HTML pages.
- firewall.py / ddos.py: unchanged policy engines.
- policies/: JSON policy files (firewall_policy.json, ddos_policy.json)
- frontend/: the dashboard HTML pages (no mock traffic/alerts; only what exists in backend)

## Run (Ubuntu)
1) Copy this folder into: ~/sdn-security/  (or any folder)
2) Install Ryu (if not installed):
   sudo apt update
   sudo apt install -y python3-pip
   pip install ryu
3) Start the controller:
   cd ~/sdn-security
   ryu-manager controller.py

## Open the dashboard
By default Ryu WSGI listens on port 8080.
Open:
- http://127.0.0.1:8080/overview.html

## API endpoints
- GET  /api/health
- GET  /api/overview
- GET  /api/firewall/blocked-ips
- POST /api/firewall/blocked-ips/add    {"ip":"10.0.0.7"}
- POST /api/firewall/blocked-ips/remove {"ip":"10.0.0.7"}
- GET  /api/firewall/deny-rules
- POST /api/reload   (reloads JSON policies into memory)

Notes:
- Updating blocked_ips updates both the JSON file and the in-memory FirewallEngine immediately.
- Removing already-installed OpenFlow drop rules is NOT implemented in this version.
