# AWS Honeypot Threat Intelligence

I deployed a Cowrie SSH/Telnet honeypot on AWS and left it running for about 6 months. Over that period it logged **1,001,468 events** from **7,241 unique IP addresses** across **139,027 sessions**. This repo contains the analysis scripts I used to process those logs and the threat intelligence report I generated from them.

## What This Project Does

The honeypot sits on an AWS EC2 instance and pretends to be a vulnerable SSH server. Attackers find it through automated scanning, try to brute-force their way in, and once they get a shell, they run commands, download malware, and try to spread further. Cowrie captures all of it — every login attempt, every command, every file download.

I then pulled the logs off the server and wrote a Python script to chew through the JSON log files and spit out a full threat intelligence report as a Word document, complete with charts and tables.

## Key Findings

| Metric | Value |
|--------|-------|
| Total Events | 1,001,468 |
| Collection Period | Sep 10, 2025 – Mar 10, 2026 (181 days) |
| Unique Source IPs | 7,241 |
| Total Sessions | 139,027 |
| Login Attempts | 126,042 (68.6% success rate) |
| Unique Malware Samples | 3,824 |
| Commands Captured | 102,632 |
| Countries Represented | 30 |
| MITRE ATT&CK Techniques Mapped | 7 |

The top attacking country was China by a wide margin (287K+ events), followed by Hong Kong and Indonesia. The most common credentials were `root/3245gs5662d34` and `root/root` — a mix of what looks like a targeted botnet credential and the usual default password suspects.

After getting in, most attackers ran recon commands (`uname`, `whoami`, checking CPU info and memory), injected SSH keys for persistence, and attempted to download malware from external C2 servers. I extracted 18 unique C2 URLs and cataloged 3,824 unique malware samples by SHA256 hash.

## Architecture

```
                           ┌───────────────────────────────────────┐
                           │  AWS EC2 (t2.micro)                   │
                           │                                       │
┌──────────────────┐       │  ┌─────────────────────────────────┐  │
│  Attacker Traffic │──────▶│  │  Docker                         │  │
│  Port 22  ───────────────▶│  │  Port 22 → 2222 (Cowrie SSH)   │  │
│  Port 23  ───────────────▶│  │  Port 23 → 2223 (Cowrie Telnet)│  │
└──────────────────┘       │  └─────────────────────────────────┘  │
                           │                                       │
┌──────────────────┐       │  ┌─────────────────────────────────┐  │
│  Admin (My IP)   │──────▶│  │  Real SSH on port 22222         │  │
│  Port 22222      │       │  └─────────────────────────────────┘  │
└──────────────────┘       └──────────────────┬────────────────────┘
                                              │ docker cp + SCP
                                              ▼
                           ┌───────────────────────────────────────┐
                           │  Local Machine                        │
                           │  Logs → Google Drive → Colab Analysis │
                           │  → Threat Intel Report (.docx)        │
                           └───────────────────────────────────────┘
```

### Security Group Rules

| Rule | Port | Source | Purpose |
|------|------|--------|---------|
| SSH (honeypot) | 22 | 0.0.0.0/0 | Open to internet — attracts attackers |
| Telnet (honeypot) | 23 | 0.0.0.0/0 | Open to internet — Cowrie Telnet trap |
| SSH (admin) | 22222 | My IP only | Secure management access |

## How I Built It

### 1. EC2 Setup
Spun up a **t2.micro** instance on AWS — Cowrie is lightweight, so there was no need for anything bigger. Configured the security group to expose ports 22 and 23 to the internet (that's the whole point — let the attackers in), while restricting the real SSH port to my IP only. I changed the EC2 instance's actual SSH daemon to listen on port 22222:

```
# /etc/ssh/sshd_config
Port 22222
```

This freed up port 22 for the honeypot and kept my admin access locked down. I connected to the instance via SSH from PowerShell on port 22222 for all management tasks.

### 2. Honeypot Deployment
Installed Docker on the EC2 instance and ran Cowrie inside a container. The port mapping in Docker handled the routing:

```yaml
ports:
  - "22:2222"    # External SSH → Cowrie SSH
  - "23:2223"    # External Telnet → Cowrie Telnet
```

So from an attacker's perspective, they're hitting a normal SSH server on port 22. Docker forwards that to Cowrie's internal port 2222, where it simulates a real shell environment and logs everything — login attempts, commands, file downloads, all written to JSON log files inside the container.

The actual EC2 system was never exposed to attackers. Even if someone "logged in" successfully, they were contained inside Cowrie's emulated environment with no access to the real host.

### 3. Log Collection
Once I had enough data, I pulled the logs out in two steps:
- Used `docker cp` to copy the log directory from the Cowrie container to the EC2 host
- Used `scp` with my SSH key (on port 22222) to transfer the logs from EC2 to my local machine

I then uploaded the logs to Google Drive so I could work with them in Colab.

### 4. Analysis & Report Generation
Wrote a Python script in Google Colab that:
- Parses all the JSON log files from Cowrie
- Counts and ranks source IPs, credentials, commands, sessions
- Categorizes post-compromise commands by intent (recon, persistence, defense evasion, etc.)
- Looks up geolocation and ISP data for the top attacking IPs using the ip-api.com API
- Maps observed activity to MITRE ATT&CK techniques
- Generates 7 different chart types (area charts, bar charts, pie chart) with matplotlib
- Builds a full Word document report with python-docx, including tables, embedded charts, styled headings, and a title page

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Observations |
|---|---|---|---|
| T1595 | Active Scanning | Reconnaissance | 132,770 |
| T1110 | Brute Force | Credential Access | 39,611 |
| T1078 | Valid Accounts | Initial Access | 86,431 |
| T1059 | Command & Scripting Interpreter | Execution | 108,773 |
| T1105 | Ingress Tool Transfer | Command & Control | 15,235 |
| T1572 | Protocol Tunneling | Command & Control | 113 |

## Interesting Observations

**The SSH key injection was everywhere.** Over 10,000 sessions included a sequence that deleted the existing `.ssh` directory, created a new one, and dropped in an attacker-controlled authorized key. That's T1098 (Account Manipulation) in practice — once that key is planted, the attacker has persistent access even if the password changes.

**Peak day: December 16, 2025** saw 210,913 events — nearly 40x the daily average. Worth investigating whether that was a single botnet ramping up or a coordinated scanning campaign.

**Most attackers were automated.** The average session lasted just 5.5 seconds. These aren't humans poking around — they're scripts that log in, run a handful of commands, drop malware, and move on to the next target.

**HTTP requests on an SSH port.** 317 connections sent `GET / HTTP/1.1` as their SSH version string. These are web scanners that found port 22 open and tried HTTP anyway, which tells you how indiscriminate large-scale scanning really is.

## Repo Structure

```
├── README.md                  ← You're here
├── report/
│   └── cowrie_threat_report.docx   ← Final threat intelligence report
├── notebooks/
│   └── honeypot_analysis.ipynb     ← Google Colab notebook
├── scripts/
│   └── honeypot_analysis.py        ← Standalone analysis script
└── visuals/
    ├── daily_events.png
    ├── top_source_ips.png
    ├── geo_distribution.png
    ├── credential_pie.png
    ├── top_usernames.png
    ├── top_passwords.png
    └── command_categories.png
```

## Dependencies

Only three pip packages beyond the standard library:

```bash
pip install python-docx matplotlib requests
```

Everything else (`json`, `collections`, `datetime`, `pathlib`, `hashlib`, etc.) is built into Python.

## What I'd Do Differently Next Time

- **Pipe logs to S3 in real-time** instead of manually copying them out with docker cp + scp. Would make the whole pipeline more hands-off.
- **Add more honeypot protocols.** Cowrie handles SSH and Telnet, but deploying HTTP, RDP, and SMB honeypots alongside it would give a much broader picture of attacker behavior.
- **Feed logs into a SIEM.** Running the analysis as a batch job works, but streaming into Splunk or Wazuh would enable real-time alerting and correlation.
- **Automate the report generation** on a weekly cadence so you can spot trends as they develop rather than analyzing 6 months of data at once.

## Author

**Sai Krishna Masetti**
- [LinkedIn](https://www.linkedin.com/in/sai-krishna-masetti)
- [Portfolio](https://saikrishna-masetti.github.io/)
