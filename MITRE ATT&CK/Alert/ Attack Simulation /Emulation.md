# ⚔️ Adversary Emulation & Detection Validation Lab

## Overview

This project is a Linux-based adversary emulation and SOC validation framework designed for:

* Network visibility testing
* Detection engineering validation
* MITRE ATT&CK simulation
* Suricata / IDS / IPS rule validation
* EDR telemetry generation
* Blue-team alert testing
* Layer 3–7 traffic generation
* Security monitoring demonstrations

The framework generates controlled attack-like behaviors inside a lab environment to help defenders:

* Validate detections
* Tune IDS signatures
* Improve alert fidelity
* Test SIEM pipelines
* Observe endpoint telemetry
* Correlate MITRE ATT&CK techniques

---

# ⚠️ Important Notice

This project is intended strictly for:

* Authorized security labs
* Detection engineering
* Defensive security research
* SOC training
* Purple-team exercises
* Academic cybersecurity testing

Do NOT run this framework:

* On production networks
* Against unauthorized systems
* On public infrastructure
* On third-party environments

The author is not responsible for misuse.

---

# 🧠 Project Purpose

Modern SOC environments require realistic telemetry to validate:

* Suricata rules
* SIEM detections
* EDR alerts
* MITRE ATT&CK mappings
* Threat hunting logic
* Network anomaly detection
* Behavioral analytics

This framework creates:

* Reconnaissance traffic
* Layer-7 traffic
* Credential access patterns
* Discovery behavior
* Simulated lateral movement
* Exfiltration indicators
* Adversary-in-the-middle telemetry
* Flooding and anomaly traffic
* Service enumeration patterns
* Beaconing behavior

---

# 🏗️ Architecture

The workflow consists of:

1. Environment Discovery
2. Dependency Installation
3. Service Preparation
4. Network Telemetry Generation
5. ATT&CK Technique Simulation
6. Detection Triggering
7. Cleanup & Recovery

---

# ⚙️ Payload Delivery Workflow

The project demonstrates:

* Base64 payload encoding
* ELF payload generation
* Script reconstruction
* Temporary execution flow

## Encoding Phase

The bash simulation script is encoded into Base64:

```bash
base64 -w 0 script.sh > encoded_alert.txt
```

## Payload Generation

An ELF payload is generated using Metasploit:

```bash
msfvenom -p linux/x64/exec \
CMD="echo <BASE64> | base64 -d > /tmp/script.sh && chmod +x /tmp/script.sh && /tmp/script.sh" \
-f elf -o network.elf
```

## Execution Flow

The payload:

1. Recreates the script in `/tmp`
2. Grants execute permissions
3. Executes the simulation framework
4. Generates SOC telemetry
5. Performs cleanup

---

# 🔍 Core Functional Areas

---

# 1. Environment & Network Discovery

The framework automatically identifies:

* Active network interface
* Local IP address
* Default gateway
* Public IP address
* Wireless interface usage
* Routing information

## Purpose

This phase creates baseline telemetry associated with:

* System discovery
* Network discovery
* Host identification
* Environment awareness

## Detection Opportunities

* Host enumeration alerts
* Interface discovery monitoring
* Network configuration discovery
* Command execution telemetry

---

# 2. Dependency & Service Provisioning

The script validates and installs tools required for telemetry generation.

## Installed Components

### Reconnaissance

* Nmap
* Nikto
* DNS utilities
* SNMP utilities

### Traffic Generation

* Curl
* Netcat
* OpenSSL
* Socat

### Credential & Access Simulation

* Hydra
* SMB client
* SSH services

### Network Manipulation

* Bettercap
* Arpspoof
* Responder
* Hping3

### Data & Protocol Testing

* SQLMap
* SIP tools
* SMB tools
* SNMP tools

## Services Started

* Apache
* SSH
* SMB
* SNMP

## Purpose

Creates realistic enterprise-like services for:

* Port discovery
* Enumeration
* Service fingerprinting
* Authentication telemetry

---

# 3. Layer 7 Traffic Simulation

The framework generates extensive application-layer traffic.

## Behaviors

* HTTP requests
* HTTPS requests
* TLS handshakes
* DNS lookups
* DIG queries
* SMTP simulation
* IMAP traffic
* SMB enumeration
* SIP traffic

## Detection Value

Useful for validating:

* Suricata Layer-7 rules
* TLS fingerprinting
* HTTP anomaly detection
* DNS monitoring
* Protocol analytics
* SIEM correlation

---

# 4. Reconnaissance Simulation

The project simulates reconnaissance activity commonly mapped to MITRE ATT&CK.

## Behaviors

* Port scanning
* Service discovery
* Vulnerability scanning
* Banner grabbing
* NSE scripting
* Web enumeration
* Gateway probing

## Tools Used

* Nmap
* Nikto
* Netcat

## ATT&CK Techniques

| Technique | Description               |
| --------- | ------------------------- |
| T1046     | Network Service Discovery |
| T1595     | Active Scanning           |
| T1595.002 | Vulnerability Scanning    |
| T1018     | Remote System Discovery   |

---

# 5. Credential Access Simulation

The framework generates credential-access-like telemetry.

## Behaviors

* SSH brute-force simulation
* SMB brute-force attempts
* Password pattern generation
* Shadow file access attempts
* Password-store discovery

## Detection Opportunities

* Brute-force alerts
* Credential access analytics
* Privilege monitoring
* Authentication anomaly detection

## ATT&CK Techniques

| Technique | Description                      |
| --------- | -------------------------------- |
| T1110     | Brute Force                      |
| T1003.008 | OS Credential Dumping            |
| T1555     | Credentials from Password Stores |

---

# 6. Command & Control Simulation

The framework generates C2-style network behavior.

## Behaviors

* Beaconing traffic
* Repeated HTTP requests
* Simulated exfiltration
* Proxy/tunnel-like traffic
* Encoded payload transfers

## Detection Opportunities

* Beacon detection
* Data exfiltration monitoring
* HTTP anomaly detection
* DNS anomaly detection
* Long-lived connection analysis

## ATT&CK Techniques

| Technique | Description                            |
| --------- | -------------------------------------- |
| T1071.001 | Application Layer Protocol             |
| T1048     | Exfiltration Over Alternative Protocol |
| T1090     | Proxy                                  |
| T1041     | Exfiltration Over C2 Channel           |

---

# 7. Adversary-in-the-Middle Simulation

The project contains controlled simulations of network interception behaviors.

## Components

* ARP spoofing simulation
* Bettercap traffic manipulation
* Responder telemetry
* Network sniffing behaviors
* Target rotation logic

## Detection Opportunities

* ARP anomaly detection
* MITM detection
* LLMNR/NBT-NS monitoring
* Rogue responder alerts
* Network spoofing telemetry

## ATT&CK Techniques

| Technique | Description             |
| --------- | ----------------------- |
| T1557     | Adversary-in-the-Middle |
| T1557.001 | LLMNR/NBT-NS Poisoning  |

---

# 8. Discovery & Enumeration Behaviors

The framework simulates extensive system and network discovery activity.

## Behaviors

* User discovery
* Group discovery
* OS discovery
* Interface discovery
* Account discovery
* Active connection enumeration

## Detection Opportunities

* Discovery sequence analytics
* Host profiling alerts
* Process telemetry correlation
* Command auditing

## ATT&CK Techniques

| Technique | Description                            |
| --------- | -------------------------------------- |
| T1082     | System Information Discovery           |
| T1033     | System Owner/User Discovery            |
| T1016     | System Network Configuration Discovery |
| T1087     | Account Discovery                      |

---

# 9. Defense Evasion & Anti-Forensics Simulation

The project generates behavior associated with anti-forensics and evasion.

## Behaviors

* Bash history clearing
* Timestomping simulation
* Logout trigger creation
* Permission modifications
* Persistence-like configuration changes

## Detection Opportunities

* Audit log monitoring
* Persistence detection
* File integrity monitoring
* Shell profile modification alerts

## ATT&CK Techniques

| Technique | Description                                 |
| --------- | ------------------------------------------- |
| T1070.002 | Clear Linux or Mac System Logs              |
| T1070.006 | Timestomp                                   |
| T1546.004 | Unix Shell Configuration Modification       |
| T1222.002 | File and Directory Permissions Modification |

---

# 10. Flooding & Anomaly Traffic

The framework creates high-volume and anomalous traffic patterns.

## Behaviors

* SYN flood patterns
* UDP flood patterns
* ICMP flood patterns
* DNS flood traffic
* Heavy payload transmission

## Detection Opportunities

* IDS flood detection
* Rate anomaly monitoring
* Traffic spike analytics
* DoS detection tuning

---

# 11. SQL Injection & Web Attack Simulation

The framework generates web attack telemetry.

## Behaviors

* SQL injection patterns
* Path traversal patterns
* Script injection payloads
* Encoded exfiltration payloads
* Automated SQLMap scanning

## Detection Opportunities

* WAF validation
* HTTP signature testing
* Payload decoding analytics
* Layer-7 inspection

---

# 12. Persistence Simulation

The framework simulates persistence-like modifications.

## Behaviors

* Cron job creation
* Shell configuration modification
* Logout trigger persistence
* Temporary boot script simulation

## Detection Opportunities

* Persistence analytics
* Scheduled task monitoring
* Configuration integrity alerts

---

# 13. Data Exfiltration Simulation

The framework generates exfiltration-style telemetry.

## Behaviors

* HTTP POST uploads
* Base64 encoded transfers
* TCP file transfer simulation
* DNS-based signaling
* High-volume transfers

## Detection Opportunities

* DLP validation
* Egress monitoring
* Encoded payload detection
* Data transfer analytics

---

# 🧹 Cleanup & Recovery

The framework performs automatic cleanup.

## Cleanup Operations

* Terminates spawned processes
* Removes temporary files
* Clears generated artifacts
* Stops temporary listeners
* Resets networking state
* Removes generated payloads

## Purpose

Ensures:

* Safer lab recovery
* Reduced environmental impact
* Easier repeated testing
* Minimal leftover artifacts

---

# 🛡️ Detection Engineering Value

This framework is useful for:

## SOC Analysts

* Alert validation
* Incident simulation
* Detection triage practice

## Detection Engineers

* Suricata rule testing
* SIEM parser validation
* Behavioral analytics tuning

## Threat Hunters

* IOC generation
* ATT&CK correlation
* Telemetry baselining

## Purple Teams

* Defensive control testing
* ATT&CK coverage analysis
* End-to-end detection validation

---

# 📊 MITRE ATT&CK Coverage

The framework touches multiple ATT&CK tactics:

| Tactic            | Examples              |
| ----------------- | --------------------- |
| Reconnaissance    | T1595                 |
| Discovery         | T1082, T1016          |
| Credential Access | T1110, T1003          |
| Persistence       | T1546                 |
| Defense Evasion   | T1070                 |
| Command & Control | T1071                 |
| Exfiltration      | T1041, T1048          |
| Lateral Movement  | T1021                 |
| Collection        | T1005                 |
| Impact            | Flood/DoS simulations |

---

# 🔥 Key Features

* Automated attack telemetry generation
* Large-scale protocol coverage
* Layer 3–7 traffic simulation
* MITRE ATT&CK alignment
* Multi-tool orchestration
* Automated dependency handling
* Base64 payload execution workflow
* Cleanup automation
* Detection engineering focus
* SOC-ready telemetry generation

---

# 🧪 Recommended Lab Setup

## Recommended Environment

* Ubuntu/Kali Linux
* Isolated virtual network
* Suricata IDS/IPS
* ELK Stack / Splunk / Wazuh
* Security Onion
* VMware / VirtualBox / Proxmox


---

# 📌 Example Use Cases

* Suricata signature validation
* SIEM detection engineering
* Blue-team labs
* SOC analyst training
* Threat hunting exercises
* Purple-team operations
* ATT&CK mapping demonstrations
* Academic research

---

# 🚀 Future Improvements

Potential enhancements:

* Automated ATT&CK reporting
* JSON telemetry export
* Containerized deployment
* Zeek integration
* Sigma rule generation
* Wazuh decoder integration
* Real-time dashboarding
* Automated PCAP generation

---

# 📜 License

This project is intended for educational and authorized defensive security research only.

Use responsibly and only within environments you own or are explicitly authorized to test.

---

# 👨‍💻 Author Notes

This project demonstrates how realistic adversary behaviors can be emulated to:

* Improve SOC visibility
* Strengthen detection logic
* Validate defensive tooling
* Train analysts using realistic telemetry

The focus is:

* Detection engineering
* Defensive operations
* ATT&CK-driven simulations
* Security monitoring validation

---

# ⭐ Repository Highlights

* MITRE ATT&CK aligned
* Multi-stage adversary emulation
* Suricata detection validation
* Layer 7 telemetry generation
* Automated cleanup workflow
* Detection engineering focused
* Blue-team oriented research project
