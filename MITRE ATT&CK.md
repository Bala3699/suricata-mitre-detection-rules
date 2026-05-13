# MITRE ATT&CK Detection Engineering using Suricata IDS

## Overview

This project contains a collection of custom Suricata IDS detection rules mapped to the MITRE ATT&CK framework for detecting suspicious and potentially malicious network activity in a controlled cybersecurity lab environment.

The objective of this project is to improve understanding of:

- Detection Engineering
- SOC Monitoring Workflows
- IDS Rule Development
- Network Threat Detection
- Security Telemetry Analysis
- MITRE ATT&CK Technique Mapping

The rules were manually developed and tested against simulated network behaviors to validate alert generation and improve practical blue-team detection skills.

---

# Features

- Custom Suricata IDS detection rules
- MITRE ATT&CK mapped detections
- Detection validation and alert testing
- Network traffic monitoring
- Security telemetry analysis
- Reconnaissance detection
- Brute-force detection
- Reverse shell detection
- Command & Control detection
- DNS tunneling detection
- Exfiltration monitoring
- Defense evasion detection

---

# Technologies Used

| Technology | Purpose |
|---|---|
| Suricata IDS | Intrusion Detection |
| Linux | Lab Environment |
| Bash | Testing & Automation |
| MITRE ATT&CK Framework | Threat Mapping |
| Wireshark | Packet Analysis |
| Nmap | Reconnaissance Simulation |

---

# Repository Structure

```bash
.
├── README.md
│
├── rules/
│   └── mitre.rules
│
├── screenshots/
│   ├── suricata-alerts.png
│   ├── fast-log-output.png
│   ├── wireshark-analysis.png
│   └── rule-validation.png
│
├── logs/
│   └── sample-alerts.log
│
├── docs/
│   ├── mitre-mapping.md
│   └── rule-explanations.md
│
└── LICENSE
```

---

# Detection Categories

## Reconnaissance (TA0043)

Detection logic includes:

- SYN scanning
- Nmap NSE probing
- Vulnerability scanning
- Nikto detection
- SQLMap detection
- Banner grabbing
- Ping sweeps

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1595 | Active Scanning |
| T1595.002 | Vulnerability Scanning |
| T1046 | Network Service Discovery |
| T1018 | Remote System Discovery |

---

## Initial Access (TA0001)

Detection logic includes:

- SQL injection attempts
- Path traversal attempts
- Public-facing application exploitation
- Suspicious POST requests

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1190 | Exploit Public-Facing Application |

---

## Execution (TA0002)

Detection logic includes:

- PowerShell encoded commands
- Reverse shell indicators
- Command injection attempts
- Payload execution patterns
- Suspicious shell commands

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.004 | Unix Shell |
| T1203 | Exploitation for Client Execution |

---

## Persistence (TA0003)

Detection logic includes:

- `.bashrc` modification
- Web shell indicators
- XSS injection patterns

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1546.004 | Unix Shell Configuration Modification |
| T1505 | Server Software Component |

---

## Privilege Escalation (TA0004)

Detection logic includes:

- Meterpreter migration patterns
- Process injection indicators
- Shellcode transfer artifacts

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1055 | Process Injection |

---

## Defense Evasion (TA0005)

Detection logic includes:

- Base64 obfuscation
- XOR encoded payloads
- Shikata Ga Nai patterns
- Firewall enumeration
- Timestomping
- File permission modification

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1027 | Obfuscated Files or Information |
| T1070.006 | Timestomp |
| T1222.002 | File and Directory Permissions Modification |
| T1562.001 | Impair Defenses |

---

## Credential Access (TA0006)

Detection logic includes:

- SSH brute-force attempts
- SMB brute-force attempts
- FTP brute-force attempts
- Telnet brute-force attempts
- LLMNR poisoning
- NBT-NS poisoning
- Shadow file access detection
- MITM indicators

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1110 | Brute Force |
| T1110.001 | Password Guessing |
| T1557.001 | LLMNR/NBT-NS Poisoning |
| T1003.008 | OS Credential Dumping |
| T1040 | Network Sniffing |

---

## Discovery (TA0007)

Detection logic includes:

- SMB enumeration
- MSSQL scanning
- RDP scanning
- SNMP enumeration
- SSH banner grabbing
- SIP probes

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1046 | Network Service Discovery |
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |

---

## Lateral Movement (TA0008)

Detection logic includes:

- SSH lateral movement
- SMB share enumeration

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1021.004 | SSH |
| T1021.002 | SMB/Admin Shares |

---

## Command and Control (TA0011)

Detection logic includes:

- HTTP beaconing
- Meterpreter traffic
- DNS tunneling
- SOCKS proxy traffic
- Reverse shell communication
- Encoded traffic streams

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1071.001 | Web Protocols |
| T1071.004 | DNS |
| T1090 | Proxy |
| T1132 | Data Encoding |
| T1105 | Ingress Tool Transfer |

---

## Exfiltration (TA0010)

Detection logic includes:

- Base64 data exfiltration
- SSH private key transfer
- Sensitive file transfer
- Large file downloads

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1041 | Exfiltration Over C2 Channel |
| T1048 | Exfiltration Over Alternative Protocol |
| T1030 | Data Transfer Size Limits |

---

## Impact (TA0040)

Detection logic includes:

- ICMP flood detection
- SYN flood detection
- UDP flood detection
- DNS flood activity
- Xmas flood patterns

### MITRE Techniques

| Technique ID | Technique Name |
|---|---|
| T1498.001 | Direct Network Flood |

---

# Example Rule

```rules
alert tcp any any -> $HOME_NET 22 (
    msg:"MITRE T1110.001 Brute Force - SSH Login Attempts";
    flow:to_server,established;
    threshold:type both, track by_src, count 10, seconds 10;
    metadata:
        attack_stage Credential_Access,
        mitre_tactic_id TA0006,
        mitre_tactic_name Credential_Access,
        mitre_technique_id T1110,
        mitre_technique_name Brute_Force,
        mitre_subtechnique_id T1110.001,
        mitre_subtechnique_name Password_Guessing;
    sid:100017;
    rev:2;
)
```

---

# Rule Components

| Component | Description |
|---|---|
| alert | Generates alert when rule matches |
| tcp/http/dns | Protocol being inspected |
| flow | Traffic direction |
| content | Pattern matching logic |
| threshold | Alert rate limiting |
| metadata | MITRE ATT&CK mapping |
| sid | Unique rule identifier |
| rev | Rule revision |

---

# Sample Alert

```text
[**] [1:100017:2] MITRE T1110.001 Brute Force - SSH Login Attempts [**]
[Classification: Attempted Administrator Privilege Gain]
[Priority: 2]
05/12/2026-18:22:10.123456 192.168.1.5 -> 192.168.1.10
TCP TTL:64 TOS:0x0 ID:39421 IpLen:20 DgmLen:40
```

---

# Learning Outcomes

Through this project, I gained practical experience in:

- Writing custom Suricata rules
- Detection engineering workflows
- IDS alert validation
- Threat detection methodologies
- Network traffic analysis
- MITRE ATT&CK mapping
- SOC monitoring concepts
- Security telemetry analysis

---

# Screenshots

Recommended screenshots to include:

- Suricata alert terminal output
- fast.log alerts
- Wireshark packet captures
- Rule trigger validation
- DNS tunneling detections
- Reverse shell alerts
- MITRE ATT&CK mapped detections

---

# Future Improvements

Planned future enhancements include:

- Sigma rule conversion
- SIEM integration
- Elastic Stack dashboards
- EVE JSON correlation
- Advanced behavioral detections
- Automated alert analysis
- Detection tuning and optimization

---

# Educational Purpose

This project was developed strictly for:

- Educational purposes
- Detection engineering practice
- Defensive cybersecurity research
- Controlled lab simulations

Do not use these rules or testing methods against systems without authorization.

---

# Author

**Bala Murugan**

Cybersecurity | SOC | Detection Engineering | Network Security

---

# GitHub Topics

```text
cybersecurity
suricata
mitre-attack
detection-engineering
soc
ids
network-security
blue-team
threat-detection
linux
```

---

# License

This project is intended for educational and research purposes only.
