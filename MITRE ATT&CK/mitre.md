
# 🛡️ MITRE ATT&CK Suricata Detection Rules Documentation

## 📌 Overview

This document contains the detailed explanation of all **Suricata IDS detection rules** implemented in this project and their mapping to the **MITRE ATT&CK framework**.

Each rule is designed to detect specific adversary behaviors such as scanning, brute force, payload delivery, lateral movement, and data exfiltration.

---

## 🎯 Purpose

The purpose of these rules is to:

- Detect malicious or suspicious network behavior
- Map network activity to MITRE ATT&CK techniques
- Simulate SOC detection engineering workflows
- Generate alerts for security analysis
- Understand real-world attacker behavior patterns

---

## 🧠 Detection Categories

The rules are grouped into the following attack phases:

### 🔍 1. Reconnaissance (TA0043)

Detects early-stage attacker activity such as scanning and enumeration.

**Techniques covered:**
- T1595 → Active Scanning (Nmap, Nikto, SQLMap)
- T1046 → Network Service Discovery

---

### 💥 2. Execution (TA0002)

Detects payload execution and malicious command activity.

**Techniques covered:**
- T1059 → Command and Scripting Interpreter
- T1203 → Exploitation for Client Execution

---

### 🔐 3. Credential Access (TA0006)

Detects brute force and credential theft attempts.

**Techniques covered:**
- T1110 → Brute Force (SSH, FTP, SMB, Telnet)
- T1557 → Adversary-in-the-Middle (LLMNR/NBT-NS Poisoning)
- T1040 → Network Sniffing (MITM behavior)

---

### 🔁 4. Lateral Movement (TA0008)

Detects movement inside the network.

**Techniques covered:**
- T1021.004 → SSH Remote Services
- T1021.002 → SMB Enumeration

---

### 🧭 5. Command & Control (TA0011)

Detects communication with attacker-controlled systems.

**Techniques covered:**
- T1071 → Application Layer Protocol (HTTP/DNS)
- T1090 → Proxy / SOCKS tunneling
- T1105 → Ingress Tool Transfer
- T1071.004 → DNS Tunneling

---

### 📤 6. Exfiltration (TA0010)

Detects data theft or leakage.

**Techniques covered:**
- T1041 → Exfiltration over C2 Channel
- T1048 → Exfiltration over Alternative Protocol
- T1030 → Large Data Transfer

---

### 🕶️ 7. Defense Evasion (TA0005)

Detects attempts to hide malicious activity.

**Techniques covered:**
- T1027 → Obfuscated Files or Information
- T1070.006 → Timestomping
- T1562.001 → Impair Defenses
- T1036 → Masquerading

---

### ⚙️ 8. Persistence (TA0003)

Detects long-term access techniques.

**Techniques covered:**
- T1546.004 → Bash profile modification
- T1505 → Web shell behavior

---

## 🧾 Rule Format Example

All Suricata rules follow this structure:

```suricata
alert tcp any any -> $HOME_NET 22 (
    msg:"MITRE T1110 - SSH Brute Force Attempt";
    flow:to_server;
    threshold:type both, track by_src, count 5, seconds 60;
    sid:100001;
    rev:1;
)
````

---

## 📊 MITRE Mapping Table (Sample)

| SID    | Technique ID | Technique Name    |
| ------ | ------------ | ----------------- |
| 100001 | T1110        | Brute Force       |
| 100002 | T1595        | Active Scanning   |
| 100003 | T1046        | Network Discovery |
| 100004 | T1059        | Command Execution |
| 100005 | T1071        | C2 Communication  |

---

## ⚙️ Detection Logic Summary

These rules mainly use:

* Packet inspection (TCP/UDP/HTTP/DNS)
* Keyword matching (payload signatures)
* Threshold-based detection (rate of requests)
* Flow tracking (established connections)
* Protocol analysis (HTTP headers, DNS queries)

---

## 🧪 Testing Environment

All rules are tested in a controlled lab using:

* Nmap (Scanning)
* Hydra (Brute Force)
* Curl/Wget (HTTP payloads)
* Custom Bash scripts
* Simulated C2 traffic

---

## ⚠️ Important Note

These rules are **not production-tuned IDS rules**.
They are designed for:

* Learning purposes
* SOC training
* Detection engineering practice
* MITRE ATT&CK simulation

---

## 👨‍💻 Author

**Bala Murugan**
SOC Analyst | Cybersecurity Learner | Detection Engineering | Blue Team

---

