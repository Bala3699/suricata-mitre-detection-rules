
# 🛡️ Suricata MITRE ATT&CK Detection Rules

## 📌 Repository Overview

This repository contains a custom set of **Suricata IDS/IPS detection rules** mapped to the **MITRE ATT&CK framework**.  

The project focuses on building practical **detection engineering skills** by simulating adversary behaviors and generating alerts based on real-world attack techniques in a controlled lab environment.

It is designed for learning **SOC operations, network security monitoring, and threat detection engineering**.

---

## 🎯 Project Objective

The main goal of this project is to:

- Develop custom Suricata detection rules
- Map network behaviors to MITRE ATT&CK techniques
- Simulate adversary activities in a lab environment
- Generate and analyze security alerts
- Understand SOC detection workflows

---

## 🧠 Detection Coverage

This rule set includes detection logic for:

- 🔍 Reconnaissance (Scanning, enumeration)
- 🌐 Network Service Discovery
- 💥 Brute Force Attacks
- 🧬 Payload-based detection
- 🔐 Credential Access attempts
- 🧭 Command & Control (C2) behavior
- 📤 Data Exfiltration patterns
- 🕶️ Defense Evasion techniques
- 🔁 Lateral movement detection
- 🧪 IDS evasion testing patterns

---

## 🧰 Technologies Used

- Suricata IDS/IPS
- Linux (Ubuntu)
- MITRE ATT&CK Framework
- Wireshark
- Nmap
- Bash scripting

---

## 📁 Project Structure

```bash
suricata-mitre-detection-rules/
│
├── rules/
│   └── mitre.rules        # All Suricata detection rules
│
── Alert/
│   ├── alert.sh           # Traffic simulation / trigger scripts (optional)
│   └── attack_simulation.sh # Script for executing specific attack techniques
│
├── logs/
│   └── suricata.log       # Generated alert logs
│
├── screenshots/
│   └── alerts.png         # Evidence of rule execution
│
└── README.md
````

---

## ⚙️ How It Works

1. Traffic is generated using tools such as:

   * Nmap (scanning)
   * Hydra (brute force)
   * Curl / Wget (payload simulation)
   * Custom bash scripts

2. Suricata monitors network traffic in real-time

3. If traffic matches a rule in `mitre.rules`, an alert is generated:

```text
[ALERT] MITRE T1110 - SSH Brute Force Detected
```

4. Alerts are logged for analysis and investigation

---

## 🧾 Example Suricata Rule

```suricata
alert tcp any any -> $HOME_NET 22 (
    msg:"MITRE T1110 - SSH Brute Force Attempt";
    flow:to_server;
    threshold:type both, track by_src, count 5, seconds 60;
    sid:100001;
    rev:1;
)
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name                    |
| ------------ | --------------------------------- |
| T1595        | Active Scanning                   |
| T1046        | Network Service Discovery         |
| T1110        | Brute Force                       |
| T1059        | Command and Scripting Interpreter |
| T1105        | Ingress Tool Transfer             |
| T1041        | Exfiltration Over C2 Channel      |
| T1071        | Application Layer Protocol        |

---

## 📊 Key Features

* Custom IDS rule creation
* MITRE ATT&CK mapping
* Real-time alert generation
* Network traffic analysis
* SOC-style detection simulation
* Controlled lab testing environment

---

## 🧪 Testing Methodology

The rules were tested using:

* Network scanning (Nmap)
* Brute force simulation (Hydra)
* HTTP payload injection tests
* DNS query simulation
* Reverse shell / C2 behavior simulation
* Custom traffic generation scripts

---

## 📸 Screenshots 
https://github.com/Bala3699/suricata-mitre-detection-rules/edit/main/MITRE%20ATT%26CK/Readme.md
![Alert](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/WhatsApp%20Image%202026-05-13%20at%2011.34.29%20AM.jpeg)
![Alert2](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/WhatsApp%20Image%202026-05-13%20at%2011.34.38%20AM.jpeg)
![Aler3](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/asdf.jpeg)
![Aler4](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/AS.jpeg)
![Aler5](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/ads.jpeg)
![Aler6](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/dsa.jpeg)
![Aler7](https://github.com/Bala3699/suricata-mitre-detection-rules/blob/main/MITRE%20ATT%26CK/Pic/eww.jpeg)
---

## 📚 Learning Outcomes

This project helped me gain practical experience in:

* Detection engineering fundamentals
* Writing Suricata IDS rules
* SOC alert analysis workflows
* MITRE ATT&CK mapping
* Network traffic inspection
* False positive vs true positive tuning
* Security monitoring concepts

---

## ⚠️ Disclaimer

This project is strictly for **educational and cybersecurity research purposes only**.
All testing was performed in a **controlled lab environment**.

---

## 📄 License

This project is licensed under the **MIT License**.

### MIT License Summary:

You are free to:

* Use
* Copy
* Modify
* Distribute

But you must include the original license and attribution.

Full license text:

```text
MIT License

Copyright (c) 2026 Bala Murugan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## 👨‍💻 Author

**Bala Murugan**
Cybersecurity | SOC Analyst | Detection Engineering | Blue Team Learner

---

## 🚀 Project Impact

This project demonstrates practical skills in:

* SOC detection engineering
* Network security monitoring
* IDS rule development
* Threat behavior simulation
* MITRE ATT&CK-based detection mapping

---


