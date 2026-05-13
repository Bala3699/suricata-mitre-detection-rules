# ============================================================
# Suricata MITRE ATT&CK Rules — Generated from aler.sh
# ============================================================

# -----------------------------------------------------------
# CASE 33 / TA0043 — RECONNAISSANCE
# -----------------------------------------------------------

# T1595 — Active Scanning: SYN Scan (nmap -sS)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1595 Active Scanning - Possible SYN Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 3; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id none; sid:100001; rev:3;)

# T1595.002 — Vulnerability Scanning: Nikto Web Scanner User-Agent
alert http any any -> $HOME_NET any (msg:"MITRE T1595.002 Vulnerability Scanning - Nikto Scanner Detected"; flow:to_server,established; http.user_agent; content:"Nikto"; nocase; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id T1595.002, mitre_subtechnique_name Vulnerability_Scanning; sid:100002; rev:2;)

# T1595.002 — Vulnerability Scanning: Nikto Custom User-Agent
alert http any any -> $HOME_NET any (msg:"MITRE T1595.002 Vulnerability Scanning - Nikto Custom User-Agent"; flow:to_server,established; http.user_agent; content:"Mozilla/5.0"; nocase; http.uri; content:".php"; nocase; threshold:type both, track by_src, count 15, seconds 10; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id T1595.002, mitre_subtechnique_name Vulnerability_Scanning; sid:100003; rev:2;)

# T1046 — Network Service Discovery: Port Scan (nmap -sV, nc -zv)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1046 Network Service Discovery - Sequential Port Scan"; flags:S; threshold:type both, track by_src, count 15, seconds 5; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100004; rev:2;)

# T1595 — Active Scanning: sqlmap User-Agent
alert http any any -> $HOME_NET any (msg:"MITRE T1595 Active Scanning - SQLMap User-Agent Detected"; flow:to_server,established; http.user_agent; content:"sqlmap"; nocase; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id none; sid:100005; rev:2;)

# T1595 — Active Scanning: NSE Vuln Scripts (nmap --script vuln)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1595 Active Scanning - Nmap NSE Script Probe"; flow:to_server,established; content:"Nmap Scripting Engine"; nocase; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id none; sid:100006; rev:2;)

# -----------------------------------------------------------
# CASE 34 — NETWORK-BASED ATTACKS
# -----------------------------------------------------------

# T1498.001 — Network DoS: ICMP Flood (ping -f)
alert icmp any any -> $HOME_NET any (msg:"MITRE T1498.001 Network DoS - ICMP Flood"; itype:8; threshold:type both, track by_src, count 100, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100007; rev:2;)

# T1498.001 — Network DoS: SYN Flood on port 445 (hping3 -S --flood -p 445)
alert tcp any any -> $HOME_NET 445 (msg:"MITRE T1498.001 Network DoS - TCP SYN Flood Port 445"; flow:to_server; flags:S; threshold:type both, track by_src, count 100, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100008; rev:3;)

# T1498.001 — Network DoS: SYN Flood on port 443 (hping3 -S --flood -p 443)
alert tcp any any -> $HOME_NET 443 (msg:"MITRE T1498.001 Network DoS - TCP SYN Flood Port 443"; flow:to_server; flags:S; threshold:type both, track by_src, count 100, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100009; rev:3;)

# T1498.001 — Network DoS: UDP Flood (hping3 --udp --flood)
alert udp any any -> $HOME_NET any (msg:"MITRE T1498.001 Network DoS - UDP Flood"; threshold:type both, track by_src, count 100, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100010; rev:2;)

# T1498.001 — Network DoS: Xmas Flood (hping3 -X --flood)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1498.001 Network DoS - TCP Xmas Scan Flood"; flags:FPU; threshold:type both, track by_src, count 50, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100011; rev:2;)

# T1498.001 — Network DoS: UDP DNS Flood (hping3 --udp -p 53 --flood)
alert udp any any -> $HOME_NET 53 (msg:"MITRE T1498.001 Network DoS - UDP DNS Flood"; threshold:type both, track by_src, count 100, seconds 3; metadata:attack_stage Impact, mitre_tactic_id TA0040, mitre_tactic_name Impact, mitre_technique_id T1498, mitre_technique_name Network_Denial_of_Service, mitre_subtechnique_id T1498.001, mitre_subtechnique_name Direct_Network_Flood; sid:100012; rev:2;)

# -----------------------------------------------------------
# CASE 34 — PAYLOAD-BASED ATTACKS
# -----------------------------------------------------------

# T1203 — Exploitation: Malware Keyword over TCP port 80
alert tcp any any -> $HOME_NET 80 (msg:"MITRE T1203 Exploitation - Malware Keyword in TCP Payload"; flow:to_server,established; content:"malware attack exploit"; nocase; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1203, mitre_technique_name Exploitation_for_Client_Execution, mitre_subtechnique_id none; sid:100013; rev:2;)

# T1203 — Exploitation: EICAR Test File
alert tcp any any -> $HOME_NET 80 (msg:"MITRE T1203 Exploitation - EICAR Antivirus Test String"; flow:to_server,established; content:"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1203, mitre_technique_name Exploitation_for_Client_Execution, mitre_subtechnique_id none; sid:100014; rev:2;)

# T1595 — Banner Grabbing via HTTP HEAD
alert http any any -> $HOME_NET any (msg:"MITRE T1595 Active Scanning - HTTP HEAD Banner Grabbing"; flow:to_server,established; http.method; content:"HEAD"; metadata:attack_stage Reconnaissance, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id none; sid:100015; rev:2;)

# T1059.004 — Command Injection via TCP
alert tcp any any -> $HOME_NET 80 (msg:"MITRE T1059.004 Unix Shell Command Injection - id whoami via NC"; flow:to_server,established; content:"|3b| id|3b|"; nocase; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1059, mitre_technique_name Command_and_Scripting_Interpreter, mitre_subtechnique_id T1059.004, mitre_subtechnique_name Unix_Shell; sid:100016; rev:2;)

# -----------------------------------------------------------
# CASE 35 — CREDENTIAL ACCESS
# -----------------------------------------------------------

# T1110.001 — Brute Force: SSH (hydra)
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1110.001 Brute Force - SSH Login Attempts"; flow:to_server,established; threshold:type both, track by_src, count 10, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1110, mitre_technique_name Brute_Force, mitre_subtechnique_id T1110.001, mitre_subtechnique_name Password_Guessing; sid:100017; rev:2;)

# T1110.001 — Brute Force: SMB (hydra smb)
alert tcp any any -> $HOME_NET 445 (msg:"MITRE T1110.001 Brute Force - SMB Login Attempts"; flow:to_server,established; threshold:type both, track by_src, count 10, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1110, mitre_technique_name Brute_Force, mitre_subtechnique_id T1110.001, mitre_subtechnique_name Password_Guessing; sid:100018; rev:2;)

# T1110.001 — Brute Force: FTP (hydra -s 21)
alert tcp any any -> $HOME_NET 21 (msg:"MITRE T1110.001 Brute Force - FTP Login Attempts"; flow:to_server,established; threshold:type both, track by_src, count 10, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1110, mitre_technique_name Brute_Force, mitre_subtechnique_id T1110.001, mitre_subtechnique_name Password_Guessing; sid:100019; rev:2;)

# T1110.001 — Brute Force: Telnet (hydra -s 23)
alert tcp any any -> $HOME_NET 23 (msg:"MITRE T1110.001 Brute Force - Telnet Login Attempts"; flow:to_server,established; threshold:type both, track by_src, count 10, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1110, mitre_technique_name Brute_Force, mitre_subtechnique_id T1110.001, mitre_subtechnique_name Password_Guessing; sid:100020; rev:2;)

# T1557.001 — LLMNR/NBT-NS Poisoning: Responder
alert udp any any -> $HOME_NET 5355 (msg:"MITRE T1557.001 LLMNR Poisoning - Responder LLMNR Probe"; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1557, mitre_technique_name Adversary_in_the_Middle, mitre_subtechnique_id T1557.001, mitre_subtechnique_name LLMNR_NBT_NS_Poisoning; sid:100021; rev:2;)

# T1557.001 — NBT-NS Poisoning: Responder
alert udp any any -> $HOME_NET 137 (msg:"MITRE T1557.001 NBT-NS Poisoning - Responder NBT-NS Probe"; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1557, mitre_technique_name Adversary_in_the_Middle, mitre_subtechnique_id T1557.001, mitre_subtechnique_name LLMNR_NBT_NS_Poisoning; sid:100022; rev:2;)

# -----------------------------------------------------------
# CASE 11 — EXFILTRATION & C2
# -----------------------------------------------------------

# T1041 — Exfiltration Over C2: Sensitive File via Raw TCP
alert tcp $HOME_NET any -> any 8080 (msg:"MITRE T1041 Exfiltration Over C2 Channel - Possible Sensitive Data via TCP 8080"; flow:to_server,established; content:"root:"; metadata:attack_stage Exfiltration, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1041, mitre_technique_name Exfiltration_Over_C2_Channel, mitre_subtechnique_id none; sid:100023; rev:2;)

# T1048 — Exfiltration Over Alternative Protocol: Base64 POST
alert http any any -> any any (msg:"MITRE T1048 Exfiltration Over Alternative Protocol - Base64 Encoded POST Data"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"data="; content:"SENSITIVE"; nocase; metadata:attack_stage Exfiltration, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1048, mitre_technique_name Exfiltration_Over_Alternative_Protocol, mitre_subtechnique_id none; sid:100024; rev:2;)

# T1041 — Exfiltration: SSH Private Key Keyword over TCP 80
alert tcp any any -> $HOME_NET 80 (msg:"MITRE T1041 Exfiltration - SSH Private Key Keyword in Traffic"; flow:to_server,established; content:"BEGIN RSA PRIVATE KEY"; metadata:attack_stage Exfiltration, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1041, mitre_technique_name Exfiltration_Over_C2_Channel, mitre_subtechnique_id none; sid:100025; rev:2;)

# -----------------------------------------------------------
# CASE 12 — SQL INJECTION (T1190)
# -----------------------------------------------------------

# T1190 — Exploit Public-Facing Application: SQL Injection Pattern
alert http any any -> $HOME_NET any (msg:"MITRE T1190 Exploit Public-Facing Application - SQL Injection OR 1=1"; flow:to_server,established; http.uri; content:"OR 1=1"; nocase; metadata:attack_stage Initial_Access, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public-Facing_Application, mitre_subtechnique_id none; sid:100026; rev:2;)

# T1190 — Exploit Public-Facing Application: Path Traversal
alert http any any -> $HOME_NET any (msg:"MITRE T1190 Exploit Public-Facing Application - Path Traversal /etc/passwd"; flow:to_server,established; http.uri; content:"../"; content:"etc/passwd"; nocase; metadata:attack_stage Initial_Access, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public-Facing_Application, mitre_subtechnique_id none; sid:100027; rev:2;)

# T1190 — Exploit Public-Facing Application: Base64 /etc/passwd Exfil via POST
alert http any any -> $HOME_NET any (msg:"MITRE T1190 Exploit Public-Facing Application - Base64 passwd Exfil POST"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"exfil="; metadata:attack_stage Initial_Access, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public-Facing_Application, mitre_subtechnique_id none; sid:100028; rev:2;)

# -----------------------------------------------------------
# CASE 13 — T1046: NETWORK SERVICE DISCOVERY
# -----------------------------------------------------------

# T1046 — Service Discovery: SMB (port 445)
alert tcp any any -> $HOME_NET 445 (msg:"MITRE T1046 Network Service Scanning - SMB Probe Port 445"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100029; rev:3;)

# T1046 — Service Discovery: MSSQL (port 1433)
alert tcp any any -> $HOME_NET 1433 (msg:"MITRE T1046 Network Service Scanning - MSSQL Probe Port 1433"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100030; rev:3;)

# T1046 — Service Discovery: RDP (port 3389)
alert tcp any any -> $HOME_NET 3389 (msg:"MITRE T1046 Network Service Scanning - RDP Probe Port 3389"; flow:to_server; flags:S; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100031; rev:3;)

# -----------------------------------------------------------
# CASE 14 — T1021.004: REMOTE SERVICES (SSH)
# -----------------------------------------------------------

# T1021.004 — Remote Services: SSH Lateral Movement Attempt
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1021.004 Remote Services - SSH Lateral Movement Attempt"; flow:to_server,established; content:"SSH-"; threshold:type both, track by_src, count 3, seconds 60; metadata:attack_stage Lateral_Movement, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1021, mitre_technique_name Remote_Services, mitre_subtechnique_id T1021.004, mitre_subtechnique_name SSH; sid:100032; rev:2;)

# -----------------------------------------------------------
# CASE 15 — T1071.001: APPLICATION LAYER PROTOCOL (C2 Beaconing)
# -----------------------------------------------------------

# T1071.001 — C2 Beaconing: Custom User-Agent to External Host
alert http $HOME_NET any -> any any (msg:"MITRE T1071.001 C2 Beaconing - Suspicious User-Agent C2-Emulator"; flow:to_server,established; http.user_agent; content:"C2-Emulator"; nocase; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.001, mitre_subtechnique_name Web_Protocols; sid:100033; rev:2;)

# -----------------------------------------------------------
# CASE 16 — T1048: EXFILTRATION OVER ALTERNATIVE PROTOCOL
# -----------------------------------------------------------

# T1048 — Exfiltration: Base64 POST to External Host
alert http $HOME_NET any -> any any (msg:"MITRE T1048 Exfiltration Over Alternative Protocol - Base64 POST to External"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/post"; nocase; metadata:attack_stage Exfiltration, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1048, mitre_technique_name Exfiltration_Over_Alternative_Protocol, mitre_subtechnique_id none; sid:100034; rev:2;)

# -----------------------------------------------------------
# CASE 17 — DISCOVERY (T1082, T1033, T1016, T1087)
# -----------------------------------------------------------

# T1082 — System Information Discovery: SSH Banner Grab
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1082 System Information Discovery - SSH Banner Grab"; flow:to_server,established; content:"SSH-"; threshold:type both, track by_src, count 3, seconds 30; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1082, mitre_technique_name System_Information_Discovery, mitre_subtechnique_id none; sid:100035; rev:2;)

# T1016 — System Network Config Discovery: SNMP Enumeration
alert udp any any -> $HOME_NET 161 (msg:"MITRE T1016 System Network Config Discovery - SNMP Walk Enumeration"; content:"|30|"; depth:1; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1016, mitre_technique_name System_Network_Configuration_Discovery, mitre_subtechnique_id none; sid:100036; rev:2;)

# -----------------------------------------------------------
# CASE 18 — T1003.008: CREDENTIAL ACCESS (Shadow File)
# -----------------------------------------------------------

# T1003.008 — OS Credential Dumping: /etc/shadow access over network
alert tcp $HOME_NET any -> any any (msg:"MITRE T1003.008 Credential Dumping - Shadow File Content Detected"; flow:to_server,established; content:"root:$"; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1003, mitre_technique_name OS_Credential_Dumping, mitre_subtechnique_id T1003.008, mitre_subtechnique_name /etc/passwd_and_/etc/shadow; sid:100037; rev:2;)

# -----------------------------------------------------------
# CASE 21 — T1071.004: DNS TUNNELING / EXFILTRATION
# -----------------------------------------------------------

# T1071.004 — DNS Tunneling: High-volume DNS queries (DGA pattern)
alert dns any any -> any 53 (msg:"MITRE T1071.004 DNS Tunneling - High Volume DNS Queries Possible DGA"; threshold:type both, track by_src, count 20, seconds 10; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.004, mitre_subtechnique_name DNS; sid:100038; rev:2;)

# T1071.004 — DNS Tunneling: Suspicious long subdomain query
alert dns any any -> any 53 (msg:"MITRE T1071.004 DNS Tunneling - Unusually Long DNS Query Name"; dns.query; pcre:"/[a-z0-9]{20,}\.(com|net|org|io)/i"; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.004, mitre_subtechnique_name DNS; sid:100039; rev:2;)

# -----------------------------------------------------------
# CASE 23 — T1090: PROXY / SSH TUNNEL
# -----------------------------------------------------------

# T1090 — Proxy: SOCKS proxy via SSH tunnel (-D 1080)
alert tcp any any -> $HOME_NET 1080 (msg:"MITRE T1090 Proxy - SOCKS Proxy Connection on Port 1080"; flow:to_server,established; flags:S; threshold:type both, track by_src, count 3, seconds 30; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1090, mitre_technique_name Proxy, mitre_subtechnique_id none; sid:100040; rev:2;)

# -----------------------------------------------------------
# CASE 22 — T1562.001: DISABLE / MODIFY TOOLS (Firewall Check)
# -----------------------------------------------------------

# T1562.001 — Impair Defenses: Firewall Enumeration (ufw status) over SSH
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1562.001 Impair Defenses - Possible Firewall Enumeration over SSH"; flow:to_server,established; content:"ufw"; nocase; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1562, mitre_technique_name Impair_Defenses, mitre_subtechnique_id T1562.001, mitre_subtechnique_name Disable_or_Modify_Tools; sid:100041; rev:2;)

# -----------------------------------------------------------
# CASE 36 — T1110 EXTERNAL BRUTE FORCE + T1046 LATERAL SCAN
# -----------------------------------------------------------

# T1110 — Brute Force: SSH against Live Hosts (hydra)
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1110 Brute Force - Aggressive SSH Brute Force External Target"; flow:to_server,established; threshold:type both, track by_src, count 20, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1110, mitre_technique_name Brute_Force, mitre_subtechnique_id none; sid:100042; rev:2;)

# T1046 — Port Scan: Web/SMB/SSH against other LAN hosts
alert tcp any any -> $HOME_NET [22,80,443,445] (msg:"MITRE T1046 Network Service Scanning - Targeted Port Scan 22/80/443/445"; flow:to_server; flags:S; threshold:type both, track by_src, count 10, seconds 5; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100043; rev:3;)

# -----------------------------------------------------------
# CASE 37 — T1557: ADVERSARY IN THE MIDDLE (ARP Spoof / Bettercap)
# -----------------------------------------------------------

# T1557.002 — ARP Cache Poisoning: Gratuitous ARP flood
alert tcp any any -> $HOME_NET any (msg:"MITRE T1557.002 ARP Cache Poisoning - Gratuitous ARP Flood - Enable arp detection in suricata.yaml if needed"; flags:S; threshold:type both, track by_src, count 30, seconds 5; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1557, mitre_technique_name Adversary_in_the_Middle, mitre_subtechnique_id T1557.002, mitre_subtechnique_name ARP_Cache_Poisoning; sid:100044; rev:2;)

# -----------------------------------------------------------
# CASE 9 — T1071 / T1105: DOWNLOAD FROM SUSPICIOUS IPs
# -----------------------------------------------------------

# T1105 — Ingress Tool Transfer: Download from hardcoded suspicious IPs
alert http $HOME_NET any -> [102.130.113.30,102.130.113.42,102.130.113.9,102.130.115.59,102.130.117.167,102.130.117.25,102.130.119.48,102.130.127.117,102.205.44.23,102.205.44.250,102.205.44.36,102.205.44.5] any (msg:"MITRE T1105 Ingress Tool Transfer - HTTP Request to Suspicious Hardcoded IP"; flow:to_server,established; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1105, mitre_technique_name Ingress_Tool_Transfer, mitre_subtechnique_id none; sid:100045; rev:2;)

# -----------------------------------------------------------
# CASE 34 — T1040: NETWORK SNIFFING (bettercap net.sniff)
# -----------------------------------------------------------

# T1040 — Network Sniffing: ARP full-duplex spoof with sniffing
alert tcp any any -> $HOME_NET 8080 (msg:"MITRE T1040 Network Sniffing - Possible MITM Capture Relay Port 8080"; flow:to_server,established; threshold:type both, track by_src, count 5, seconds 10; metadata:attack_stage Credential_Access, mitre_tactic_id TA0006, mitre_tactic_name Credential_Access, mitre_technique_id T1040, mitre_technique_name Network_Sniffing, mitre_subtechnique_id none; sid:100046; rev:2;)

# -----------------------------------------------------------
# T1222.002 — FILE PERMISSION MODIFICATION (/etc/shadow chmod 777)
# -----------------------------------------------------------

# T1222.002 — File Permission Modification: Shadow file world-writable
alert tcp $HOME_NET any -> any any (msg:"MITRE T1222.002 File Permission Modification - chmod 777 Shadow File Keyword"; flow:to_server,established; content:"chmod"; content:"shadow"; distance:0; nocase; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1222, mitre_technique_name File_and_Directory_Permissions_Modification, mitre_subtechnique_id T1222.002, mitre_subtechnique_name Linux_and_Mac_File_and_Directory_Permissions_Modification; sid:100047; rev:2;)

# -----------------------------------------------------------
# T1036 — MASQUERADING (process renaming)
# -----------------------------------------------------------

# T1036 — Masquerading: Suspicious process copy detected via SSH command
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1036 Masquerading - Suspicious Process Copy Command via SSH"; flow:to_server,established; content:"cp -r"; content:"/Music/"; nocase; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1036, mitre_technique_name Masquerading, mitre_subtechnique_id none; sid:100048; rev:2;)

# -----------------------------------------------------------
# T1070.006 — TIMESTOMPING
# -----------------------------------------------------------

# T1070.006 — Timestomp: touch with historical timestamp via SSH
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1070.006 Timestomp - touch -t Historical Timestamp Command"; flow:to_server,established; content:"touch"; content:"-m -t 2023"; nocase; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1070, mitre_technique_name Indicator_Removal, mitre_subtechnique_id T1070.006, mitre_subtechnique_name Timestomp; sid:100049; rev:2;)

# -----------------------------------------------------------
# T1546.004 — UNIX SHELL CONFIG MODIFICATION (Persistence)
# -----------------------------------------------------------

# T1546.004 — Event Triggered Execution: bashrc modification
alert tcp any any -> $HOME_NET 22 (msg:"MITRE T1546.004 Persistence - bashrc Modification Detected"; flow:to_server,established; content:".bashrc"; content:"TMOUT"; nocase; metadata:attack_stage Persistence, mitre_tactic_id TA0003, mitre_tactic_name Persistence, mitre_technique_id T1546, mitre_technique_name Event_Triggered_Execution, mitre_subtechnique_id T1546.004, mitre_subtechnique_name Unix_Shell_Configuration_Modification; sid:100050; rev:2;)

# -----------------------------------------------------------
# T1505.003 — WEB SHELL / XSS INJECTION TEST
# -----------------------------------------------------------

# T1505 — Server Software Component: XSS Injection test via POST
alert http any any -> $HOME_NET any (msg:"MITRE T1505 Server Software Component - XSS Script Tag Injection Test"; flow:to_server,established; http.request_body; content:"<script>"; nocase; metadata:attack_stage Persistence, mitre_tactic_id TA0003, mitre_tactic_name Persistence, mitre_technique_id T1505, mitre_technique_name Server_Software_Component, mitre_subtechnique_id none; sid:100051; rev:2;)

# -----------------------------------------------------------
# T1498 — LARGE FILE DOWNLOAD (Data transfer flood)
# -----------------------------------------------------------

# T1498 / T1030 — Large Data Transfer: 10MB test file download
alert http $HOME_NET any -> any any (msg:"MITRE T1030 Data Transfer Size Limits - Large File Download Detected 10MB"; flow:to_server,established; http.uri; content:"10MB.zip"; nocase; metadata:attack_stage Exfiltration, mitre_tactic_id TA0010, mitre_tactic_name Exfiltration, mitre_technique_id T1030, mitre_technique_name Data_Transfer_Size_Limits, mitre_subtechnique_id none; sid:100052; rev:2;)

# -----------------------------------------------------------
# T1021.002 — SMB ENUMERATION (smbclient -L)
# -----------------------------------------------------------

# T1021.002 — Remote Services: SMB Share Enumeration
alert tcp any any -> $HOME_NET 445 (msg:"MITRE T1021.002 Remote Services SMB - SMB Share Enumeration Anonymous"; flow:to_server,established; content:"|ff|SMB"; depth:8; metadata:attack_stage Lateral_Movement, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1021, mitre_technique_name Remote_Services, mitre_subtechnique_id T1021.002, mitre_subtechnique_name SMB_Windows_Admin_Shares; sid:100053; rev:2;)

# -----------------------------------------------------------
# T1040 — SIP PROTOCOL PROBE
# -----------------------------------------------------------

# T1040 — Network Sniffing: SIP OPTIONS probe
alert udp any any -> $HOME_NET 5060 (msg:"MITRE T1046 Service Discovery - SIP OPTIONS Probe"; content:"OPTIONS sip:"; nocase; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1046, mitre_technique_name Network_Service_Scanning, mitre_subtechnique_id none; sid:100054; rev:2;)

# -----------------------------------------------------------
# T1059.004 — CRUNCH WORDLIST PIPED VIA NC (Data Encoding)
# -----------------------------------------------------------

# T1132 — Data Encoding: Base64 encoded crunch output piped to port 3000
alert tcp any any -> $HOME_NET 3000 (msg:"MITRE T1132 Data Encoding - Base64 Wordlist Stream via Netcat Port 3000"; flow:to_server,established; threshold:type both, track by_src, count 30, seconds 5; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1132, mitre_technique_name Data_Encoding, mitre_subtechnique_id none; sid:100055; rev:2;)

# -----------------------------------------------------------
# T1018 — REMOTE SYSTEM DISCOVERY (nmap subnet ping sweep)
# -----------------------------------------------------------

# T1018 — Remote System Discovery: ICMP subnet sweep
alert icmp any any -> $HOME_NET any (msg:"MITRE T1018 Remote System Discovery - ICMP Subnet Ping Sweep"; itype:8; threshold:type both, track by_src, count 10, seconds 5; metadata:attack_stage Discovery, mitre_tactic_id TA0007, mitre_tactic_name Discovery, mitre_technique_id T1018, mitre_technique_name Remote_System_Discovery, mitre_subtechnique_id none; sid:100056; rev:2;)

# -----------------------------------------------------------
# T1566 / TESTMYNIDS — NIDS EVASION TEST URL
# -----------------------------------------------------------

# NIDS Test: testmynids.org UID index request
alert http $HOME_NET any -> any any (msg:"NIDS Test Rule - testmynids.org UID Test Request"; flow:to_server,established; http.host; content:"testmynids.org"; metadata:attack_stage Testing, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning, mitre_subtechnique_id none; sid:100057; rev:1;)


# -----------------------------------------------------------
# CASE 38 — T1059: COMMAND AND SCRIPTING INTERPRETER
# -----------------------------------------------------------

# T1059.001 — PowerShell: Encoded command over HTTP
alert http any any -> $HOME_NET any (msg:"MITRE T1059.001 Command and Scripting Interpreter - PowerShell Encoded Command in HTTP"; flow:to_server,established; http.uri; content:"powershell"; nocase; content:"-enc"; nocase; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1059, mitre_technique_name Command_and_Scripting_Interpreter, mitre_subtechnique_id T1059.001, mitre_subtechnique_name PowerShell; sid:100058; rev:2;)

# T1059.004 — Unix Shell: Reverse shell via bash over TCP
alert tcp any any -> $HOME_NET any (msg:"MITRE T1059.004 Command and Scripting Interpreter - Bash Reverse Shell Keyword"; flow:to_server,established; content:"bash -i"; nocase; content:"/dev/tcp/"; nocase; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1059, mitre_technique_name Command_and_Scripting_Interpreter, mitre_subtechnique_id T1059.004, mitre_subtechnique_name Unix_Shell; sid:100059; rev:2;)

# T1059 — Scripting: wget/curl payload fetch via HTTP
alert http any any -> $HOME_NET any (msg:"MITRE T1059 Command and Scripting Interpreter - Payload Fetch via wget or curl"; flow:to_server,established; http.user_agent; content:"curl"; nocase; http.uri; content:".sh"; nocase; metadata:attack_stage Execution, mitre_tactic_id TA0002, mitre_tactic_name Execution, mitre_technique_id T1059, mitre_technique_name Command_and_Scripting_Interpreter, mitre_subtechnique_id none; sid:100060; rev:2;)

# -----------------------------------------------------------
# CASE 38 — T1027: OBFUSCATED FILES OR INFORMATION
# -----------------------------------------------------------

# T1027 — Obfuscation: Base64 encoded payload in HTTP URI
alert http any any -> $HOME_NET any (msg:"MITRE T1027 Obfuscated Files or Information - Base64 Encoded Payload in URI"; flow:to_server,established; http.uri; pcre:"/[A-Za-z0-9+\/]{40,}={0,2}/"; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1027, mitre_technique_name Obfuscated_Files_or_Information, mitre_subtechnique_id none; sid:100061; rev:2;)

# T1027 — Obfuscation: Shikata_ga_nai encoded payload pattern
alert tcp any any -> $HOME_NET any (msg:"MITRE T1027 Obfuscated Files or Information - Shikata Ga Nai XOR Encoder Signature"; flow:to_server,established; content:"|d9 74 24 f4|"; depth:50; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1027, mitre_technique_name Obfuscated_Files_or_Information, mitre_subtechnique_id none; sid:100062; rev:2;)

# T1027 — Obfuscation: Meterpreter-like XOR byte pattern in TCP stream
alert tcp any any -> $HOME_NET any (msg:"MITRE T1027 Obfuscated Files or Information - Possible XOR Obfuscated Payload in TCP"; flow:to_server,established; content:"|fc e8|"; depth:4; threshold:type both, track by_src, count 3, seconds 10; metadata:attack_stage Defense_Evasion, mitre_tactic_id TA0005, mitre_tactic_name Defense_Evasion, mitre_technique_id T1027, mitre_technique_name Obfuscated_Files_or_Information, mitre_subtechnique_id none; sid:100063; rev:2;)

# -----------------------------------------------------------
# CASE 38 — T1071: APPLICATION LAYER PROTOCOL (C2 CALLBACK)
# -----------------------------------------------------------
# T1071.001 — C2 Callback: Meterpreter-style HTTP beacon

# T1071.001 — C2 Callback: Outbound reverse shell connection on port 4444
alert tcp $HOME_NET any -> any 4444 (msg:"MITRE T1071.001 Application Layer Protocol - Outbound TCP C2 Callback Port 4444"; flow:to_server,established; flags:S; threshold:type both, track by_src, count 3, seconds 30; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.001, mitre_subtechnique_name Web_Protocols; sid:100065; rev:2;)

# T1071.001 — C2 Callback: Common alternative reverse shell ports
alert tcp $HOME_NET any -> any [1337,4444,5555,6666,7777,8888,9999] (msg:"MITRE T1071.001 Application Layer Protocol - Outbound Connection on Common Reverse Shell Port"; flow:to_server; flags:S; threshold:type both, track by_src, count 3, seconds 30; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.001, mitre_subtechnique_name Web_Protocols; sid:100066; rev:2;)

# -----------------------------------------------------------
# CASE 38 — T1055: PROCESS INJECTION (Meterpreter migrate)
# -----------------------------------------------------------

# T1055 — Process Injection: Meterpreter migrate keyword in TCP stream
alert tcp any any -> $HOME_NET any (msg:"MITRE T1055 Process Injection - Meterpreter Migrate Command in TCP Stream"; flow:established; content:"migrate"; nocase; content:"explorer.exe"; nocase; distance:0; within:30; metadata:attack_stage Privilege_Escalation, mitre_tactic_id TA0004, mitre_tactic_name Privilege_Escalation, mitre_technique_id T1055, mitre_technique_name Process_Injection, mitre_subtechnique_id none; sid:100067; rev:2;)

# T1055 — Process Injection: Shellcode stub in TCP payload (common prologue)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1055 Process Injection - Shellcode NOP Sled or Stub Pattern Detected"; flow:to_server,established; content:"|90 90 90 90 90 90 90 90|"; depth:100; metadata:attack_stage Privilege_Escalation, mitre_tactic_id TA0004, mitre_tactic_name Privilege_Escalation, mitre_technique_id T1055, mitre_technique_name Process_Injection, mitre_subtechnique_id none; sid:100068; rev:2;)

# T1055 — Process Injection: Remote thread creation pattern (WriteProcessMemory artifact)
alert tcp any any -> $HOME_NET any (msg:"MITRE T1055 Process Injection - Possible Remote Memory Write Artifact in Stream"; flow:to_server,established; content:"|4d 5a|"; depth:2; content:"|50 45 00 00|"; within:200; metadata:attack_stage Privilege_Escalation, mitre_tactic_id TA0004, mitre_tactic_name Privilege_Escalation, mitre_technique_id T1055, mitre_technique_name Process_Injection, mitre_subtechnique_id none; sid:100069; rev:2;)


alert http $HOME_NET any -> any any (msg:"MITRE T1071.001 Application Layer Protocol - Meterpreter HTTP C2 Beacon"; flow:to_server,established; http.method; content:"GET"; http.uri; content:"/"; http.user_agent; content:"MSIE 6.0"; nocase; metadata:attack_stage Command_and_Control, mitre_tactic_id TA0011, mitre_tactic_name Command_and_Control, mitre_technique_id T1071, mitre_technique_name Application_Layer_Protocol, mitre_subtechnique_id T1071.001, mitre_subtechnique_name Web_Protocols; sid:100064; rev:4;)
