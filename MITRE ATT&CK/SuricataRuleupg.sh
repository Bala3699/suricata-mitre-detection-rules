#!/bin/bash

# =========================================================
# CyberSentinel - Advanced Threat Feed Installer
# Author: Balamutugan
# Purpose:
#   Install and enable advanced Suricata threat feeds
# =========================================================

echo "==========================================="
echo " CyberSentinel Threat Feed Installer"
echo "==========================================="

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] Please run as root."
   exit 1
fi

echo ""
echo "[1/8] Updating Suricata source index..."
suricata-update update-sources

echo ""
echo "[2/8] Enabling Emerging Threats Open..."
suricata-update enable-source et/open

echo ""
echo "[3/8] Enabling URLHaus malware feed..."
suricata-update enable-source abuse.ch/urlhaus

echo ""
echo "[4/8] Enabling SSL Blacklist feed..."
suricata-update enable-source abuse.ch/sslbl-blacklist

echo ""
echo "[5/8] Enabling Feodo Tracker botnet feed..."
suricata-update enable-source abuse.ch/feodotracker

echo ""
echo "[6/8] Enabling Nmap detection rules..."
suricata-update enable-source aleksibovellan/nmap

echo ""
echo "[7/8] Enabling threat hunting rules..."
suricata-update enable-source tgreen/hunting

echo ""
echo "[8/8] Enabling lateral movement rules..."
suricata-update enable-source stamus/lateral

echo ""
echo "==========================================="
echo " Updating all rules..."
echo "==========================================="

suricata-update

echo ""
echo "==========================================="
echo " Testing Suricata configuration..."
echo "==========================================="

suricata -T -c /etc/suricata/suricata.yaml

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS] Configuration test passed."
else
    echo ""
    echo "[ERROR] Configuration test failed."
    exit 1
fi

echo ""
echo "==========================================="
echo " Restarting Suricata..."
echo "==========================================="

systemctl restart suricata

echo ""
echo "==========================================="
echo " Checking Suricata status..."
echo "==========================================="

systemctl status suricata --no-pager

echo ""
echo "==========================================="
echo " Rule Statistics"
echo "==========================================="

RULE_COUNT=$(grep -c "alert" /var/lib/suricata/rules/suricata.rules)

echo "Total alert rules loaded: $RULE_COUNT"

echo ""
echo "==========================================="
echo " Enabled Sources"
echo "==========================================="

suricata-update list-enabled-sources

echo ""
echo "==========================================="
echo " CyberSentinel Threat Feeds Installed"
echo "==========================================="
echo ""
echo "Installed Feeds:"
echo "  - ET Open"
echo "  - URLHaus"
echo "  - SSL Blacklist"
echo "  - Feodo Tracker"
echo "  - Nmap Detection"
echo "  - Threat Hunting"
echo "  - Lateral Movement"
echo ""
echo "Your CyberSentinel IDS is now upgraded."
echo ""
