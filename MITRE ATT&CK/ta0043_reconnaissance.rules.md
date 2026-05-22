# ==============================================================================
# MITRE ATT&CK TA0043: RECONNAISSANCE DETECTION RULESET (11 TECHNIQUES)
# ==============================================================================

# 10mm | T1595: Active Scanning (Inbound Port Sweep)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"TA0043 - T1595 Active Scanning (Inbound Port Sweep)"; flags:S; threshold:type threshold, track by_src, count 50, seconds 5; metadata:affected_product Any, attack_target Server, mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1595, mitre_technique_name Active_Scanning; classtype:attempted-recon; sid:2004301; rev:1;)

# 20mm | T1592: Gather Victim Host Information (SNMP OS SysDesc Poll)
alert udp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"TA0043 - T1592 Gather Victim Host Info (SNMP OS SysDesc Poll)"; content:"|30|"; depth:1; content:"|06 08 2b 06 01 02 01 01 01 00|"; fast_pattern; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1592, mitre_technique_name Gather_Victim_Host_Information; classtype:attempted-recon; sid:2004302; rev:1;)

# 30mm | T1590: Gather Victim Network Information (DNS Zone Transfer AXFR)
alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"TA0043 - T1590 Gather Victim Network Info (DNS Zone Transfer AXFR)"; content:"|00 fc|"; offset:15; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1590, mitre_technique_name Gather_Victim_Network_Information; classtype:attempted-recon; sid:2004303; rev:1;)

# 40mm | T1589: Gather Victim Identity Information (LDAP User Enumeration)
alert tcp $EXTERNAL_NET any -> $HOME_NET 389 (msg:"TA0043 - T1589 Gather Victim Identity Info (LDAP User Enumeration)"; content:"sAMAccountName="; nocase; fast_pattern; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1589, mitre_technique_name Gather_Victim_Identity_Information; classtype:attempted-recon; sid:2004304; rev:1;)

# 50mm | T1591: Gather Victim Organization Information (Corporate Metadata Scraping)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"TA0043 - T1591 Gather Victim Org Info (Corporate Metadata Scraping)"; http_uri; content:"/orgchart"; nocase; or; content:"/legal-notices"; nocase; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1591, mitre_technique_name Gather_Victim_Organization_Information; classtype:attempted-recon; sid:2004305; rev:1;)

# 60mm | T1598: Phishing for Information (Inbound Credential Harvest Attachment)
alert smtp $EXTERNAL_NET any -> $SMTP_SERVERS any (msg:"TA0043 - T1598 Phishing for Information (Inbound Credential Harvest Attachment)"; file_data; content:"filename="; content:".html"; nocase; pcre:"/Content-Disposition\x3a.*filename=.*\.html/mi"; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1598, mitre_technique_name Phishing_for_Information; classtype:bad-unknown; sid:2004306; rev:1;)

# 70mm | T1597: Search Closed Sources (Internal Lookup Against Leak Indexer)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TA0043 - T1597 Search Closed Sources (Internal Lookup Against Leak Indexer)"; http_uri; content:"/api/v1/leakcheck"; nocase; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1597, mitre_technique_name Search_Closed_Sources; classtype:policy-violation; sid:2004307; rev:1;)

# 80mm | T1596: Search Open Technical Databases (Shodan/Censys Scanner Inbound)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"TA0043 - T1596 Search Open Technical DBs (Shodan/Censys Scanner Inbound)"; http_user_agent; content:"shodan"; nocase; or; content:"censys"; nocase; or; content:"zoomeye"; nocase; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1596, mitre_technique_name Search_Open_Technical_Databases; classtype:attempted-recon; sid:2004308; rev:1;)

# 90mm | T1593: Search Open Websites/Domains (Outbound OSINT Target Profile)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TA0043 - T1593 Search Open Websites (Outbound OSINT Target Profile)"; http_uri; content:"whois.xml"; nocase; or; content:"dnsdumpster"; nocase; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1593, mitre_technique_name Search_Open_Websites; classtype:policy-violation; sid:2004309; rev:1;)

# 100mm | T1594: Search Victim-Owned Websites (Directory Fuzzing)
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"TA0043 - T1594 Search Victim-Owned Websites (Directory Fuzzing)"; http_uri; content:"/.env"; fast_pattern; or; content:"/wp-json/wp/v2/users"; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1594, mitre_technique_name Search_Victim_Owned_Websites; classtype:attempted-recon; sid:2004310; rev:1;)

# 110mm | T1608: Stage Capabilities (Outbound Tool Retrieval)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TA0043 - T1608 Stage Capabilities (Outbound Tool Retrieval)"; http_uri; content:"://githubusercontent.com"; nocase; or; content:"://pastebin.com"; nocase; metadata:mitre_tactic_id TA0043, mitre_tactic_name Reconnaissance, mitre_technique_id T1608, mitre_technique_name Stage_Capabilities; classtype:bad-unknown; sid:2004311; rev:1;)
