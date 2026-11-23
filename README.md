# Operate a SOC Workstation

## Summary
A CompTIA Security+ live lab (SY0-701 objective 1.1) in the simulated Structureality environment. Working from the ADMIN Windows client, I triaged a Critical Wazuh alert in DFIR-IRIS, investigated the source event in the Wazuh SIEM, and classified it as a false positive. I then mapped the lab network from DNS on the domain controller, the internal VyOS router, and the OPNsense border firewall.

The alert was Wazuh rule 92213, level 15, titled "Executable file dropped in folder commonly used by malware." It was mapped to MITRE ATT&CK T1105 Ingress Tool Transfer (Command and Control) and came from a Sysmon Event ID 11 on agent 003 (admin, 10.1.16.102). The event showed `powershell.exe` creating a `__PSScriptPolicyTest_*.ps1` file in `C:\Users\Jaime\AppData\Local\Temp`. That file is a normal Windows PowerShell execution-policy test, not malware. I merged the alert into case #3, confirmed the file path and process in Wazuh Document Details, and closed the case as a false positive at Informational severity.

The lab uses split DNS (`ad.structureality.com` and `structureality.com`). `www.structureality.com` resolves to 172.16.0.201 on the screened subnet. The VyOS internal router provides the .254 default gateways for the edge (10.1.128.254), servers (10.1.16.254), and clients (10.1.24.254) subnets, and its default route goes via 10.1.28.253 on the border firewall. OPNsense (`gw.ad.structureality.com`) has a WAN address of 203.0.113.1/29 learned by DHCP, a LAN address of 10.1.128.253 with a route for 10.1.0.0/17, a screened interface at 172.16.0.254/24, and a guest interface at 192.168.16.254/24. NAT port-forwarding publishes HTTP, HTTPS, and SSH to the web server at 172.16.0.201, and IMAP, IMAPS, and SMTP submission to MS at 10.1.16.2.

The main subnets and hosts in this environment:

- 10.1.16.0/24 (servers): DC, MS, SOC, GIT, and ADMIN. SOC is a Debian host running DFIR-IRIS and Wazuh. MS is the file, mail, and helpdesk server.
- 10.1.24.0/24 (clients): PC and LAPTOP
- 10.1.128.0/24 (border LAN): the OPNsense LAN interface
- 172.16.0.0/24 (screened subnet): the NODE web server at 172.16.0.201
- 192.168.16.0/24 (guest): present on the firewall

## My Role
I completed this hands-on in CompTIA's live lab on November 23, 2026. I signed in to DFIR-IRIS as Jaime through ADFS, worked the alert and case, used Wazuh to inspect the source event, and connected to DNS Manager, the VyOS router, and the OPNsense firewall to map the network. Structureality and this environment are part of the course lab, not a real workplace or my own network. The write-up is my own.

## Skills and tools
DFIR-IRIS case management, Wazuh SIEM (endpoint inventory, threat hunting, event filtering, and document inspection), Sysmon Event ID 11 review, MITRE ATT&CK mapping (T1105), false-positive classification, Windows DNS Manager, VyOS (`show interfaces`), and OPNsense (interface overview and NAT port forwarding).

## Evidence

### 1. DFIR-IRIS dashboard, signed in as Jaime
IRIS is at `https://soc.structureality.com:4430`. I authenticated through ADFS as Jaime.

![IRIS dashboard](screenshots/01-iris-dashboard.png)

### 2. Critical alert for rule 92213 (T1105)
The alert title is "Executable file dropped in folder commonly used by malware." Details show rule 92213, level 15, agent 003 (admin), MITRE T1105 Ingress Tool Transfer under Command and Control, and source location EventChannel.

![IRIS alert T1105](screenshots/02-iris-alert-t1105.png)

### 3. Full alert log: powershell.exe and the policy-test file
The full log is a Sysmon Event ID 11 from `admin.ad.structureality.com`. `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` created `__PSScriptPolicyTest_s1rndisd.qpp.ps1` in `C:\Users\Jaime\AppData\Local\Temp` as user `structureality\Jaime`.

![IRIS alert full log](screenshots/03-iris-alert-full-log.png)

### 4. Merging the alert into a new case
I used Merge into a new case and kept the alert title, prefixed with `[ALERT]`.

![Merge into a new case](screenshots/04-iris-merge-new-case.png)

### 5. Case #3 opened
The new case is #3, owned by Jaime, still marked Critical and Open, with customer Structureality.

![Case #3 opened](screenshots/05-iris-case-3-open.png)

### 6. Wazuh overview
The SIEM is at `https://siem.structureality.com:4433`. The overview showed 3 active agents and 2 disconnected, with 6 Critical, 1 High, 70 Medium, and 1,124 Low alerts in the last 24 hours.

![Wazuh dashboard](screenshots/06-wazuh-dashboard.png)

### 7. Active Wazuh agents
The three active agents were all Windows Server 2025 Standard running Wazuh 4.14.0: 001 DC (10.1.16.1), 002 MS (10.1.16.2), and 003 admin (10.1.16.102).

![Wazuh active agents](screenshots/07-wazuh-active-agents.png)

### 8. Agent 003 (ADMIN)
The admin agent page confirms IP 10.1.16.102, hostname ADMIN, Wazuh 4.14.0, and Windows Server 2025 Standard.

![Wazuh admin agent](screenshots/08-wazuh-admin-agent.png)

### 9. Threat Hunting on agent 003
Filtered to manager `soc` and agent 003, Threat Hunting showed 804 events in the last 24 hours, including 5 at level 12 or above, and no authentication failures or successes.

![Wazuh Threat Hunting](screenshots/09-wazuh-threat-hunting.png)

### 10. Filter for level 12 and above
Applying that filter reduced the view to the 5 high-severity events, with the alerts chart peaking at level 15.

![Level 12+ filter](screenshots/10-wazuh-level12-filter.png)

### 11. Events tab: five hits on rule 92213
The Events view listed five hits on admin for "Executable file dropped in folder commonly used by malware," all rule 92213 at level 15.

![Wazuh events for rule 92213](screenshots/11-wazuh-events-92213.png)

### 12. Document Details: target filename
Inspecting one of the events showed `powershell.exe` (process ID 7136) writing `C:\Users\Jaime\AppData\Local\Temp\__PSScriptPolicyTest_ds2tilzo.q0g.ps1` as `structureality\jaime` at 2026-11-23 16:00:39 UTC. That filename pattern is the Windows PowerShell execution-policy test, so the alert is a false positive.

![Wazuh Document Details](screenshots/12-wazuh-document-details.png)

### 13. Case #3 closed as a false positive
Back in IRIS, I classified the case as a false positive alert, set the severity to Informational, and closed it on 2026-11-23.

![Case #3 closed](screenshots/13-iris-case-closed-false-positive.png)

### 14. DNS: the ad.structureality.com zone
In DNS Manager on the DC, the `ad.structureality.com` zone shows `dc` at 10.1.16.1, `git` at 10.1.16.33, and the zone hosted on `dc.ad.structureality.com`.

![ad.structureality.com DNS zone](screenshots/14-dns-ad-zone.png)

### 15. DNS: the structureality.com zone
Split DNS is in use. In the `structureality.com` zone, `www` and the zone apex both point to 172.16.0.201. Other visible records include `mail` at 10.1.16.2, `soc` at 10.1.16.242, `gw` at 10.1.128.253, `git` at 10.1.16.33, and CNAME records such as `siem` and `wazuh` to `soc.structureality.com`.

![structureality.com DNS zone](screenshots/15-dns-structureality-zone-www.png)

### 16. VyOS `show interfaces`
I connected to the internal router over SSH (`vyos@10.1.254.254`, which is the router's loopback address). `show interfaces` lists the .254 gateways: eth0 10.1.128.254/24 (LAN edge, up), eth1 10.1.16.254/24 (LAN servers, up), and eth2 10.1.24.254/24 (LAN clients, up). Two other interfaces were down and were not used for this lab. The lab notes that `show ip route` shows a static default route (0.0.0.0/0) via 10.1.28.253, an interface on the border firewall.

![VyOS show interfaces](screenshots/16-vyos-show-interfaces.png)

### 17. OPNsense dashboard
The border firewall is at `https://gw.ad.structureality.com`. The dashboard shows the WAN DHCP gateway at 203.0.113.6 and the LAN gateway at 10.1.128.254 (the VyOS edge address).

![OPNsense dashboard](screenshots/17-opnsense-dashboard.png)

### 18. OPNsense Interfaces Overview
WAN (hn0) is 203.0.113.1/29 on DHCP, with a default route and the 203.0.113.0/29 prefix. LAN (hn1) is 10.1.128.253/24 with routes for 10.1.0.0/17 and 10.1.128.0/24. SCREENED (opt1) is 172.16.0.254/24, and GUEST (opt2) is 192.168.16.254/24.

![OPNsense Interfaces Overview](screenshots/18-opnsense-interfaces-overview.png)

### 19. NAT Port Forward rules
Enabled WAN forwards send TCP 80, 443, and 22 to 172.16.0.201, and TCP 143 (IMAP), 993 (IMAPS), and 587 (SMTP submission) to 10.1.16.2. A LAN anti-lockout rule for ports 80 and 443 is also present.

![OPNsense NAT Port Forward](screenshots/19-opnsense-nat-port-forward.png)

## Disclaimer
This is a CompTIA Security+ course live lab in a simulated environment. Structureality is a fictional company used for training. The screenshots and write-up document my own work in that lab; they do not represent a real production network or employer.
