# Threat Actor Dossier: APT28
> MITRE ATT&CK Group ID: **G0007**
> Generated: 2026-04-03 04:23 UTC  |  Sources: mitre_attack

## Synopsis

APT28 is a Russian state-sponsored threat actor first observed in 2004 that conducts espionage operations through a comprehensive arsenal of 91 documented ATT&CK techniques spanning defense evasion, collection, credential access, command and control, and persistence. The group operates under multiple aliases including IRON TWILIGHT, Sofacy, and Fancy Bear, and maintains an active malware toolkit including CHOPSTICK, Mimikatz, and ADVSTORESHELL. Recent operational activity demonstrates sustained focus on credential harvesting and client-side exploitation, including a multi-stage phishing campaign targeting Ukrainian infrastructure via UKR.NET users and exploitation of Microsoft Office and MSHTML vulnerabilities (CVE-2026-21513) throughout early 2026. APT28's evolving tradecraft reflects ongoing prioritization of critical infrastructure targeting across European and Eurasian government, energy, and research organizations, with particular reliance on widely-deployed productivity software as initial access vectors. The group's persistent operational tempo and tactical sophistication underscore its status as a persistent intelligence collection threat aligned with Russian state interests.

## Overview

| Field | Value |
|---|---|
| **Origin** | Russia |
| **First Seen** | 2004 |
| **Motivations** | espionage |
| **Also Known As** | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch |

## TTP Table

| Technique ID | Tactic | Name | Confidence |
|---|---|---|---|
| T1001.001 | Command and Control | Junk Data | MEDIUM |
| T1003 | Credential Access | OS Credential Dumping | MEDIUM |
| T1003.001 | Credential Access | LSASS Memory | MEDIUM |
| T1003.003 | Credential Access | NTDS | MEDIUM |
| T1005 | Collection | Data from Local System | MEDIUM |
| T1014 | Defense Evasion | Rootkit | MEDIUM |
| T1021.002 | Lateral Movement | SMB/Windows Admin Shares | MEDIUM |
| T1025 | Collection | Data from Removable Media | MEDIUM |
| T1027.013 | Defense Evasion | Encrypted/Encoded File | MEDIUM |
| T1030 | Exfiltration | Data Transfer Size Limits | MEDIUM |
| T1036 | Defense Evasion | Masquerading | MEDIUM |
| T1036.005 | Defense Evasion | Match Legitimate Resource Name or Location | MEDIUM |
| T1037.001 | Persistence | Logon Script (Windows) | MEDIUM |
| T1039 | Collection | Data from Network Shared Drive | MEDIUM |
| T1040 | Credential Access | Network Sniffing | MEDIUM |
| T1048.002 | Exfiltration | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | MEDIUM |
| T1056.001 | Collection | Keylogging | MEDIUM |
| T1057 | Discovery | Process Discovery | MEDIUM |
| T1059.001 | Execution | PowerShell | MEDIUM |
| T1059.003 | Execution | Windows Command Shell | MEDIUM |
| T1068 | Privilege Escalation | Exploitation for Privilege Escalation | MEDIUM |
| T1070.001 | Defense Evasion | Clear Windows Event Logs | MEDIUM |
| T1070.004 | Defense Evasion | File Deletion | MEDIUM |
| T1070.006 | Defense Evasion | Timestomp | MEDIUM |
| T1071.001 | Command and Control | Web Protocols | MEDIUM |
| T1071.003 | Command and Control | Mail Protocols | MEDIUM |
| T1074.001 | Collection | Local Data Staging | MEDIUM |
| T1074.002 | Collection | Remote Data Staging | MEDIUM |
| T1078 | Defense Evasion | Valid Accounts | MEDIUM |
| T1078.004 | Defense Evasion | Cloud Accounts | MEDIUM |
| T1083 | Discovery | File and Directory Discovery | MEDIUM |
| T1090.002 | Command and Control | External Proxy | MEDIUM |
| T1090.003 | Command and Control | Multi-hop Proxy | MEDIUM |
| T1091 | Lateral Movement | Replication Through Removable Media | MEDIUM |
| T1092 | Command and Control | Communication Through Removable Media | MEDIUM |
| T1098.002 | Persistence | Additional Email Delegate Permissions | MEDIUM |
| T1102.002 | Command and Control | Bidirectional Communication | MEDIUM |
| T1105 | Command and Control | Ingress Tool Transfer | MEDIUM |
| T1110 | Credential Access | Brute Force | MEDIUM |
| T1110.001 | Credential Access | Password Guessing | MEDIUM |
| T1110.003 | Credential Access | Password Spraying | MEDIUM |
| T1113 | Collection | Screen Capture | MEDIUM |
| T1114.002 | Collection | Remote Email Collection | MEDIUM |
| T1119 | Collection | Automated Collection | MEDIUM |
| T1120 | Discovery | Peripheral Device Discovery | MEDIUM |
| T1133 | Persistence | External Remote Services | MEDIUM |
| T1134.001 | Defense Evasion | Token Impersonation/Theft | MEDIUM |
| T1137.002 | Persistence | Office Test | MEDIUM |
| T1140 | Defense Evasion | Deobfuscate/Decode Files or Information | MEDIUM |
| T1189 | Initial Access | Drive-by Compromise | MEDIUM |
| T1190 | Initial Access | Exploit Public-Facing Application | MEDIUM |
| T1199 | Initial Access | Trusted Relationship | MEDIUM |
| T1203 | Execution | Exploitation for Client Execution | MEDIUM |
| T1204.001 | Execution | Malicious Link | MEDIUM |
| T1204.002 | Execution | Malicious File | MEDIUM |
| T1210 | Lateral Movement | Exploitation of Remote Services | MEDIUM |
| T1211 | Defense Evasion | Exploitation for Defense Evasion | MEDIUM |
| T1213 | Collection | Data from Information Repositories | MEDIUM |
| T1213.002 | Collection | Sharepoint | MEDIUM |
| T1218.011 | Defense Evasion | Rundll32 | MEDIUM |
| T1221 | Defense Evasion | Template Injection | MEDIUM |
| T1498 | Impact | Network Denial of Service | MEDIUM |
| T1505.003 | Persistence | Web Shell | MEDIUM |
| T1528 | Credential Access | Steal Application Access Token | MEDIUM |
| T1542.003 | Persistence | Bootkit | MEDIUM |
| T1546.015 | Privilege Escalation | Component Object Model Hijacking | MEDIUM |
| T1547.001 | Persistence | Registry Run Keys / Startup Folder | MEDIUM |
| T1550.001 | Defense Evasion | Application Access Token | MEDIUM |
| T1550.002 | Defense Evasion | Pass the Hash | MEDIUM |
| T1557.004 | Credential Access | Evil Twin | MEDIUM |
| T1559.002 | Execution | Dynamic Data Exchange | MEDIUM |
| T1560 | Collection | Archive Collected Data | MEDIUM |
| T1560.001 | Collection | Archive via Utility | MEDIUM |
| T1564.001 | Defense Evasion | Hidden Files and Directories | MEDIUM |
| T1564.003 | Defense Evasion | Hidden Window | MEDIUM |
| T1566.001 | Initial Access | Spearphishing Attachment | MEDIUM |
| T1567 | Exfiltration | Exfiltration Over Web Service | MEDIUM |
| T1573.001 | Command and Control | Symmetric Cryptography | MEDIUM |
| T1583.001 | Resource Development | Domains | MEDIUM |
| T1583.003 | Resource Development | Virtual Private Server | MEDIUM |
| T1583.006 | Resource Development | Web Services | MEDIUM |
| T1584.008 | Resource Development | Network Devices | MEDIUM |
| T1586.002 | Resource Development | Email Accounts | MEDIUM |
| T1588.002 | Resource Development | Tool | MEDIUM |
| T1589.001 | Reconnaissance | Credentials | MEDIUM |
| T1591 | Reconnaissance | Gather Victim Org Information | MEDIUM |
| T1595.002 | Reconnaissance | Vulnerability Scanning | MEDIUM |
| T1596 | Reconnaissance | Search Open Technical Databases | MEDIUM |
| T1598 | Reconnaissance | Phishing for Information | MEDIUM |
| T1598.003 | Reconnaissance | Spearphishing Link | MEDIUM |
| T1669 | Initial Access | Wi-Fi Networks | MEDIUM |

## Associated Malware / Tools

| Name | Type | Description |
|---|---|---|
| Wevtutil | malware | Wevtutil is a Windows command-line utility that enables administrators to retrieve information about event logs and… |
| certutil | malware | certutil is a command-line utility that can be used to obtain certificate authority information and configure… |
| CHOPSTICK | malware | CHOPSTICK is a malware family of modular backdoors used by APT28. It has been used since at least 2012 and is usually… |
| Net | malware | The Net utility is a component of the Windows operating system. It is used in command-line operations for control of… |
| Forfiles | malware | Forfiles is a Windows utility commonly used in batch jobs to execute commands on one or more selected files or… |
| DealersChoice | malware | DealersChoice is a Flash exploitation framework used by APT28. (Citation: Sofacy DealersChoice) |
| Mimikatz | malware | Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords, along with many… |
| ADVSTORESHELL | malware | ADVSTORESHELL is a spying backdoor that has been used by APT28 from at least 2012 to 2016. It is generally used for… |
| Cannon | malware | Cannon is a Trojan with variants written in C# and Delphi. It was first observed in April 2018. (Citation: Unit42… |
| Komplex | malware | Komplex is a backdoor that has been used by APT28 on OS X and appears to be developed in a similar manner to XAgentOSX… |
| HIDEDRV | malware | HIDEDRV is a rootkit used by APT28. It has been deployed along with Downdelph to execute and hide that malware.… |
| JHUHUGIT | malware | JHUHUGIT is malware used by APT28. It is based on Carberp source code and serves as reconnaissance malware. (Citation:… |
| Koadic | malware | Koadic is a Windows post-exploitation framework and penetration testing tool that is publicly available on GitHub.… |
| Winexe | malware | Winexe is a lightweight, open source tool similar to PsExec designed to allow system administrators to execute commands… |
| Responder | malware | Responder is an open source tool used for LLMNR, NBT-NS and MDNS poisoning, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue… |
| cipher.exe | malware | cipher.exe is a native Microsoft utility that manages encryption of directories and files on NTFS (New Technology File… |
| XTunnel | malware | XTunnel a VPN-like network proxy tool that can relay traffic between a C2 server and a victim. It was first seen in May… |
| Drovorub | malware | Drovorub is a Linux malware toolset comprised of an agent, client, server, and kernel modules, that has been used by… |
| Tor | malware | Tor is a software suite and network that provides increased anonymity on the Internet. It creates a multi-hop proxy… |
| CORESHELL | malware | CORESHELL is a downloader used by APT28. The older versions of this malware are known as SOURFACE and newer versions as… |
| OLDBAIT | malware | OLDBAIT is a credential harvester used by APT28. (Citation: FireEye APT28) (Citation: FireEye APT28 January 2017) |
| Downdelph | malware | Downdelph is a first-stage downloader written in Delphi that has been used by APT28 in rare instances between 2013 and… |
| XAgentOSX | malware | XAgentOSX is a trojan that has been used by APT28 on OS X and appears to be a port of their standard CHOPSTICK or… |
| USBStealer | malware | USBStealer is malware that has been used by APT28 since at least 2005 to extract information from air-gapped networks.… |
| Zebrocy | malware | Zebrocy is a Trojan that has been used by APT28 since at least November 2015. The malware comes in several programming… |
| reGeorg | malware | reGeorg is an open-source web shell written in Python that can be used as a proxy to bypass firewall rules and tunnel… |
| Fysbis | malware | Fysbis is a Linux-based backdoor used by APT28 that dates back to at least 2014.(Citation: Fysbis Palo Alto Analysis) |
| LoJax | malware | LoJax is a UEFI rootkit used by APT28 to persist remote access software on targeted systems.(Citation: ESET LoJax Sept… |

## Recent Intelligence

> Synthesized from 4 vendor research articles using AI.

### Recorded Future (Public) — 2025-12-17  `MEDIUM relevance`

**[BlueDelta’s Persistent Campaign Against UKR.NET](https://www.recordedfuture.com/research/bluedeltas-persistent-campaign-against-ukrnet)**

APT28 (operating as BlueDelta) conducted a persistent credential-harvesting campaign targeting UKR.NET users, employing advanced phishing techniques across multiple stages. The campaign demonstrates evolved tradecraft in the actor's ongoing operations against Ukrainian infrastructure and users.

*Landscape context: **Threat Landscape Context:**

This campaign reflects an intensifying focus by Russian state-sponsored actors on compromising Ukrainian critical infrastructure and government communications through identity-layer attacks, exploiting the accessibility and scale advantages of phishing over direct network intrusion during sustained conflict. The evolution of BlueDelta's credential-harvesting tradecraft against UKR.NET specifically indicates Russian operators are refining targeting precision and social engineering sophistication against high-value organizational email systems as traditional perimeter defenses improve.*

### Recorded Future (Public) — 2026-01-07  `MEDIUM relevance`

**[GRU-Linked BlueDelta Evolves Credential Harvesting](https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting)**

APT28 (tracked as BlueDelta by Insikt Group) evolved credential-harvesting campaigns targeting government, energy, and research organizations across Europe and Eurasia as of early 2026. The group's operational focus reflects a shift toward intensified collection against critical infrastructure and state institutions in the specified regions. No specific tactical innovations, tool changes, or temporal details beyond the January 2026 reporting date are provided in the article excerpt.

*Landscape context: This reflects an ongoing shift toward persistent, low-detection-risk credential harvesting as a precursor to targeted intrusions, particularly against critical infrastructure where initial access brokers command premium value in the espionage supply chain. The geographic focus on Europe and Eurasia signals GRU's prioritization of strategic sectors where credential compromise enables sustained intelligence collection with minimal operational exposure.*

### Recorded Future (Public) — 2026-02-24  `MEDIUM relevance`

**[January 2026 CVE Landscape: 23 Critical Vulnerabilities Mark 5% Increase, APT28 Exploits Microsoft Office Zero-Day](https://www.recordedfuture.com/blog/january-2026-cve-landscape)**

APT28 exploited a Microsoft Office zero-day vulnerability during January 2026, demonstrating continued focus on widely-used productivity software as an attack vector. The article provides no additional details regarding targeting scope, geographic focus, or tactical evolution beyond this single exploit activity.

*Landscape context: The January 2026 CVE landscape reflects an accelerating pattern of nation-state actors like APT28 moving away from custom exploit development and toward rapid weaponization of public zero-days, particularly targeting productivity suites that maintain privileged access within enterprise environments. This shift underscores a strategic pivot toward exploits with immediate operational impact over traditional persistence mechanisms, driven by the expanding public disclosure cycle and compressed patching windows in enterprise deployments.*

### Recorded Future (Public) — 2026-03-12  `LOW relevance`

**[February 2026 CVE Landscape: 13 Critical Vulnerabilities Mark 43% Drop from January](https://www.recordedfuture.com/blog/february-2026-cve-landscape)**

APT28 exploited CVE-2026-21513, an MSHTML flaw, in February 2026 by delivering malicious Windows Shortcut files to enable multi-stage payload delivery. This represents continued Russian state-sponsored interest in client-side exploitation vectors targeting Microsoft technologies for initial access and lateral movement.

*Landscape context: The article demonstrates a continued pattern of Russian state-sponsored actors like APT28 leveraging publicly disclosed or easily accessible vulnerability information to conduct targeted operations, as evidenced by their exploitation of CVE-2026-21513 via commonplace file formats like Windows Shortcuts. This reflects a broader shift where nation-state threat actors are prioritizing rapid weaponization of known flaws over zero-day development, likely driven by the shortened time-to-exploitation windows created by coordinated disclosure practices and public PoC availability.*


### Malware Details

**Wevtutil** (malware)

Wevtutil is a Windows command-line utility that enables administrators to retrieve information about event logs and publishers.(Citation: Wevtutil Microsoft Documentation)

**certutil** (malware)

certutil is a command-line utility that can be used to obtain certificate authority information and configure Certificate Services. (Citation: TechNet Certutil)

**CHOPSTICK** (malware)

CHOPSTICK is a malware family of modular backdoors used by APT28. It has been used since at least 2012 and is usually dropped on victims as second-stage malware, though it has been used as first-stage malware in several cases. It has both Windows and Linux variants. (Citation: FireEye APT28) (Citation: ESET Sednit Part 2) (Citation: FireEye APT28 January 2017) (Citation: DOJ GRU Indictment Jul 2018) It is tracked separately from the X-Agent for Android.

**Net** (malware)

The Net utility is a component of the Windows operating system. It is used in command-line operations for control of users, groups, services, and network connections. (Citation: Microsoft Net Utility)

Net has a great deal of functionality, (Citation: Savill 1999) much of which is useful for an adversary, such as gathering system and network information for Discovery, moving laterally through SMB/Windows Admin Shares using <code>net use</code> commands, and interacting with services. The net1.exe utility is executed for certain functionality when net.exe is run and can be used directly in commands such as <code>net1 user</code>.

**Forfiles** (malware)

Forfiles is a Windows utility commonly used in batch jobs to execute commands on one or more selected files or directories (ex: list all directories in a drive, read the first line of all files created yesterday, etc.). Forfiles can be executed from either the command line, Run window, or batch files/scripts. (Citation: Microsoft Forfiles Aug 2016)

**DealersChoice** (malware)

DealersChoice is a Flash exploitation framework used by APT28. (Citation: Sofacy DealersChoice)

**Mimikatz** (malware)

Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords, along with many other features that make it useful for testing the security of networks. (Citation: Deply Mimikatz) (Citation: Adsecurity Mimikatz Guide)

**ADVSTORESHELL** (malware)

ADVSTORESHELL is a spying backdoor that has been used by APT28 from at least 2012 to 2016. It is generally used for long-term espionage and is deployed on targets deemed interesting after a reconnaissance phase. (Citation: Kaspersky Sofacy) (Citation: ESET Sednit Part 2)

**Cannon** (malware)

Cannon is a Trojan with variants written in C# and Delphi. It was first observed in April 2018. (Citation: Unit42 Cannon Nov 2018)(Citation: Unit42 Sofacy Dec 2018)

**Komplex** (malware)

Komplex is a backdoor that has been used by APT28 on OS X and appears to be developed in a similar manner to XAgentOSX (Citation: XAgentOSX 2017) (Citation: Sofacy Komplex Trojan).

**HIDEDRV** (malware)

HIDEDRV is a rootkit used by APT28. It has been deployed along with Downdelph to execute and hide that malware. (Citation: ESET Sednit Part 3) (Citation: Sekoia HideDRV Oct 2016)

**JHUHUGIT** (malware)

JHUHUGIT is malware used by APT28. It is based on Carberp source code and serves as reconnaissance malware. (Citation: Kaspersky Sofacy) (Citation: F-Secure Sofacy 2015) (Citation: ESET Sednit Part 1) (Citation: FireEye APT28 January 2017)

**Koadic** (malware)

Koadic is a Windows post-exploitation framework and penetration testing tool that is publicly available on GitHub. Koadic has several options for staging payloads and creating implants, and performs most of its operations using Windows Script Host.(Citation: Github Koadic)(Citation: Palo Alto Sofacy 06-2018)(Citation: MalwareBytes LazyScripter Feb 2021)

**Winexe** (malware)

Winexe is a lightweight, open source tool similar to PsExec designed to allow system administrators to execute commands on remote servers. (Citation: Winexe Github Sept 2013) Winexe is unique in that it is a GNU/Linux based client. (Citation: Überwachung APT28 Forfiles June 2015)

**Responder** (malware)

Responder is an open source tool used for LLMNR, NBT-NS and MDNS poisoning, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. (Citation: GitHub Responder)

**cipher.exe** (malware)

cipher.exe is a native Microsoft utility that manages encryption of directories and files on NTFS (New Technology File System) partitions by using the Encrypting File System (EFS).(Citation: cipher.exe)

**XTunnel** (malware)

XTunnel a VPN-like network proxy tool that can relay traffic between a C2 server and a victim. It was first seen in May 2013 and reportedly used by APT28 during the compromise of the Democratic National Committee. (Citation: Crowdstrike DNC June 2016) (Citation: Invincea XTunnel) (Citation: ESET Sednit Part 2)

**Drovorub** (malware)

Drovorub is a Linux malware toolset comprised of an agent, client, server, and kernel modules, that has been used by APT28.(Citation: NSA/FBI Drovorub August 2020)

**Tor** (malware)

Tor is a software suite and network that provides increased anonymity on the Internet. It creates a multi-hop proxy network and utilizes multilayer encryption to protect both the message and routing information. Tor utilizes "Onion Routing," in which messages are encrypted with multiple layers of encryption; at each step in the proxy network, the topmost layer is decrypted and the contents forwarded on to the next node until it reaches its destination. (Citation: Dingledine Tor The Second-Generation Onion Router)

**CORESHELL** (malware)

CORESHELL is a downloader used by APT28. The older versions of this malware are known as SOURFACE and newer versions as CORESHELL.(Citation: FireEye APT28) (Citation: FireEye APT28 January 2017)

**OLDBAIT** (malware)

OLDBAIT is a credential harvester used by APT28. (Citation: FireEye APT28) (Citation: FireEye APT28 January 2017)

**Downdelph** (malware)

Downdelph is a first-stage downloader written in Delphi that has been used by APT28 in rare instances between 2013 and 2015. (Citation: ESET Sednit Part 3)

**XAgentOSX** (malware)

XAgentOSX is a trojan that has been used by APT28  on OS X and appears to be a port of their standard CHOPSTICK or XAgent trojan. (Citation: XAgentOSX 2017)

**USBStealer** (malware)

USBStealer is malware that has been used by APT28 since at least 2005 to extract information from air-gapped networks. It does not have the capability to communicate over the Internet and has been used in conjunction with ADVSTORESHELL. (Citation: ESET Sednit USBStealer 2014) (Citation: Kaspersky Sofacy)

**Zebrocy** (malware)

Zebrocy is a Trojan that has been used by APT28 since at least November 2015. The malware comes in several programming language variants, including C++, Delphi, AutoIt, C#, VB.NET, and Golang. (Citation: Palo Alto Sofacy 06-2018)(Citation: Unit42 Cannon Nov 2018)(Citation: Unit42 Sofacy Dec 2018)(Citation: CISA Zebrocy Oct 2020)

**reGeorg** (malware)

reGeorg is an open-source web shell written in Python that can be used as a proxy to bypass firewall rules and tunnel data in and out of targeted networks.(Citation: Fortinet reGeorg MAR 2019)(Citation: GitHub reGeorg 2016)

**Fysbis** (malware)

Fysbis is a Linux-based backdoor used by APT28 that dates back to at least 2014.(Citation: Fysbis Palo Alto Analysis)

**LoJax** (malware)

LoJax is a UEFI rootkit used by APT28 to persist remote access software on targeted systems.(Citation: ESET LoJax Sept 2018)


## Campaigns

### APT28 Nearest Neighbor Campaign

APT28 Nearest Neighbor Campaign was conducted by APT28 from early February 2022 to November 2024 against organizations and individuals with expertise on Ukraine. APT28 primarily leveraged living-off-the-land techniques, while leveraging the zero-day exploitation of CVE-2022-38028. Notably, APT28 leveraged Wi-Fi networks in close proximity to the intended target to gain initial access to the victim environment. By daisy-chaining multiple compromised organizations nearby the intended target, APT28 discovered dual-homed systems (with both a wired and wireless network connection) to enable Wi-Fi and use compromised credentials to connect to the victim network.(Citation: Nearest Neighbor Volexity)

