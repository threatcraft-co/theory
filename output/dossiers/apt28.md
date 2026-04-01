# Threat Actor Dossier: APT28
> MITRE ATT&CK Group ID: **G0007**
> Generated: 2026-03-31 18:52 UTC  |  Sources: mitre_attack, malpedia, alienvault_otx

## Overview

| Field | Value |
|---|---|
| **Origin** | Russia |
| **First Seen** | 2004 |
| **Motivations** | espionage |
| **Also Known As** | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch, SIG40, Grizzly Steppe, G0007, ATK5, Fighting Ursa, ITG05, Blue Athena, TA422, T-APT-12, APT-C-20, UAC-0028, UAC-0001, BlueDelta, APT 28, TsarTeam, Group-4127, Grey-Cloud |

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

## Indicators of Compromise (OTX: 57)

| Type | Value | Confidence | Threat Type | Malware Family | First Seen |
|---|---|---|---|---|---|
| cve | CVE-2015-3043 |  |  |  |  |
| cve | CVE-2015-1701 |  |  |  |  |
| cve | CVE-2014-0515 |  |  |  |  |
| cve | CVE-2015-5119 |  |  |  |  |
| cve | CVE-2015-7645 |  |  |  |  |
| cve | CVE-2015-1641 |  |  |  |  |
| cve | CVE-2014-1776 |  |  |  |  |
| cve | CVE-2015-4902 |  |  |  |  |
| cve | CVE-2014-3897 |  |  |  |  |
| cve | CVE-2014-6332 |  |  |  |  |
| domain | ssl-icloud.com |  |  |  |  |
| domain | updatecenter.name |  |  |  |  |
| domain | securitypractic.com |  |  |  |  |
| domain | pass-google.com |  |  |  |  |
| domain | drivers-update.info |  |  |  |  |
| domain | nato-press.com |  |  |  |  |
| domain | n0vinite.com |  |  |  |  |
| domain | standartnevvs.com |  |  |  |  |
| domain | kavkazcentr.info |  |  |  |  |
| domain | mail.g0v.pl |  |  |  |  |
| email | morata_al@mail.com |  |  |  |  |
| email | partanencomp@mail.com |  |  |  |  |
| email | olivier_servgr@mail.com |  |  |  |  |
| hash_md5 | 8c4fa713c5e2b009114adda758adc445 |  |  |  |  |
| hash_md5 | 3b0ecd011500f61237c205834db0e13a |  |  |  |  |
| hash_md5 | 791428601ad12b9230b9ace4f2138713 |  |  |  |  |
| hash_md5 | 5882fda97fdf78b47081cc4105d44f7c |  |  |  |  |
| hash_md5 | da2a657dc69d7320f2ffc87013f257ad |  |  |  |  |
| hash_md5 | 48656a93f9ba39410763a2196aabc67f |  |  |  |  |
| hash_md5 | 9eebfebe3987fec3c395594dc57a0c4c |  |  |  |  |
| hash_md5 | 8b92fe86c5b7a9e34f433a6fbac8bc3a |  |  |  |  |
| hash_md5 | ead4ec18ebce6890d20757bb9f5285b1 |  |  |  |  |
| hash_md5 | 1259c4fe5efd9bf07fc4c78466f2dd09 |  |  |  |  |
| hash_sha1 | ed9f3e5e889d281437b945993c6c2a80c60fdedc |  |  |  |  |
| hash_sha1 | e742b917d3ef41992e67389cd2fe2aab0f9ace5b |  |  |  |  |
| hash_sha1 | 17661a04b4b150a6f70afdabe3fd9839cc56bee8 |  |  |  |  |
| hash_sha1 | 90c3b756b1bb849cba80994d445e96a9872d0cf5 |  |  |  |  |
| hash_sha1 | 9b276a0f5fd824c3dff638c5c127567c65222230 |  |  |  |  |
| hash_sha1 | 3956cfe34566ba8805f9b1fe0d2639606a404cd4 |  |  |  |  |
| hash_sha1 | 351c3762be9948d01034c69aced97628099a90b0 |  |  |  |  |
| hash_sha1 | ef755f3fa59960838fa2b37b7dedce83ce41f05c |  |  |  |  |
| hash_sha1 | 80dca565807fa69a75a7dd278cef1daaee34236e |  |  |  |  |
| hash_sha1 | c2e8c584d5401952af4f1db08cf4b6016874ddac |  |  |  |  |
| hash_sha256 | fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61 |  |  |  |  |
| hash_sha256 | 8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb |  |  |  |  |
| hash_sha256 | 02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592 |  |  |  |  |
| hash_sha256 | 45a93e4b9ae5bece0d53a3a9a83186b8975953344d4dfb340e9de0015a247c54 |  |  |  |  |
| hash_sha256 | cffa1d9fc336a1ad89af90443b15c98b71e679aeb03b3a68a5e9c3e7ecabc3d4 |  |  |  |  |
| hash_sha256 | 2a06f142d87bd9b66621a30088683d6fcec019ba5cc9e5793e54f8d920ab0134 |  |  |  |  |
| hash_sha256 | 227b7fe495ad9951aebf0aae3c317c1ac526cdd255953f111341b0b11be3bbc5 |  |  |  |  |
| hash_sha256 | 96a19a90caa41406b632a2046f3a39b5579fbf730aca2357f84bf23f2cbc1fd3 |  |  |  |  |
| hash_sha256 | c1b8fc00d815e777e39f34a520342d1942ebd29695c9453951a988c61875bcd7 |  |  |  |  |
| hash_sha256 | 1f81609d9bbdc7f1d2c8846dcfc4292b3e2642301d9c59130f58e21abb0001be |  |  |  |  |
| ip | 185.10.58.170 |  |  |  |  |
| ip | 104.171.117.216 |  |  |  |  |
| ip | 141.255.160.52 |  |  |  |  |
| url | http://www.adobeincorp.net/adhoc/XAgent.ipa |  |  |  |  |

## Targeted Sectors

- Government
- Military
- Aerospace

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
| X-Agent | malware |  |
| ArguePatch | malware | During a campaign against a Ukrainian energy provider, a new loader of a new version of CaddyWiper called "ArguePatch"… |
| DriveOcean | malware | Communicates via Google Drive. |
| Unidentified 114 (APT28 InfoStealer) | malware | According to Trend Micro, this is a small information stealer written in .NET, that pushes its loot to a benign file… |
| XP PrivEsc (CVE-2014-4076) | malware |  |
| X-Tunnel (.NET) | malware | This is a rewrite of win.xtunnel using the .NET framework that surfaced late 2017. |
| Zebrocy (AutoIT) | malware |  |
| CredoMap | malware |  |
| Mocky LNK | malware | LNK files used to lure and orchestrate execution of various scripts, interacting with the Mocky API service. |
| OCEANMAP | malware |  |
| SpyPress | malware | According to ESET, SpyPress is a set of Javascript payloads targeting different webmail frameworks (HORDE, MDAEMON,… |
| STEELHOOK | malware |  |
| MASEPIE | malware |  |
| LAMEHUG | malware | According to CERT-UA, LAMEHUG uses an LLM (Qwen) to dynamically generate commands to gather basic information about a… |
| CaddyWiper | malware | CaddyWiper is another destructive malware believed to be deployed to target Ukraine. CaddyWiper wipes all files under… |
| Computrace | malware |  |
| FusionDrive | malware |  |
| GooseEgg | malware |  |
| Graphite | malware | Trellix describes Graphite as a malware using the Microsoft Graph API and OneDrive for C&C. It was found being deployed… |
| PocoDown | malware | uses POCO C++ cross-platform library, Xor-based string obfuscation, SSL library code and string overlap with Xtunnel,… |

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

### ThreatLocker Blog — 2026-03-11  `MEDIUM relevance`

**[What Is LameHug? How APT28 is using LLMs to generate attack commands](https://www.threatlocker.com/blog/what-is-lamehug-how-apt28-is-using-llms-to-generate-attack-commands)**

APT28 has integrated large language models into its attack infrastructure, deploying the LameHug infostealer to generate attack commands dynamically. This represents an evolution in the group's operational approach, shifting from static command generation to AI-assisted attack execution. The article does not specify targeting sectors, countries, or provide additional tactical details beyond the LLM integration.

*Landscape context: # Threat Landscape Context

This development reflects an emerging pattern of state-sponsored actors operationalizing large language models to automate command generation and reduce operational friction, potentially lowering the technical barriers for distributed attack execution. APT28's integration of LLM-assisted tooling suggests nation-state adoption of AI-driven attack orchestration is transitioning from experimental to operational deployment in live campaigns.*


## Campaigns

- **APT28 Nearest Neighbor Campaign**
  [APT28 Nearest Neighbor Campaign](https://attack.mitre.org/campaigns/C0051) was conducted by [APT28](https://attack.mitre.org/groups/G0007)…
