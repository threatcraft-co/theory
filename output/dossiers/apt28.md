# Threat Actor Dossier: APT28
> MITRE ATT&CK Group ID: **G0007**
> Generated: 2026-04-03 18:26 UTC  |  Sources: alienvault_otx, mitre_attack, malpedia

## Synopsis

Fancy Bear is a Russian state-sponsored threat actor attributed to APT28 that has conducted espionage operations since 2004, primarily targeting government, military, and aerospace sectors. The actor maintains a sophisticated toolkit encompassing 91 documented ATT&CK techniques across defense evasion, collection, credential access, command and control, and persistence, utilizing malware such as CHOPSTICK, Mimikatz, and ADVSTORESHELL alongside living-off-the-land tools including Wevtutil, certutil, and Net. Recent activity through early 2026 demonstrates evolved tradecraft with credential-harvesting campaigns targeting Ukrainian infrastructure users and expanded collection operations against critical infrastructure and state institutions across Europe and Eurasia. Fancy Bear has exploited multiple client-side attack vectors including Microsoft Office zero-days and the MSHTML vulnerability (CVE-2026-21513) to deliver multi-stage payloads via malicious Windows Shortcut files, reflecting sustained focus on widely-used productivity software for initial access. The actor's operational evolution indicates a shift toward intensified targeting of energy, research, and government organizations, demonstrating persistent capability development and sustained Russian state-sponsored espionage priorities.

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

## Detection Opportunities

### T1003 — OS Credential Dumping

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Antivirus Password Dumper Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/category/antivirus/av_password_dumper.yml) | CRITICAL | antivirus | selection |
| [HackTool - Rubeus Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml) | CRITICAL | process_creation / windows | selection |
| [Hacktool Execution - Imphash](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml) | CRITICAL | process_creation / windows | selection |
| [Potential Credential Dumping Via LSASS Process Clone](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lsass_process_clone.yml) | CRITICAL | process_creation / windows | selection |
| [WCE wceaux.dll Access](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_mal_wceaux_dll.yml) | CRITICAL | windows / security | selection |
| [HackTool - Potential Remote Credential Dumping Activity Via CrackMapExec Or Impacket-Secretsdump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml) | HIGH | windows / file_event | selection |
| [HackTool - Rubeus Execution - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_hktl_rubeus.yml) | HIGH | windows / ps_script | selection |
| [Hacktool Execution - PE Metadata](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_execution_via_pe_metadata.yml) | HIGH | process_creation / windows | selection |
| [Linux Keylogging with Pam.d](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml) | HIGH | linux / auditd | 1 of selection_* |
| [Live Memory Dump Using Powershell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_memorydump_getstoragediagnosticinfo.yml) | HIGH | windows / ps_script | selection |

### T1003.001 — LSASS Memory

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Antivirus Password Dumper Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/category/antivirus/av_password_dumper.yml) | CRITICAL | antivirus | selection |
| [HackTool - Credential Dumping Tools Named Pipe Created](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_hktl_generic_cred_dump_tools_pipes.yml) | CRITICAL | windows / pipe_created | selection |
| [HackTool - Dumpert Process Dumper Default File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_hktl_dumpert.yml) | CRITICAL | file_event / windows | selection |
| [HackTool - Dumpert Process Dumper Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml) | CRITICAL | process_creation / windows | selection |
| [HackTool - Inveigh Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_inveigh.yml) | CRITICAL | process_creation / windows | selection |
| [HackTool - SafetyKatz Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_safetykatz.yml) | CRITICAL | process_creation / windows | selection |
| [HackTool - Windows Credential Editor (WCE) Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_wce.yml) | CRITICAL | process_creation / windows | 1 of selection_* |
| [Potential Credential Dumping Via LSASS Process Clone](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lsass_process_clone.yml) | CRITICAL | process_creation / windows | selection |
| [Potential Credential Dumping Via LSASS SilentProcessExit Technique](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_silentprocessexit_lsass.yml) | CRITICAL | registry_event / windows | selection |
| [Windows Credential Editor Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_hack_wce_reg.yml) | CRITICAL | registry_event / windows | selection |

### T1003.003 — NTDS

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Copying Sensitive Files with Credential Data](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml) | HIGH | process_creation / windows | all of selection_esent_* or selection_susp_paths |
| [Create Volume Shadow Copy with Powershell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml) | HIGH | windows / ps_script | selection |
| [Cred Dump Tools Dropped Files](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_cred_dump_tools_dropped_files.yml) | HIGH | file_event / windows | selection |
| [NTDS Exfiltration Filename Patterns](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_ntds_exfil_tools.yml) | HIGH | windows / file_event | selection |
| [NTDS.DIT Creation By Uncommon Parent Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.yml) | HIGH | windows / file_event | selection_file and 1 of selection_process_* |
| [NTDS.DIT Creation By Uncommon Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_process.yml) | HIGH | windows / file_event | selection_ntds and 1 of selection_process_* |
| [PUA - DIT Snapshot Viewer](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_ditsnap.yml) | HIGH | process_creation / windows | selection |
| [Possible Impacket SecretDump Remote Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_impacket_secretdump.yml) | HIGH | windows / security | selection |
| [Possible Impacket SecretDump Remote Activity - Zeek](https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_smb_converted_win_impacket_secretdump.yml) | HIGH | zeek / smb_files | selection |
| [Sensitive File Dump Via Wbadmin.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wbadmin_dump_sensitive_files.yml) | HIGH | process_creation / windows | all of selection_* |

### T1005 — Data from Local System

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [OpenCanary - SMB File Open Request](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_smb_file_open.yml) | HIGH | application / opencanary | selection |
| [SQLite Chromium Profile Data DB Access](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sqlite_chromium_profile_data.yml) | HIGH | process_creation / windows | all of selection_* |
| [SQLite Firefox Profile Data DB Access](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sqlite_firefox_gecko_profile_data.yml) | HIGH | process_creation / windows | all of selection_* |
| [Script Interpreter Spawning Credential Scanner - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml) | HIGH | process_creation / linux | all of selection_* |
| [Script Interpreter Spawning Credential Scanner - Windows](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_script_interpretor_spawn_credential_scanner.yml) | HIGH | process_creation / windows | all of selection_* |
| [VeeamBackup Database Credentials Dump Via Sqlcmd.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.yml) | HIGH | process_creation / windows | all of selection_* |
| [ADFS Database Named Pipe Connection By Uncommon Tool](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_adfs_namedpipe_connection_uncommon_tool.yml) | MEDIUM | windows / pipe_created | selection and not 1 of filter_main_* |
| [Crash Dump Created By Operating System](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_wer_systemerrorreporting/win_system_crash_dump_created.yml) | MEDIUM | windows / system | selection |
| [Esentutl Steals Browser Information](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_esentutl_webcache.yml) | MEDIUM | process_creation / windows | all of selection* |
| [Veeam Backup Database Suspicious Query](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_db_recon.yml) | MEDIUM | process_creation / windows | all of selection_* |

### T1014 — Rootkit

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Triple Cross eBPF Rootkit Install Commands](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_triple_cross_rootkit_install.yml) | HIGH | process_creation / linux | selection |

### T1021.002 — SMB/Windows Admin Shares

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [CobaltStrike Service Installations - System](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml) | CRITICAL | windows / system | selection_id and (selection1 or selection2 or selection3 or selection4) |
| [Potential DCOM InternetExplorer.Application DLL Hijack](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_dcom_iertutil_dll_hijack.yml) | CRITICAL | windows / file_event | selection |
| [Potential DCOM InternetExplorer.Application DLL Hijack - Image Load](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_iexplore_dcom_iertutil_dll_hijack.yml) | CRITICAL | windows / image_load | selection |
| [Wmiprvse Wbemcomn DLL Hijack - File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml) | CRITICAL | windows / file_event | selection |
| [CobaltStrike Service Installations - Security](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_cobaltstrike_service_installs.yml) | HIGH | windows / security | event_id and 1 of selection* |
| [DCOM InternetExplorer.Application Iertutil DLL Hijack - Security](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_dcom_iertutil_dll_hijack.yml) | HIGH | windows / security | selection and not filter |
| [First Time Seen Remote Named Pipe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_lm_namedpipe.yml) | HIGH | windows / security | selection1 and not false_positives |
| [First Time Seen Remote Named Pipe - Zeek](https://github.com/SigmaHQ/sigma/blob/master/rules/network/zeek/zeek_smb_converted_win_lm_namedpipe.yml) | HIGH | zeek / smb_files | selection and not 1 of filter_* |
| [HackTool - SharpMove Tool Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sharpmove.yml) | HIGH | process_creation / windows | selection_img or all of selection_cli_* |
| [Impacket PsExec Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_impacket_psexec.yml) | HIGH | windows / security | selection1 |

### T1030 — Data Transfer Size Limits

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Split A File Into Pieces](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml) | LOW | macos / process_creation | selection |
| [Split A File Into Pieces - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/syscall/lnx_auditd_split_file_into_pieces.yml) | LOW | linux / auditd | selection |

### T1036 — Masquerading

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [CreateDump Process Dump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Forfiles.EXE Child Process Masquerading](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_forfiles_child_process_masquerading.yml) | HIGH | process_creation / windows | selection and not 1 of filter_main_* |
| [HackTool - XORDump Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_xordump.yml) | HIGH | process_creation / windows | selection |
| [Password Protected ZIP File Opened (Suspicious Filenames)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml) | HIGH | windows / security | selection and selection_filename |
| [Potential LSASS Process Dump Via Procdump](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml) | HIGH | process_creation / windows | all of selection_* |
| [Potential SysInternals ProcDump Evasion](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [Process Execution From A Potentially Suspicious Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_execution_path.yml) | HIGH | process_creation / windows | selection and not 1 of filter_optional_* |
| [Process Memory Dump Via Comsvcs.DLL](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml) | HIGH | process_creation / windows | (selection_img and 1 of selection_cli_*) or selection_generic |
| [Renamed CreateDump Utility Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_createdump.yml) | HIGH | process_creation / windows | 1 of selection_* and not filter |
| [Renamed Plink Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_plink.yml) | HIGH | process_creation / windows | selection and not filter |

### T1036.005 — Match Legitimate Resource Name or Location

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection and not filter |
| [Potential MsiExec Masquerading](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml) | HIGH | process_creation / windows | selection and not filter |
| [Scheduled Task Creation Masquerading as System Processes](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_schtasks_system_process.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious Process Masquerading As SvcHost.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml) | HIGH | process_creation / windows | selection and not 1 of filter_main_* |
| [Uncommon Svchost Command Line Parameter](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_uncommon_command_line_flags.yml) | HIGH | process_creation / windows | selection and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Creation Of Pod In System Namespace](https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.yml) | MEDIUM | application / kubernetes / audit | selection |
| [Files With System DLL Name In Unsuspected Locations](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_creation_system_dll_files.yml) | MEDIUM | file_event / windows | selection and not 1 of filter_main_* |
| [Files With System Process Name In Unsuspected Locations](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_creation_system_file.yml) | MEDIUM | file_event / windows | selection and not 1 of filter_main_* |
| [Potential Binary Impersonating Sysinternals Tools](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_tools_masquerading.yml) | MEDIUM | process_creation / windows | 1 of selection_* and not 1 of filter_* |
| [Suspicious Files in Default GPO Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_default_gpo_dir_write.yml) | MEDIUM | windows / file_event | selection |

### T1037.001 — Logon Script (Windows)

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Persistence Via Logon Scripts - CommandLine](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_registry_logon_script.yml) | HIGH | process_creation / windows | selection |
| [Uncommon Userinit Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.yml) | HIGH | process_creation / windows | selection and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Potential Persistence Via Logon Scripts - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_logon_scripts_userinitmprlogonscript.yml) | MEDIUM | registry_set / windows | selection |

### T1039 — Data from Network Shared Drive

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Copy From Or To Admin Share Or Sysvol Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml) | MEDIUM | process_creation / windows | selection_target and (selection_other_tools or all of selection_cmd_* or all ... |
| [Suspicious Access to Sensitive File Extensions](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_raccess_sensitive_fext.yml) | MEDIUM | windows / security | selection |

### T1040 — Network Sniffing

**Sigma Rules (9)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Sniffing](https://github.com/SigmaHQ/sigma/blob/master/rules/network/cisco/aaa/cisco_cli_net_sniff.yml) | MEDIUM | cisco / aaa | keywords |
| [Harvesting Of Wifi Credentials Via Netsh.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_netsh_wifi_credential_harvesting.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [New Network Trace Capture Started Via Netsh.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_netsh_packet_capture.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [PktMon.EXE Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pktmon_execution.yml) | MEDIUM | process_creation / windows | selection |
| [Potential Network Sniffing Activity Using Network Tools](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_network_sniffing.yml) | MEDIUM | process_creation / windows | 1 of selection_* |
| [Potential Packet Capture Activity Via Start-NetEventSession - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_packet_capture.yml) | MEDIUM | windows / ps_script | selection |
| [Windows Pcap Drivers](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_pcap_drivers.yml) | MEDIUM | windows / security | selection |
| [Network Sniffing - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_network_sniffing.yml) | LOW | linux / auditd | 1 of selection_* |
| [Network Sniffing - MacOs](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_network_sniffing.yml) | INFORMATIONAL | process_creation / macos | selection |

### T1056.001 — Keylogging

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Linux Keylogging with Pam.d](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml) | HIGH | linux / auditd | 1 of selection_* |
| [Potential Keylogger Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_keylogger_activity.yml) | MEDIUM | windows / ps_script | selection |
| [Powershell Keylogging](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_keylogging.yml) | MEDIUM | windows / ps_script | 1 of selection_* |

### T1057 — Process Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - PCHunter Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_pchunter.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [Recon Command Output Piped To Findstr.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_findstr_recon_pipe_output.yml) | MEDIUM | process_creation / windows | selection and not 1 of filter_optional_* |
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/master/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | cisco / aaa | keywords |
| [Suspicious Process Discovery With Get-Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml) | LOW | windows / ps_script | selection |
| [System Info Discovery via Sysinfo Syscall](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/syscall/lnx_auditd_susp_discovery_sysinfo_syscall.yml) | LOW | linux / auditd | selection and not 1 of filter_optional_* |

### T1059.001 — PowerShell

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Bad Opsec Powershell Code Artifacts](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_module/posh_pm_bad_opsec_artifacts.yml) | CRITICAL | windows / ps_module | selection_4103 |
| [Silence.EDA Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_apt_silence_eda.yml) | CRITICAL | windows / ps_script | empire and dnscat |
| [AWS EC2 Startup Shell Script Change](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml) | HIGH | aws / cloudtrail | selection_source |
| [Base64 Encoded PowerShell Command Detected](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml) | HIGH | process_creation / windows | selection |
| [BloodHound Collection Files](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml) | HIGH | windows / file_event | selection and not 1 of filter_optional_* |
| [Cmd.EXE Missing Space Characters Execution Anomaly](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_no_space_execution.yml) | HIGH | process_creation / windows | 1 of selection* and not 1 of filter_* |
| [DSInternals Suspicious PowerShell Cmdlets](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_dsinternals_cmdlets.yml) | HIGH | windows / process_creation | selection |
| [DSInternals Suspicious PowerShell Cmdlets - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_dsinternals_cmdlets.yml) | HIGH | windows / ps_script | selection |
| [Exchange PowerShell Snap-Ins Usage](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_snapins_hafnium.yml) | HIGH | process_creation / windows | all of selection_* and not 1 of filter_* |
| [Execution of Powershell Script in Public Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_public_folder.yml) | HIGH | process_creation / windows | selection |

### T1059.003 — Windows Command Shell

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [AWS EC2 Startup Shell Script Change](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml) | HIGH | aws / cloudtrail | selection_source |
| [Conhost.exe CommandLine Path Traversal](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_conhost_path_traversal.yml) | HIGH | process_creation / windows | selection |
| [DNS Query by Finger Utility](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_finger.yml) | HIGH | windows / dns_query | selection |
| [HTML Help HH.EXE Suspicious Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml) | HIGH | process_creation / windows | selection |
| [HackTool - CrackMapExec Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution.yml) | HIGH | process_creation / windows | 1 of selection_* or all of part_localauth* |
| [HackTool - CrackMapExec Execution Patterns](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution_patterns.yml) | HIGH | process_creation / windows | selection |
| [HackTool - Koadic Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_koadic.yml) | HIGH | process_creation / windows | all of selection_* |
| [HackTool - RedMimicry Winnti Playbook Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_redmimicry_winnti_playbook.yml) | HIGH | windows / process_creation | selection |
| [Network Connection Initiated via Finger.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_finger.yml) | HIGH | network_connection / windows | selection |
| [Operator Bloopers Cobalt Strike Commands](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_bloopers_cmd.yml) | HIGH | process_creation / windows | all of selection_* |

### T1068 — Exploitation for Privilege Escalation

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Audit CVE Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml) | CRITICAL | windows / application | selection |
| [HackTool - SysmonEOP Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sysmoneop.yml) | CRITICAL | process_creation / windows | 1 of selection_* |
| [Possible Coin Miner CPU Priority Param](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_coinminer.yml) | CRITICAL | linux / auditd | 1 of cmd* |
| [Buffer Overflow Attempts](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/lnx_buffer_overflows.yml) | HIGH | linux | keywords |
| [HKTL - SharpSuccessor Privilege Escalation Tool Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sharpsuccessor_execution.yml) | HIGH | process_creation / windows | selection |
| [Malicious Driver Load](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/driver_load/driver_load_win_mal_drivers.yml) | HIGH | windows / driver_load | selection |
| [OMIGOD SCX RunAsProvider ExecuteScript](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml) | HIGH | linux / process_creation | selection |
| [OMIGOD SCX RunAsProvider ExecuteShellCommand](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml) | HIGH | linux / process_creation | selection |
| [Process Explorer Driver Creation By Non-Sysinternals Binary](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_sysinternals_procexp_driver_susp_creation.yml) | HIGH | windows / file_event | selection and not 1 of filter_main_* |
| [Suspicious Spool Service Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_spoolsv_susp_child_processes.yml) | HIGH | process_creation / windows | spoolsv and ( suspicious_unrestricted or (suspicious_net and not suspicious_n... |

### T1070.001 — Clear Windows Event Logs

**Sigma Rules (6)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Important Windows Eventlog Cleared](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml) | HIGH | windows / system | selection |
| [Security Eventlog Cleared](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml) | HIGH | windows / security | 1 of selection_* |
| [Suspicious Eventlog Clearing or Configuration Change Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml) | HIGH | process_creation / windows | (all of selection_wevtutil_*) or (all of selection_other_ps_*) or (selection_... |
| [Suspicious Windows Trace ETW Session Tamper Via Logman.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.yml) | HIGH | process_creation / windows | all of selection* |
| [Eventlog Cleared](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml) | MEDIUM | windows / system | selection and not 1 of filter_main_* |
| [Suspicious Eventlog Clear](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_clear_eventlog.yml) | MEDIUM | windows / ps_script | selection |

### T1070.004 — File Deletion

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Prefetch File Deleted](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml) | HIGH | windows / file_delete | selection and not 1 of filter_main_* |
| [Suspicious Ping/Del Command Combination](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_ping_del_combined_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [ADS Zone.Identifier Deleted By Uncommon Application](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_zone_identifier_ads_uncommon.yml) | MEDIUM | windows / file_delete | selection and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Backup Catalog Deleted](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/microsoft_windows_backup/win_susp_backup_delete.yml) | MEDIUM | windows / application | selection |
| [Cisco File Deletion](https://github.com/SigmaHQ/sigma/blob/master/rules/network/cisco/aaa/cisco_cli_file_deletion.yml) | MEDIUM | cisco / aaa | keywords |
| [File Deleted Via Sysinternals SDelete](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_sysinternals_sdelete_file_deletion.yml) | MEDIUM | windows / file_delete | selection and not 1 of filter_* |
| [Greedy File Deletion Using Del](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_del_greedy_deletion.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Potential Secure Deletion with SDelete](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml) | MEDIUM | windows / security | selection |
| [Potentially Suspicious Ping/Copy Command Combination](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_ping_copy_combined_execution.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Directory Removal Via Rmdir](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_rmdir_execution.yml) | LOW | process_creation / windows | all of selection_* |

### T1070.006 — Timestomp

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [File Time Attribute Change](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_change_file_time_attr.yml) | MEDIUM | macos / process_creation | selection |
| [File Time Attribute Change - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_change_file_time_attr.yml) | MEDIUM | linux / auditd | execve and touch and selection2 |
| [Powershell Timestomp](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml) | MEDIUM | windows / ps_script | selection_ioc |
| [Touch Suspicious Service File](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml) | MEDIUM | linux / process_creation | selection |
| [Unauthorized System Time Modification](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_time_modification.yml) | LOW | windows / security | selection and not 1 of filter_main_* and not 1 of filter_optional_* |

### T1071.001 — Web Protocols

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - BabyShark Agent Default URL Pattern](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_hktl_baby_shark_default_agent_url.yml) | CRITICAL | proxy | selection |
| [PwnDrp Access](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_pwndrop.yml) | CRITICAL | proxy | selection |
| [APT User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_apt.yml) | HIGH | proxy | selection |
| [Bitsadmin to Uncommon IP Server Address](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_ip.yml) | HIGH | proxy | selection |
| [Bitsadmin to Uncommon TLD](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml) | HIGH | proxy | selection and not falsepositives |
| [Crypto Miner User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_cryptominer.yml) | HIGH | proxy | selection |
| [Exploit Framework User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_frameworks.yml) | HIGH | proxy | selection |
| [HackTool - CobaltStrike Malleable Profile Patterns - Proxy](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_hktl_cobalt_strike_malleable_c2_requests.yml) | HIGH | proxy | 1 of selection_* and not 1 of filter_main_* |
| [HackTool - Empire UserAgent URI Combo](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_hktl_empire_ua_uri_patterns.yml) | HIGH | proxy | selection |
| [Malware User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_malware.yml) | HIGH | proxy | selection |

### T1074.001 — Local Data Staging

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_zip_compress.yml) | MEDIUM | windows / process_creation | selection |
| [Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_module/posh_pm_susp_zip_compress.yml) | MEDIUM | windows / ps_module | selection |
| [Zip A Folder With PowerShell For Staging In Temp - PowerShell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_susp_zip_compress.yml) | MEDIUM | windows / powershell-classic | selection |
| [Zip A Folder With PowerShell For Staging In Temp - PowerShell Script](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_zip_compress.yml) | MEDIUM | windows / ps_script | selection |

### T1078 — Valid Accounts

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Win Susp Computer Name Containing Samtheadmin](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_computer_name.yml) | CRITICAL | security / windows | 1 of selection* |
| [Account Created And Deleted Within A Close Time Frame](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_ad_account_created_deleted.yml) | HIGH | azure / auditlogs | selection |
| [Activity From Anonymous IP Address](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_activity.yml) | HIGH | azure / riskdetection | selection |
| [Atypical Travel](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_atypical_travel.yml) | HIGH | azure / riskdetection | selection |
| [Azure AD Threat Intelligence](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_threat_intel.yml) | HIGH | azure / riskdetection | selection |
| [Azure Login Bypassing Conditional Access Policies](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/audit/microsoft365_bypass_conditional_access.yml) | HIGH | audit / m365 | selection and not 1 of filter_main_* |
| [Azure Subscription Permission Elevation Via AuditLogs](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_subscription_permissions_elevation_via_auditlogs.yml) | HIGH | azure / auditlogs | selection |
| [External Remote SMB Logon from Public IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml) | HIGH | windows / security | selection and not 1 of filter_main_* |
| [Impossible Travel](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_impossible_travel.yml) | HIGH | azure / riskdetection | selection |
| [Invalid PIM License](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml) | HIGH | azure / pim | selection |

### T1078.004 — Cloud Accounts

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [AWS IAM S3Browser LoginProfile Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_iam_s3browser_loginprofile_creation.yml) | HIGH | aws / cloudtrail | selection |
| [AWS IAM S3Browser Templated S3 Bucket Policy Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml) | HIGH | aws / cloudtrail | selection |
| [AWS IAM S3Browser User or AccessKey Creation](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml) | HIGH | aws / cloudtrail | selection |
| [Application AppID Uri Configuration Changes](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_appid_uri_changes.yml) | HIGH | azure / auditlogs | selection |
| [Application URI Configuration Changes](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_uri_modifications.yml) | HIGH | azure / auditlogs | selection |
| [Azure Subscription Permission Elevation Via ActivityLogs](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/activity_logs/azure_subscription_permissions_elevation_via_activitylogs.yml) | HIGH | azure / activitylogs | selection |
| [Changes To PIM Settings](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_pim_change_settings.yml) | HIGH | azure / auditlogs | selection |
| [Okta New Admin Console Behaviours](https://github.com/SigmaHQ/sigma/blob/master/rules/identity/okta/okta_new_behaviours_admin_console.yml) | HIGH | okta / okta | all of selection_* |
| [PIM Approvals And Deny Elevation](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_pim_activation_approve_deny.yml) | HIGH | azure / auditlogs | selection |
| [Potential MFA Bypass Using Legacy Client Authentication](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/signin_logs/azure_ad_suspicious_signin_bypassing_mfa.yml) | HIGH | azure / signinlogs | selection |

### T1083 — File and Directory Discovery

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - PCHunter Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_pchunter.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [PUA - Seatbelt Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_seatbelt.yml) | HIGH | process_creation / windows | selection_img or all of selection_group_* |
| [Shell Execution GCC  - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml) | HIGH | process_creation / linux | all of selection_* |
| [Shell Execution via Find - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_find_shell_execution.yml) | HIGH | process_creation / linux | all of selection_* |
| [Shell Execution via Flock - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_flock_shell_execution.yml) | HIGH | process_creation / linux | all of selection_* |
| [Shell Execution via Nice - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_nice_shell_execution.yml) | HIGH | process_creation / linux | selection |
| [Vim GTFOBin Abuse - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_vim_shell_execution.yml) | HIGH | process_creation / linux | all of selection_* |
| [PUA - TruffleHog Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_trufflehog.yml) | MEDIUM | process_creation / windows | selection_img or all of selection_cli_* |
| [PUA - TruffleHog Execution - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_pua_trufflehog.yml) | MEDIUM | process_creation / linux | selection_img or all of selection_cli_* |
| [Potential Discovery Activity Using Find - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_find_execution.yml) | MEDIUM | process_creation / linux | selection |

### T1090.002 — External Proxy

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [RDP over Reverse SSH Tunnel WFP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml) | HIGH | windows / security | selection and ( sourceRDP or destinationRDP ) and not 1 of filter* |
| [Network Communication Initiated To Portmap.IO Domain](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_portmap.yml) | MEDIUM | network_connection / windows | selection |

### T1090.003 — Multi-hop Proxy

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [DNS Query Tor .Onion Address - Sysmon](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml) | HIGH | windows / dns_query | selection |
| [Query Tor Onion Address - DNS Client](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/dns_client/win_dns_client_tor_onion.yml) | HIGH | windows / dns-client | selection |
| [Tor Client/Browser Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_tor_execution.yml) | HIGH | process_creation / windows | selection |

### T1091 — Replication Through Removable Media

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [External Disk Drive Or USB Storage Device Was Recognized By The System](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_external_device.yml) | LOW | windows / security | all of selection_* |

### T1102.002 — Bidirectional Communication

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Github Self-Hosted Runner Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_github_self_hosted_runner.yml) | MEDIUM | process_creation / windows | all of selection_worker_* or all of selection_listener_* |
| [Telegram API Access](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_telegram_api.yml) | MEDIUM | proxy | selection and not filter |
| [Telegram Bot API Request](https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_susp_telegram_api.yml) | MEDIUM | dns | selection |

### T1105 — Ingress Tool Transfer

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Curl Download And Execute Combination](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.yml) | HIGH | process_creation / windows | selection |
| [File Download And Execution Via IEExec.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_ieexec_download.yml) | HIGH | process_creation / windows | all of selection_* |
| [File Download From IP Based URL Via CertOC.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml) | HIGH | process_creation / windows | all of selection* |
| [File Download Using Notepad++ GUP Utility](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_gup_download.yml) | HIGH | process_creation / windows | all of selection* and not filter |
| [File Download Via Bitsadmin To A Suspicious Target Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.yml) | HIGH | process_creation / windows | all of selection_* |
| [File Download Via Windows Defender MpCmpRun.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mpcmdrun_download_arbitrary_file.yml) | HIGH | process_creation / windows | all of selection_* |
| [File Download with Headless Browser](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml) | HIGH | process_creation / windows | selection and not 1 of filter_optional_* |
| [File With Suspicious Extension Downloaded Via Bitsadmin](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml) | HIGH | process_creation / windows | all of selection_* |
| [Finger.EXE Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_finger_execution.yml) | HIGH | process_creation / windows | selection |
| [Legitimate Application Writing Files In Uncommon Location](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_legitimate_app_dropping_in_uncommon_location.yml) | HIGH | windows / file_event | all of selection_* |

### T1110 — Brute Force

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [External Remote SMB Logon from Public IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml) | HIGH | windows / security | selection and not 1 of filter_main_* |
| [Hack Tool User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_hacktool.yml) | HIGH | proxy | selection |
| [HackTool - CrackMapExec Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution.yml) | HIGH | process_creation / windows | 1 of selection_* or all of part_localauth* |
| [HackTool - Hydra Password Bruteforce Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_hydra.yml) | HIGH | process_creation / windows | selection |
| [Password Spray Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_password_spray.yml) | HIGH | azure / riskdetection | selection |
| [Potential MFA Bypass Using Legacy Client Authentication](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/signin_logs/azure_ad_suspicious_signin_bypassing_mfa.yml) | HIGH | azure / signinlogs | selection |
| [Sign-in Failure Due to Conditional Access Requirements Not Met](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/signin_logs/azure_conditional_access_failure.yml) | HIGH | azure / signinlogs | selection |
| [Use of Legacy Authentication Protocols](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/signin_logs/azure_legacy_authentication_protocols.yml) | HIGH | azure / signinlogs | selection |
| [AWS ConsoleLogin Failed Authentication](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml) | MEDIUM | aws / cloudtrail | selection |
| [Account Lockout](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/signin_logs/azure_account_lockout.yml) | MEDIUM | azure / signinlogs | selection |

### T1110.001 — Password Guessing

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - Hydra Password Bruteforce Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_hydra.yml) | HIGH | process_creation / windows | selection |
| [Suspicious Rejected SMB Guest Logon From IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/smbclient/security/win_smbclient_security_susp_failed_guest_logon.yml) | MEDIUM | windows / smbclient-security | selection |
| [Suspicious Connection to Remote Account](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_networkcredential.yml) | LOW | windows / ps_script | selection |

### T1113 — Screen Capture

**Sigma Rules (9)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Periodic Backup For System Registry Hives Enabled](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_enable_periodic_backup.yml) | MEDIUM | registry_set / windows | selection |
| [Screen Capture Activity Via Psr.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_psr_capture_screenshots.yml) | MEDIUM | process_creation / windows | selection |
| [Windows Recall Feature Enabled - DisableAIDataAnalysis Value Deleted](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_enable_windows_recall.yml) | MEDIUM | registry_delete / windows | selection |
| [Windows Recall Feature Enabled - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_enable_windows_recall.yml) | MEDIUM | registry_set / windows | selection |
| [Windows Recall Feature Enabled Via Reg.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_enable_windows_recall.yml) | MEDIUM | process_creation / windows | selection_img and selection_value and 1 of selection_action_* |
| [Windows Screen Capture with CopyFromScreen](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_capture_screenshots.yml) | MEDIUM | windows / ps_script | selection |
| [Screen Capture - macOS](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_screencapture.yml) | LOW | macos / process_creation | selection |
| [Screen Capture with Import Tool](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_screencapture_import.yml) | LOW | linux / auditd | import and (import_window_root or import_no_window_root) |
| [Screen Capture with Xwd](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_screencaputre_xwd.yml) | LOW | linux / auditd | selection and 1 of xwd_* |

### T1119 — Automated Collection

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Automated Collection Command PowerShell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_automated_collection.yml) | MEDIUM | windows / ps_script | all of selection* |
| [Automated Collection Command Prompt](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_automated_collection.yml) | MEDIUM | process_creation / windows | selection_ext and 1 of selection_other_* |
| [Recon Information for Export with Command Prompt](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_recon.yml) | MEDIUM | windows / process_creation | all of selection* |
| [Recon Information for Export with PowerShell](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_recon_export.yml) | MEDIUM | windows / ps_script | all of selection* |

### T1120 — Peripheral Device Discovery

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Fsutil Drive Enumeration](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_fsutil_drive_enumeration.yml) | LOW | process_creation / windows | all of selection_* |
| [Powershell Suspicious Win32_PnPEntity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_win32_pnpentity.yml) | LOW | windows / ps_script | selection |

### T1133 — External Remote Services

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [External Remote SMB Logon from Public IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml) | HIGH | windows / security | selection and not 1 of filter_main_* |
| [OpenCanary - SSH Login Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_ssh_login_attempt.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - SSH New Connection Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_ssh_new_connection.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - Telnet Login Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_telnet_login_attempt.yml) | HIGH | application / opencanary | selection |
| [Running Chrome VPN Extensions via the Registry 2 VPN Extension](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_chrome_extension.yml) | HIGH | registry_set / windows | all of chrome_* |
| [Suspicious File Created by ArcSOC.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_arcsoc_susp_file_created.yml) | HIGH | file_event / windows | selection |
| [Unusual Child Process of dns.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_dns_susp_child_process.yml) | HIGH | process_creation / windows | selection and not filter |
| [Unusual File Deletion by Dns.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_delete/file_delete_win_unusual_deletion_by_dns_exe.yml) | HIGH | file_delete / windows | selection and not filter |
| [Unusual File Modification by dns.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_change/file_change_win_unusual_modification_by_dns_exe.yml) | HIGH | file_change / windows | selection and not filter |
| [User Added to Remote Desktop Users Group](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop_group.yml) | HIGH | process_creation / windows | all of selection_* |

### T1134.001 — Token Impersonation/Theft

**Sigma Rules (9)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - Koh Default Named Pipe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_hktl_koh_default_pipe.yml) | CRITICAL | windows / pipe_created | selection |
| [HackTool - NoFilter Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_hktl_nofilter.yml) | HIGH | windows / security | 1 of selection_* |
| [HackTool - SharpDPAPI Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sharp_dpapi_execution.yml) | HIGH | windows / process_creation | selection_img or (selection_other_cli and 1 of selection_other_options_*) |
| [HackTool - SharpImpersonation Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sharp_impersonation.yml) | HIGH | windows / process_creation | 1 of selection_* |
| [Meterpreter or Cobalt Strike Getsystem Service Installation - Security](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml) | HIGH | windows / security | selection_eid and 1 of selection_cli_* |
| [Meterpreter or Cobalt Strike Getsystem Service Installation - System](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml) | HIGH | windows / system | selection_id and 1 of selection_cli_* |
| [Potential Meterpreter/CobaltStrike Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_meterpreter_getsystem.yml) | HIGH | process_creation / windows | selection_img and 1 of selection_technique_* and not 1 of filter_* |
| [HackTool - Impersonate Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_impersonate.yml) | MEDIUM | windows / process_creation | all of selection_commandline_* or selection_hash |
| [Potential Access Token Abuse](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_access_token_abuse.yml) | MEDIUM | windows / security | selection |

### T1137.002 — Office Test

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious Microsoft Office Child Process - MacOS](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml) | HIGH | macos / process_creation | selection |
| [Office Application Startup - Office Test](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_office_test_regadd.yml) | MEDIUM | registry_event / windows | selection |

### T1140 — Deobfuscate/Decode Files or Information

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Base64 Encoded PowerShell Command Detected](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml) | HIGH | process_creation / windows | selection |
| [MSHTA Execution with Suspicious File Extensions](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Ping Hex IP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_ping_hex_ip.yml) | HIGH | process_creation / windows | selection |
| [Potential Base64 Decoded From Images](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_tail_base64_decode_from_image.yml) | HIGH | macos / process_creation | all of selection_* |
| [PowerShell Base64 Encoded FromBase64String Cmdlet](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_base64_frombase64string.yml) | HIGH | process_creation / windows | selection |
| [Suspicious Inbox Manipulation Rules](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_inbox_manipulation.yml) | HIGH | azure / riskdetection | selection |
| [DNS-over-HTTPS Enabled by Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml) | MEDIUM | windows / registry_set | 1 of selection_* |
| [Linux Base64 Encoded Pipe to Shell](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml) | MEDIUM | linux / process_creation | all of selection_* |
| [Linux Base64 Encoded Shebang In CLI](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml) | MEDIUM | linux / process_creation | selection |
| [Linux Shell Pipe to Shell](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml) | MEDIUM | linux / process_creation | all of selection* |

### T1189 — Drive-by Compromise

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cross Site Scripting Strings](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_xss_in_access_logs.yml) | HIGH | webserver | select_method and keywords and not filter |
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection and not filter |
| [Suspicious Browser Child Process - MacOS](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.yml) | MEDIUM | process_creation / macos | selection and not 1 of filter_main_* and not 1 of filter_optional_* |

### T1190 — Exploit Public-Facing Application

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [DNS Query to External Service Interaction Domains](https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_external_service_interaction_domains.yml) | HIGH | dns | selection and not 1 of filter_main_* |
| [Hack Tool User Agent](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_ua_hacktool.yml) | HIGH | proxy | selection |
| [JNDIExploit Pattern](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_jndi_exploit.yml) | HIGH | webserver | keywords |
| [Java Payload Strings](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_java_payload_in_access_logs.yml) | HIGH | webserver | keywords |
| [OMIGOD SCX RunAsProvider ExecuteScript](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml) | HIGH | linux / process_creation | selection |
| [OMIGOD SCX RunAsProvider ExecuteShellCommand](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml) | HIGH | linux / process_creation | selection |
| [OpenCanary - FTP Login Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_ftp_login_attempt.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - HTTP GET Request](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_http_get.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - HTTP POST Login Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_http_post_login_attempt.yml) | HIGH | application / opencanary | selection |
| [Potential JNDI Injection Exploitation In JVM Based Application](https://github.com/SigmaHQ/sigma/blob/master/rules/application/jvm/java_jndi_injection_exploitation_attempt.yml) | HIGH | application / jvm | keywords |

### T1199 — Trusted Relationship

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Microsoft 365 - User Restricted from Sending Email](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/threat_management/microsoft365_user_restricted_from_sending_email.yml) | MEDIUM | threat_management / m365 | selection |

### T1203 — Exploitation for Client Execution

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Antivirus Exploitation Framework Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/category/antivirus/av_exploiting.yml) | CRITICAL | antivirus | selection |
| [Audit CVE Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml) | CRITICAL | windows / application | selection |
| [Network Connection Initiated By Eqnedt32.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_eqnedt.yml) | HIGH | network_connection / windows | selection |
| [OMIGOD SCX RunAsProvider ExecuteScript](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executescript.yml) | HIGH | linux / process_creation | selection |
| [OMIGOD SCX RunAsProvider ExecuteShellCommand](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml) | HIGH | linux / process_creation | selection |
| [Suspicious ArcSOC.exe Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_arcsoc_susp_child_process.yml) | HIGH | process_creation / windows | selection and not 1 of filter_main_* |
| [Suspicious Download and Execute Pattern via Curl/Wget](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_curl_wget_exec_tmp.yml) | HIGH | process_creation / linux | all of selection_* |
| [Suspicious HWP Sub Processes](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hwp_exploits.yml) | HIGH | process_creation / windows | selection |
| [Suspicious Invocation of Shell via Rsync](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml) | HIGH | process_creation / linux | selection and not 1 of filter_main_* |
| [Suspicious Spool Service Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_spoolsv_susp_child_processes.yml) | HIGH | process_creation / windows | spoolsv and ( suspicious_unrestricted or (suspicious_net and not suspicious_n... |

### T1204.001 — Malicious Link

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential ClickFix Execution Pattern - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_potential_clickfix_execution.yml) | HIGH | registry_set / windows | all of selection_* |
| [Suspicious ClickFix/FileFix Execution Pattern](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_clickfix_filefix_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Symlink Etc Passwd](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/lnx_symlink_etc_passwd.yml) | HIGH | linux | keywords |
| [Suspicious Execution via macOS Script Editor](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml) | MEDIUM | process_creation / macos | all of selection_* |

### T1204.002 — Malicious File

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [File With Uncommon Extension Created By An Office Application](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_office_susp_file_extension.yml) | HIGH | windows / file_event | all of selection* and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/master/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection and not filter |
| [GAC DLL Loaded Via Office Applications](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_office_dotnet_gac_dll_load.yml) | HIGH | image_load / windows | selection |
| [HackTool - LittleCorporal Generated Maldoc Injection](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_hktl_littlecorporal_generated_maldoc.yml) | HIGH | process_access / windows | selection |
| [MMC Executing Files with Reversed Extensions Using RTLO Abuse](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mmc_rlo_abuse_pattern.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious Binary In User Directory Spawned From Office Application](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_spawn_exe_from_users_directory.yml) | HIGH | process_creation / windows | selection and not filter |
| [Suspicious LNK Command-Line Padding with Whitespace Characters](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_lnk_exec_hidden_cmd.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious Microsoft Office Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml) | HIGH | process_creation / windows | selection_parent and 1 of selection_child_* |
| [Suspicious Microsoft Office Child Process - MacOS](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml) | HIGH | macos / process_creation | selection |
| [Suspicious Outlook Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_outlook_susp_child_processes.yml) | HIGH | process_creation / windows | selection |

### T1210 — Exploitation of Remote Services

**Sigma Rules (7)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Audit CVE Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml) | CRITICAL | windows / application | selection |
| [Zerologon Exploitation Using Well-known Tools](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml) | CRITICAL | system / windows | selection and keywords |
| [HackTool - SharpWSUS/WSUSpendu Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_sharpwsus_wsuspendu_execution.yml) | HIGH | windows / process_creation | all of selection_wsuspendu_* or all of selection_sharpwsus_* |
| [Terminal Service Process Spawn](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_termserv_proc_spawn.yml) | HIGH | windows / process_creation | selection and not 1 of filter_* |
| [Apache Threading Error](https://github.com/SigmaHQ/sigma/blob/master/rules/web/product/apache/web_apache_threading_error.yml) | MEDIUM | apache | keywords |
| [Suspicious SysAidServer Child](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_java_sysaidserver_susp_child_process.yml) | MEDIUM | process_creation / windows | selection |
| [DNS Query Request By QuickAssist.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query/dns_query_win_quickassist.yml) | LOW | dns_query / windows | selection |

### T1211 — Exploitation for Defense Evasion

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Audit CVE Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml) | CRITICAL | windows / application | selection |
| [Microsoft Malware Protection Engine Crash](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/application_error/win_application_error_msmpeng_crash.yml) | HIGH | windows / application | selection |
| [Microsoft Malware Protection Engine Crash - WER](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/application/windows_error_reporting/win_application_msmpeng_crash_wer.yml) | HIGH | windows / application | selection |
| [Writing Of Malicious Files To The Fonts Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_hiding_malware_in_fonts_folder.yml) | MEDIUM | windows / process_creation | all of selection_* |

### T1213 — Data from Information Repositories

**Sigma Rules (7)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [OpenCanary - GIT Clone Request](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_git_clone_request.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - MSSQL Login Attempt Via SQLAuth](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_mssql_login_sqlauth.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - MSSQL Login Attempt Via Windows Authentication](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_mssql_login_winauth.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - MySQL Login Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_mysql_login_attempt.yml) | HIGH | application / opencanary | selection |
| [OpenCanary - REDIS Action Command Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_redis_command.yml) | HIGH | application / opencanary | selection |
| [Bitbucket User Details Export Attempt Detected](https://github.com/SigmaHQ/sigma/blob/master/rules/application/bitbucket/audit/bitbucket_audit_user_details_export_attempt_detected.yml) | MEDIUM | bitbucket / audit | selection |
| [Bitbucket User Permissions Export Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml) | MEDIUM | bitbucket / audit | selection |

### T1218.011 — Rundll32

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - F-Secure C3 Load by Rundll32](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_c3_rundll32_pattern.yml) | CRITICAL | process_creation / windows | selection |
| [Bad Opsec Defaults Sacrificial Processes With Improper Arguments](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_bad_opsec_sacrificial_processes.yml) | HIGH | process_creation / windows | 1 of selection_* and not 1 of filter_optional_* |
| [CobaltStrike Load by Rundll32](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml) | HIGH | process_creation / windows | all of selection* |
| [HTML Help HH.EXE Suspicious Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml) | HIGH | process_creation / windows | selection |
| [HackTool - RedMimicry Winnti Playbook Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_redmimicry_winnti_playbook.yml) | HIGH | windows / process_creation | selection |
| [Potential PowerShell Execution Via DLL](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_powershell_execution_via_dll.yml) | HIGH | process_creation / windows | all of selection_* |
| [Process Access via TrolleyExpress Exclusion](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_citrix_trolleyexpress_procdump.yml) | HIGH | process_creation / windows | selection or ( renamed and not 1 of filter* ) |
| [RunDLL32 Spawning Explorer](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_spawn_explorer.yml) | HIGH | process_creation / windows | selection and not filter |
| [Rundll32 UNC Path Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml) | HIGH | process_creation / windows | all of selection_* |
| [Shell32 DLL Execution in Suspicious Directory](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |

### T1221 — Template Injection

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Server Side Template Injection Strings](https://github.com/SigmaHQ/sigma/blob/master/rules/web/webserver_generic/web_ssti_in_access_logs.yml) | HIGH | webserver | select_method and keywords and not filter |

### T1498 — Network Denial of Service

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [OpenCanary - NTP Monlist Request](https://github.com/SigmaHQ/sigma/blob/master/rules/application/opencanary/opencanary_ntp_monlist.yml) | HIGH | application / opencanary | selection |
| [Deployment Deleted From Kubernetes Cluster](https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_deployment_deleted.yml) | LOW | application / kubernetes / audit | selection |

### T1505.003 — Web Shell

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Certificate Request Export to Exchange Webserver](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/msexchange/win_exchange_proxyshell_certificate_generation.yml) | CRITICAL | msexchange-management / windows | keywords_export_command and keywords_export_params |
| [Mailbox Export to Exchange Webserver](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/msexchange/win_exchange_proxyshell_mailbox_export.yml) | CRITICAL | msexchange-management / windows | (export_command and export_params) or role_assignment |
| [Webshell Remote Command Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/syscall/lnx_auditd_web_rce.yml) | CRITICAL | linux / auditd | selection |
| [Antivirus Web Shell Detection](https://github.com/SigmaHQ/sigma/blob/master/rules/category/antivirus/av_webshell.yml) | HIGH | antivirus | selection |
| [Chopper Webshell Process Pattern](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_webshell_chopper.yml) | HIGH | process_creation / windows | all of selection_* |
| [Exchange Set OabVirtualDirectory ExternalUrl Property](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/msexchange/win_exchange_set_oabvirtualdirectory_externalurl.yml) | HIGH | windows / msexchange-management | keywords |
| [Linux Webshell Indicators](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_webshell_detection.yml) | HIGH | linux / process_creation | 1 of selection_* and sub_processes |
| [Shellshock Expression](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/lnx_shellshock.yml) | HIGH | linux | keywords |
| [Suspicious ASPX File Drop by Exchange](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml) | HIGH | windows / file_event | all of selection* |
| [Suspicious Child Process Of SQL Server](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mssql_susp_child_process.yml) | HIGH | process_creation / windows | selection and not 1 of filter_optional_* |

### T1528 — Steal Application Access Token

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - Koh Default Named Pipe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created/pipe_created_hktl_koh_default_pipe.yml) | CRITICAL | windows / pipe_created | selection |
| [Anomalous Token](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml) | HIGH | azure / riskdetection | selection |
| [Anonymous IP Address](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_address.yml) | HIGH | azure / riskdetection | selection |
| [App Granted Microsoft Permissions](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_permissions_msft.yml) | HIGH | azure / auditlogs | selection |
| [Application URI Configuration Changes](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_uri_modifications.yml) | HIGH | azure / auditlogs | selection |
| [Delegated Permissions Granted For All Users](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_delegated_permissions_all_users.yml) | HIGH | azure / auditlogs | selection |
| [Primary Refresh Token Access Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/identity_protection/azure_identity_protection_prt_access.yml) | HIGH | azure / riskdetection | selection |
| [Renamed BrowserCore.EXE Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_browsercore.yml) | HIGH | process_creation / windows | selection and not 1 of filter_* |
| [Suspicious Teams Application Related ObjectAcess Event](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_teams_suspicious_objectaccess.yml) | HIGH | windows / security | selection and not filter |
| [End User Consent Blocked](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/audit_logs/azure_app_end_user_consent_blocked.yml) | MEDIUM | azure / auditlogs | selection |

### T1542.003 — Bootkit

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bcdedit_susp_execution.yml) | MEDIUM | process_creation / windows | all of selection_* |

### T1546.015 — Component Object Model Hijacking

**Sigma Rules (8)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [COM Object Hijacking Via Modification Of Default System CLSID Default Value](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_com_hijacking_builtin.yml) | HIGH | registry_set / windows | all of selection_target_* and 1 of selection_susp_location_* |
| [Potential PSFactoryBuffer COM Hijacking](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_comhijack_psfactorybuffer.yml) | HIGH | registry_set / windows | selection and not filter_main |
| [Rundll32 Registered COM Objects](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_registered_com_objects.yml) | HIGH | process_creation / windows | all of selection_* |
| [COM Hijacking via TreatAs](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_treatas_persistence.yml) | MEDIUM | registry_set / windows | selection and not 1 of filter_* |
| [Potential COM Object Hijacking Via TreatAs Subkey - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_com_key_linking.yml) | MEDIUM | registry_set / windows | selection and not 1 of filter_main_* |
| [Potential Persistence Using DebugPath](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_appx_debugger.yml) | MEDIUM | registry_set / windows | 1 of selection_* |
| [Potential Persistence Via Scrobj.dll COM Hijacking](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_persistence_scrobj_dll.yml) | MEDIUM | registry_set / windows | selection |
| [Suspicious GetTypeFromCLSID ShellExecute](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_gettypefromclsid.yml) | MEDIUM | windows / ps_script | selection |

### T1547.001 — Registry Run Keys / Startup Folder

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [File Creation In Suspicious Directory By Msdt.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_msdt_susp_directories.yml) | HIGH | file_event / windows | selection |
| [Modify User Shell Folders Startup Value](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml) | HIGH | windows / registry_set | selection and not 1 of filter_main_* |
| [Narrator's Feedback-Hub Persistence](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_narrator_feedback_persistance.yml) | HIGH | registry_event / windows | 1 of selection* |
| [New RUN Key Pointing to Suspicious Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_run_key_img_folder.yml) | HIGH | registry_set / windows | selection_target and (selection_suspicious_paths_1 or (all of selection_suspi... |
| [Potential Startup Shortcut Persistence Via PowerShell.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_powershell_startup_shortcuts.yml) | HIGH | windows / file_event | selection |
| [Registry Persistence via Explorer Run Key](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml) | HIGH | registry_set / windows | selection |
| [Suspicious Autorun Registry Modified via WMI](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_autorun_registry_modified_via_wmic.yml) | HIGH | process_creation / windows | all of selection_execution_* and (selection_suspicious_paths_1 or (all of sel... |
| [Suspicious Run Key from Download](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml) | HIGH | registry_event / windows | selection |
| [Suspicious Startup Folder Persistence](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml) | HIGH | windows / file_event | selection |
| [User Shell Folders Registry Modification via CommandLine](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_user_shell_folders_registry_modification.yml) | HIGH | process_creation / windows | all of selection_* |

### T1550.001 — Application Access Token

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [AWS Console GetSigninToken Potential Abuse](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_console_getsignintoken.yml) | MEDIUM | aws / cloudtrail | selection and not 1 of filter_main_* |
| [AWS Suspicious SAML Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_susp_saml_activity.yml) | MEDIUM | aws / cloudtrail | 1 of selection_* |
| [AWS STS AssumeRole Misuse](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_sts_assumerole_misuse.yml) | LOW | aws / cloudtrail | selection |
| [AWS STS GetSessionToken Misuse](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml) | LOW | aws / cloudtrail | selection |

### T1550.002 — Pass the Hash

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Hacktool Ruler](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_alert_ruler.yml) | HIGH | windows / security | (1 of selection*) |
| [Successful Overpass the Hash Attempt](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml) | HIGH | windows / security | selection |
| [NTLMv1 Logon Between Client and Server](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/lsasrv/win_system_lsasrv_ntlmv1.yml) | MEDIUM | windows / system | selection |
| [Pass the Hash Activity 2](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml) | MEDIUM | windows / security | 1 of selection_* and not filter |
| [NTLM Logon](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ntlm/win_susp_ntlm_auth.yml) | LOW | windows / ntlm | selection |

### T1559.002 — Dynamic Data Exchange

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Enable Microsoft Dynamic Data Exchange](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_office_enable_dde.yml) | MEDIUM | registry_set / windows | 1 of selection_* |

### T1560 — Archive Collected Data

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Compressed File Creation Via Tar.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_tar_compression.yml) | LOW | windows / process_creation | all of selection_* |
| [Compressed File Extraction Via Tar.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_tar_extraction.yml) | LOW | windows / process_creation | all of selection_* |

### T1560.001 — Archive via Utility

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Rar Usage with Password and Compression Level](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rar_compression_with_password.yml) | HIGH | process_creation / windows | selection_password and selection_other |
| [Suspicious Manipulation Of Default Accounts Via Net.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_net_user_default_accounts_manipulation.yml) | HIGH | process_creation / windows | all of selection_* and not filter |
| [7Zip Compressing Dump Files](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Compress Data and Lock With Password for Exfiltration With 7-ZIP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_7zip_password_compression.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Compress Data and Lock With Password for Exfiltration With WINZIP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_winzip_password_compression.yml) | MEDIUM | process_creation / windows | all of selection* |
| [Disk Image Mounting Via Hdiutil - MacOS](https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml) | MEDIUM | macos / process_creation | selection |
| [WinRAR Execution in Non-Standard Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_winrar_uncommon_folder_execution.yml) | MEDIUM | process_creation / windows | selection and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Winrar Compressing Dump Files](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_winrar_exfil_dmp_files.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Cisco Stage Data](https://github.com/SigmaHQ/sigma/blob/master/rules/network/cisco/aaa/cisco_cli_moving_data.yml) | LOW | cisco / aaa | keywords |
| [Compressed File Creation Via Tar.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_tar_compression.yml) | LOW | windows / process_creation | all of selection_* |

### T1564.001 — Hidden Files and Directories

**Sigma Rules (7)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PowerShell Logging Disabled Via Registry Key Tampering](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.yml) | HIGH | registry_set / windows | selection |
| [Registry Persistence via Service in Safe Mode](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml) | HIGH | registry_set / windows | selection and not 1 of filter_optional_* |
| [Set Suspicious Files as System Files Using Attrib.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_attrib_system_susp_paths.yml) | HIGH | process_creation / windows | all of selection* and not 1 of filter_optional_* |
| [Displaying Hidden Files Feature Disabled](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_hide_file.yml) | MEDIUM | registry_set / windows | selection |
| [Hiding Files with Attrib.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml) | MEDIUM | process_creation / windows | all of selection_* and not 1 of filter_main_* and not 1 of filter_optional_* |
| [Use Icacls to Hide File to Everyone](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_icacls_deny.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Hidden Files and Directories](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/execve/lnx_auditd_hidden_files_directories.yml) | LOW | linux / auditd | all of selection_* |

### T1564.003 — Hidden Window

**Sigma Rules (8)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [File Download with Headless Browser](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_file_download.yml) | HIGH | process_creation / windows | selection and not 1 of filter_optional_* |
| [HackTool - Covenant PowerShell Launcher](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_covenant.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [Potential Data Stealing Via Chromium Headless Debugging](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging.yml) | HIGH | process_creation / windows | selection |
| [Cmd Launched with Hidden Start Flags to Suspicious Targets](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_launched_with_hidden_start_flag.yml) | MEDIUM | process_creation / windows | all of selection_cmd_* and 1 of selection_cli_* |
| [PUA - AdvancedRun Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_advancedrun.yml) | MEDIUM | windows / process_creation | selection |
| [Powershell Executed From Headless ConHost Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_conhost_headless_powershell.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Suspicious PowerShell WindowStyle Option](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_windowstyle.yml) | MEDIUM | windows / ps_script | selection and not filter |
| [Browser Execution In Headless Mode](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_exec.yml) | LOW | process_creation / windows | selection |

### T1566.001 — Spearphishing Attachment

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HTML Help HH.EXE Suspicious Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml) | HIGH | process_creation / windows | selection |
| [ISO File Created Within Temp Folders](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_iso_file_mount.yml) | HIGH | file_event / windows | 1 of selection* |
| [Office Macro File Creation From Suspicious Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_office_macro_files_from_susp_process.yml) | HIGH | file_event / windows | all of selection_* |
| [Password Protected ZIP File Opened (Email Attachment)](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml) | HIGH | windows / security | selection |
| [Suspicious Double Extension File Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_double_extension.yml) | HIGH | process_creation / windows | selection |
| [Suspicious Execution From Outlook Temporary Folder](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_outlook_execution_from_temp.yml) | HIGH | process_creation / windows | selection |
| [Suspicious File Created in Outlook Temporary Directory](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_office_outlook_susp_file_creation_in_temp_dir.yml) | HIGH | windows / file_event | all of selection_* |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious HWP Sub Processes](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hwp_exploits.yml) | HIGH | process_creation / windows | selection |
| [Suspicious Microsoft OneNote Child Process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_onenote_susp_child_processes.yml) | HIGH | process_creation / windows | selection_parent and 1 of selection_opt_* and not 1 of filter_* |

### T1567 — Exfiltration Over Web Service

**Sigma Rules (10)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Communication To Ngrok Tunneling Service - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/network_connection/net_connection_lnx_ngrok_tunnel.yml) | HIGH | linux / network_connection | selection |
| [Communication To Ngrok Tunneling Service Initiated](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml) | HIGH | network_connection / windows | selection |
| [Monero Crypto Coin Mining Pool Lookup](https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml) | HIGH | dns | selection |
| [Process Initiated Network Connection To Ngrok Domain](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_ngrok.yml) | HIGH | network_connection / windows | selection |
| [Arbitrary File Download Via ConfigSecurityPolicy.EXE](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_configsecuritypolicy_download_file.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [LOLBAS Data Exfiltration by DataSvcUtil.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_data_exfiltration_by_using_datasvcutil.yml) | MEDIUM | process_creation / windows | all of selection* |
| [Network Connection Initiated To BTunnels Domains](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_btunnels.yml) | MEDIUM | network_connection / windows | selection |
| [Network Connection Initiated To Cloudflared Tunnels Domains](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_cloudflared_communication.yml) | MEDIUM | network_connection / windows | selection |
| [Network Connection Initiated To Visual Studio Code Tunnels Domain](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection/net_connection_win_domain_vscode_tunnel_connection.yml) | MEDIUM | network_connection / windows | selection |
| [Suspicious Curl File Upload - Linux](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_curl_fileupload.yml) | MEDIUM | process_creation / linux | all of selection_* and not 1 of filter_optional_* |

### T1588.002 — Tool

**Sigma Rules (9)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Hacktool Execution - Imphash](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml) | CRITICAL | process_creation / windows | selection |
| [Hacktool Execution - PE Metadata](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_execution_via_pe_metadata.yml) | HIGH | process_creation / windows | selection |
| [Renamed SysInternals DebugView Execution](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.yml) | HIGH | process_creation / windows | selection and not filter |
| [Suspicious Execution Of Renamed Sysinternals Tools - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_pua_sysinternals_renamed_execution_via_eula.yml) | HIGH | windows / registry_set | selection and not filter |
| [Usage of Renamed Sysinternals Tools - RegistrySet](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.yml) | HIGH | windows / registry_set | selection and not 1 of filter_main_* and not 1 of filter_optional_* |
| [PUA - Sysinternals Tools Execution - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_pua_sysinternals_susp_execution_via_eula.yml) | MEDIUM | windows / registry_set | selection |
| [Suspicious Keyboard Layout Load](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.yml) | MEDIUM | registry_set / windows | selection_registry |
| [PUA - Sysinternal Tool Execution - Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_pua_sysinternals_execution_via_eula.yml) | LOW | windows / registry_set | selection |
| [Potential Execution of Sysinternals Tools](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_eula_accepted.yml) | LOW | process_creation / windows | selection |

### T1595.002 — Vulnerability Scanning

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [DNS Query to External Service Interaction Domains](https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_external_service_interaction_domains.yml) | HIGH | dns | selection and not 1 of filter_main_* |

## Indicators of Compromise (OTX: 66)

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
| url | http://142.0.68.2/test-update-16-8852418/temp727612430/checkUpdate89732468.php |  |  |  |  |
| url | http://142.0.68.2/test-update-17-8752417/temp827612480/checkUpdate79832467.php |  |  |  |  |
| url | http://185.25.50.93/syshelp/kd8812u/protocol.php |  |  |  |  |
| url | http://185.25.50.93/tech99-04/litelib1/setwsdv4.php |  |  |  |  |
| url | http://185.25.50.93/techicalBS391-two/supptech18i/suppid.php |  |  |  |  |
| url | http://185.25.51.114/get-help-software/get-app-c/error-code-lookup.php |  |  |  |  |
| url | http://185.25.51.164/srv_upd_dest_two/destBB/en.php |  |  |  |  |
| url | http://185.25.51.198/get-data/searchId/get.php |  |  |  |  |
| url | http://185.25.51.198/stream-upd-service-two/definition/event.php |  |  |  |  |
| url | http://185.77.129.152/wWpYdSMRulkdp/arpz/MsKZrpUfe.php |  |  |  |  |

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

**ArguePatch** (malware)

During a campaign against a Ukrainian energy provider, a new loader of a new version of CaddyWiper called "ArguePatch" was observed by ESET researchers. ArguePatch is a modified version of Hex-Ray's Remote Debugger Server (win32_remote.exe).
ArguePatch expects a decryption key and the file of the CaddyWiper shellcode as command line parameters.

**DriveOcean** (malware)

Communicates via Google Drive.

**Unidentified 114 (APT28 InfoStealer)** (malware)

According to Trend Micro, this is a small information stealer written in .NET, that pushes its loot to a benign file sharing service and does not have a direct C&C callback.

**X-Tunnel (.NET)** (malware)

This is a rewrite of win.xtunnel using the .NET framework that surfaced late 2017.

**Mocky LNK** (malware)

LNK files used to lure and orchestrate execution of various scripts, interacting with the Mocky API service.

**SpyPress** (malware)

According to ESET, SpyPress is a set of Javascript payloads targeting different webmail frameworks (HORDE, MDAEMON, ROUNDCUBE, ZIMBRA). The observed payloads have common characteristics. All are similarly obfuscated, with variable and function names replaced with random-looking strings. Furthermore, strings used by the code, such as webmail and C&C server URLs, are also obfuscated and contained in…

**LAMEHUG** (malware)

According to CERT-UA, LAMEHUG uses an LLM (Qwen) to dynamically generate commands to gather basic information about a computer and recursively exfiltrate Office documents from a set of folders, to be uploaded either by SFTP or HTTP POST requests.

**CaddyWiper** (malware)

CaddyWiper is another destructive malware believed to be deployed to target Ukraine.

CaddyWiper wipes all files under C:\Users and all also all files under available drives from D: to Z: by overwriting the data with NULL value. If the target file is greater than 0xA00000 bytes in size (10MB), it will only wipe the first 0xA00000 bytes.

It also wipes disk partitions from \\.\PHYSICALDRIVE9 to…

**Graphite** (malware)

Trellix describes Graphite as a malware using the Microsoft Graph API and OneDrive for C&C. It was found being deployed in-memory only and served as a downloader for Empire.

**PocoDown** (malware)

uses POCO C++ cross-platform library, Xor-based string obfuscation, SSL library code and string overlap with Xtunnel, infrastructure overlap with X-Agent, probably in use since mid-2018


## Campaigns

### APT28 Nearest Neighbor Campaign

APT28 Nearest Neighbor Campaign was conducted by APT28 from early February 2022 to November 2024 against organizations and individuals with expertise on Ukraine. APT28 primarily leveraged living-off-the-land techniques, while leveraging the zero-day exploitation of CVE-2022-38028. Notably, APT28 leveraged Wi-Fi networks in close proximity to the intended target to gain initial access to the victim environment. By daisy-chaining multiple compromised organizations nearby the intended target, APT28 discovered dual-homed systems (with both a wired and wireless network connection) to enable Wi-Fi and use compromised credentials to connect to the victim network.(Citation: Nearest Neighbor Volexity)

