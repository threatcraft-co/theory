# Threat Actor Dossier: Lazarus Group
> MITRE ATT&CK Group ID: **G0032**
> Generated: 2026-04-01 05:38 UTC  |  Sources: alienvault_otx, mitre_attack, malpedia

## Overview

| Field | Value |
|---|---|
| **Origin** | North Korea |
| **First Seen** | 2009 |
| **Motivations** | espionage, financial crime |
| **Also Known As** | Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet, Operation DarkSeoul, Dark Seoul, Hastati Group, Andariel, Unit 121, Bureau 121, NewRomanic Cyber Army Team, Bluenoroff, Subgroup: Bluenoroff, Group 77, Operation Troy, Operation GhostSecret, Operation AppleJeus, APT38, APT 38, Stardust Chollima, Whois Hacking Team, Appleworm, APT-C-26, NICKEL GLADSTONE, COVELLITE, ATK3, G0032, ATK117, G0082, Citrine Sleet, DEV-0139, DEV-1222, Sapphire Sleet, COPERNICIUM, TA404, Lazarus group, BeagleBoyz, Moonstone Sleet, Black Artemis, Lazarus, Genie Spider |

## TTP Table

| Technique ID | Tactic | Name | Confidence |
|---|---|---|---|
| T1001.003 | Command and Control | Protocol or Service Impersonation | MEDIUM |
| T1005 | Collection | Data from Local System | MEDIUM |
| T1008 | Command and Control | Fallback Channels | MEDIUM |
| T1010 | Discovery | Application Window Discovery | MEDIUM |
| T1012 | Discovery | Query Registry | MEDIUM |
| T1016 | Discovery | System Network Configuration Discovery | MEDIUM |
| T1021.001 | Lateral Movement | Remote Desktop Protocol | MEDIUM |
| T1021.002 | Lateral Movement | SMB/Windows Admin Shares | MEDIUM |
| T1021.004 | Lateral Movement | SSH | MEDIUM |
| T1027.007 | Defense Evasion | Dynamic API Resolution | MEDIUM |
| T1027.009 | Defense Evasion | Embedded Payloads | MEDIUM |
| T1027.013 | Defense Evasion | Encrypted/Encoded File | MEDIUM |
| T1033 | Discovery | System Owner/User Discovery | MEDIUM |
| T1036.003 | Defense Evasion | Rename Legitimate Utilities | MEDIUM |
| T1036.004 | Defense Evasion | Masquerade Task or Service | MEDIUM |
| T1036.005 | Defense Evasion | Match Legitimate Resource Name or Location | MEDIUM |
| T1041 | Exfiltration | Exfiltration Over C2 Channel | MEDIUM |
| T1046 | Discovery | Network Service Discovery | MEDIUM |
| T1047 | Execution | Windows Management Instrumentation | MEDIUM |
| T1048.003 | Exfiltration | Exfiltration Over Unencrypted Non-C2 Protocol | MEDIUM |
| T1049 | Discovery | System Network Connections Discovery | MEDIUM |
| T1053.005 | Execution | Scheduled Task | MEDIUM |
| T1055.001 | Defense Evasion | Dynamic-link Library Injection | MEDIUM |
| T1056.001 | Collection | Keylogging | MEDIUM |
| T1057 | Discovery | Process Discovery | MEDIUM |
| T1059.001 | Execution | PowerShell | MEDIUM |
| T1059.003 | Execution | Windows Command Shell | MEDIUM |
| T1059.005 | Execution | Visual Basic | MEDIUM |
| T1070 | Defense Evasion | Indicator Removal | MEDIUM |
| T1070.003 | Defense Evasion | Clear Command History | MEDIUM |
| T1070.004 | Defense Evasion | File Deletion | MEDIUM |
| T1070.006 | Defense Evasion | Timestomp | MEDIUM |
| T1071.001 | Command and Control | Web Protocols | MEDIUM |
| T1074.001 | Collection | Local Data Staging | MEDIUM |
| T1078 | Defense Evasion | Valid Accounts | MEDIUM |
| T1082 | Discovery | System Information Discovery | MEDIUM |
| T1083 | Discovery | File and Directory Discovery | MEDIUM |
| T1090.001 | Command and Control | Internal Proxy | MEDIUM |
| T1090.002 | Command and Control | External Proxy | MEDIUM |
| T1098 | Persistence | Account Manipulation | MEDIUM |
| T1102.002 | Command and Control | Bidirectional Communication | MEDIUM |
| T1104 | Command and Control | Multi-Stage Channels | MEDIUM |
| T1105 | Command and Control | Ingress Tool Transfer | MEDIUM |
| T1106 | Execution | Native API | MEDIUM |
| T1110.003 | Credential Access | Password Spraying | MEDIUM |
| T1124 | Discovery | System Time Discovery | MEDIUM |
| T1132.001 | Command and Control | Standard Encoding | MEDIUM |
| T1134.002 | Defense Evasion | Create Process with Token | MEDIUM |
| T1140 | Defense Evasion | Deobfuscate/Decode Files or Information | MEDIUM |
| T1189 | Initial Access | Drive-by Compromise | MEDIUM |
| T1202 | Defense Evasion | Indirect Command Execution | MEDIUM |
| T1203 | Execution | Exploitation for Client Execution | MEDIUM |
| T1204.002 | Execution | Malicious File | MEDIUM |
| T1218 | Defense Evasion | System Binary Proxy Execution | MEDIUM |
| T1218.005 | Defense Evasion | Mshta | MEDIUM |
| T1218.011 | Defense Evasion | Rundll32 | MEDIUM |
| T1485 | Impact | Data Destruction | MEDIUM |
| T1489 | Impact | Service Stop | MEDIUM |
| T1491.001 | Impact | Internal Defacement | MEDIUM |
| T1529 | Impact | System Shutdown/Reboot | MEDIUM |
| T1542.003 | Persistence | Bootkit | MEDIUM |
| T1543.003 | Persistence | Windows Service | MEDIUM |
| T1547.001 | Persistence | Registry Run Keys / Startup Folder | MEDIUM |
| T1547.009 | Persistence | Shortcut Modification | MEDIUM |
| T1553.002 | Defense Evasion | Code Signing | MEDIUM |
| T1557.001 | Credential Access | LLMNR/NBT-NS Poisoning and SMB Relay | MEDIUM |
| T1560 | Collection | Archive Collected Data | MEDIUM |
| T1560.002 | Collection | Archive via Library | MEDIUM |
| T1560.003 | Collection | Archive via Custom Method | MEDIUM |
| T1561.001 | Impact | Disk Content Wipe | MEDIUM |
| T1561.002 | Impact | Disk Structure Wipe | MEDIUM |
| T1562.001 | Defense Evasion | Disable or Modify Tools | MEDIUM |
| T1562.004 | Defense Evasion | Disable or Modify System Firewall | MEDIUM |
| T1564.001 | Defense Evasion | Hidden Files and Directories | MEDIUM |
| T1566.001 | Initial Access | Spearphishing Attachment | MEDIUM |
| T1566.002 | Initial Access | Spearphishing Link | MEDIUM |
| T1566.003 | Initial Access | Spearphishing via Service | MEDIUM |
| T1571 | Command and Control | Non-Standard Port | MEDIUM |
| T1573.001 | Command and Control | Symmetric Cryptography | MEDIUM |
| T1574.001 | Persistence | DLL | MEDIUM |
| T1574.013 | Persistence | KernelCallbackTable | MEDIUM |
| T1583.001 | Resource Development | Domains | MEDIUM |
| T1583.006 | Resource Development | Web Services | MEDIUM |
| T1584.004 | Resource Development | Server | MEDIUM |
| T1585.001 | Resource Development | Social Media Accounts | MEDIUM |
| T1585.002 | Resource Development | Email Accounts | MEDIUM |
| T1587.001 | Resource Development | Malware | MEDIUM |
| T1588.002 | Resource Development | Tool | MEDIUM |
| T1588.004 | Resource Development | Digital Certificates | MEDIUM |
| T1589.002 | Reconnaissance | Email Addresses | MEDIUM |
| T1591 | Reconnaissance | Gather Victim Org Information | MEDIUM |
| T1620 | Defense Evasion | Reflective Code Loading | MEDIUM |
| T1680 | Discovery | Local Storage Discovery | MEDIUM |

## Detection Opportunities

### T1001.003 — Protocol or Service Impersonation

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious LDAP-Attributes Used](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_susp_ldap_dataexchange.yml) | HIGH | security / windows | selection exclusion filter |
| [ADSI-Cache File Creation By Uncommon Tool](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_adsi_cache_creation_by_uncommon_tool.yml) | MEDIUM | file_event / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1005 — Data from Local System

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Collect Data](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_collect_data.yml) | LOW | aaa / cisco | keywords |
| [OpenCanary - SMB File Open Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/opencanary/opencanary_smb_file_open.yml) | HIGH | application / opencanary | selection exclusion filter |
| [AWS EC2 VM Export Failure](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/aws/cloudtrail/aws_ec2_vm_export_failure.yml) | LOW | cloudtrail / aws | selection exclusion filter excluding 1 of exclusion filter* |
| [VeeamBackup Database Credentials Dump Via Sqlcmd.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_sqlcmd_veeam_dump.yml) | HIGH | process_creation / windows | all of selection_* |
| [Script Interpreter Spawning Credential Scanner - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml) | HIGH | process_creation / linux | all of selection_* |

### T1008 — Fallback Channels

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [New Outlook Macro Created](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_office_outlook_macro_creation.yml) | MEDIUM | file_event / windows | selection exclusion filter |
| [Suspicious Outlook Macro Created](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_office_outlook_susp_macro_creation.yml) | HIGH | file_event / windows | selection exclusion filter excluding exclusion filter |
| [Outlook Macro Execution Without Warning Setting Enabled](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_office_outlook_enable_macro_execution.yml) | HIGH | registry_set / windows | selection exclusion filter |
| [Potential Persistence Via Outlook LoadMacroProviderOnBoot Setting](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_office_outlook_enable_load_macro_provider_on_boot.yml) | HIGH | registry_set / windows | selection exclusion filter |

### T1010 — Application Window Discovery

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [SCM Database Handle Failure](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_scm_database_handle_failure.yml) | MEDIUM | security / windows | selection exclusion filter excluding exclusion filter |

### T1012 — Query Registry

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [HackTool - PCHunter Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_pchunter.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [Registry Manipulation via WMI Stdregprov](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_wmic_stdregprov_reg_modification.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [SysKey Registry Keys Access](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_syskey_registry_access.yml) | HIGH | security / windows | selection exclusion filter |
| [SAM Registry Hive Handle Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml) | HIGH | security / windows | selection exclusion filter |
| [Azure AD Health Monitoring Agent Registry Keys Access](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_aadhealth_mon_agent_regkey_access.yml) | MEDIUM | security / windows | selection exclusion filter excluding exclusion filter |

### T1016 — System Network Configuration Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [OpenCanary - SNMP OID Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/opencanary/opencanary_snmp_cmd.yml) | HIGH | application / opencanary | selection exclusion filter |
| [Potential Recon Activity Via Nltest.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_nltest_recon.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Nltest.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_nltest_execution.yml) | LOW | process_creation / windows | selection exclusion filter |
| [Suspicious Network Command](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_susp_network_command.yml) | LOW | process_creation / windows | selection exclusion filter |

### T1021.001 — Remote Desktop Protocol

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Publicly Accessible RDP Service](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_rdp_public_listener.yml) | HIGH | rdp / zeek | not selection exclusion filter # excluding approved_rdp |
| [RDP over Reverse SSH Tunnel WFP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml) | HIGH | security / windows | selection exclusion filter and ( sourceRDP or destinationRDP ) excluding 1 of exclusion filter* |
| [Port Forwarding Activity Via SSH.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_ssh_port_forward.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [RDP Over Reverse SSH Tunnel](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml) | HIGH | network_connection / windows | all of selection_* |
| [Suspicious RDP Redirect Using TSCON](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_tscon_rdp_redirect.yml) | HIGH | process_creation / windows | selection exclusion filter |

### T1021.002 — SMB/Windows Admin Shares

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious PsExec Execution - Zeek](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml) | HIGH | smb_files / zeek | selection exclusion filter excluding exclusion filter |
| [Copy From Or To Admin Share Or Sysvol Folder](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml) | MEDIUM | process_creation / windows | selection_target and (selection_other_tools or all of selection_cmd_* or all of selection_pwsh_*) |
| [CobaltStrike Service Installations - System](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/system/service_control_manager/win_system_cobaltstrike_service_installs.yml) | CRITICAL | system / windows | selection_id and (selection1 or selection2 or selection3 or selection4) |
| [Metasploit Or Impacket Service Installation Via SMB PsExec](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml) | HIGH | security / windows | selection exclusion filter excluding exclusion filter |
| [PUA - RemCom Default Named Pipe](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/pipe_created/pipe_created_pua_remcom_default_pipe.yml) | MEDIUM | pipe_created / windows | selection exclusion filter |

### T1021.004 — SSH

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Port Forwarding Activity Via SSH.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_ssh_port_forward.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [OpenEDR Spawning Command Shell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_comodo_ssh_shellhost_cmd_spawn.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Bitbucket Global SSH Settings Changed](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/bitbucket/audit/bitbucket_audit_global_ssh_settings_change_detected.yml) | MEDIUM | audit / bitbucket | selection exclusion filter |
| [Bitbucket User Login Failure Via SSH](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/bitbucket/audit/bitbucket_audit_user_login_failure_via_ssh_detected.yml) | MEDIUM | audit / bitbucket | selection exclusion filter |
| [OpenSSH Server Listening On Socket](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/openssh/win_sshd_openssh_server_listening_on_socket.yml) | MEDIUM | openssh / windows | selection exclusion filter |

### T1027.009 — Embedded Payloads

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Powershell Token Obfuscation - Process Creation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_token_obfuscation.yml) | HIGH | process_creation / windows | selection exclusion filter excluding 1 of filter_main_* |

### T1033 — System Owner/User Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [System Owner or User Discovery - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_user_discovery.yml) | LOW | auditd / linux | selection exclusion filter |
| [Local Accounts Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml) | LOW | process_creation / windows | (selection_cmd excluding filter_cmd) or (selection_net excluding filter_net) or 1 of selection_other_* |
| [Computer Discovery And Export Via Get-ADComputer Cmdlet](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_computer_discovery_get_adcomputer.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Whoami.EXE Execution With Output Option](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_whoami_output.yml) | MEDIUM | process_creation / windows | all of selection_main_* or selection_special |

### T1036.003 — Rename Legitimate Utilities

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Masquerading as Linux Crond Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_masquerading_crond.yml) | MEDIUM | auditd / linux | selection exclusion filter |
| [File Download Via Bitsadmin](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml) | MEDIUM | process_creation / windows | selection_img and (selection_cmd or all of selection_cli_*) |
| [File With Suspicious Extension Downloaded Via Bitsadmin](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml) | HIGH | process_creation / windows | all of selection_* |
| [Potential PendingFileRenameOperations Tampering](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_susp_pendingfilerenameoperations.yml) | MEDIUM | registry_set / windows | selection_main and 1 of selection_susp_* |
| [Suspicious Download From File-Sharing Website Via Bitsadmin](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_bitsadmin_download_file_sharing_domains.yml) | HIGH | process_creation / windows | all of selection_* |

### T1036.004 — Masquerade Task or Service

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Scheduled Task Creation Masquerading as System Processes](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_schtasks_system_process.yml) | HIGH | process_creation / windows | all of selection_* |

### T1036.005 — Match Legitimate Resource Name or Location

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection exclusion filter excluding exclusion filter |
| [Unsigned .node File Loaded](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_dll_unsigned_node_load.yml) | MEDIUM | image_load / windows | all of selection_* excluding 1 of filter_optional_* |
| [Creation Of Pod In System Namespace](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/kubernetes/audit/kubernetes_audit_pod_in_system_namespace.yml) | MEDIUM | application / kubernetes | selection exclusion filter |
| [Suspicious Files in Default GPO Folder](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_susp_default_gpo_dir_write.yml) | MEDIUM | file_event / windows | selection exclusion filter |
| [Potential MsiExec Masquerading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml) | HIGH | process_creation / windows | selection exclusion filter excluding exclusion filter |

### T1041 — Exfiltration Over C2 Channel

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [OpenCanary - TFTP Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/opencanary/opencanary_tftp_request.yml) | HIGH | application / opencanary | selection exclusion filter |
| [Network Communication Initiated To Portmap.IO Domain](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_domain_portmap.yml) | MEDIUM | network_connection / windows | selection exclusion filter |

### T1046 — Network Service Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PUA - SoftPerfect Netscan Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_netscan.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [HackTool - WinPwn Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_winpwn.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [HackTool - WinPwn Execution - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_hktl_winpwn.yml) | HIGH | ps_script / windows | selection exclusion filter |
| [Linux Network Service Scanning - Auditd](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/syscall/lnx_auditd_network_service_scanning.yml) | LOW | auditd / linux | selection exclusion filter |
| [PUA - NimScan Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_nimscan.yml) | MEDIUM | process_creation / windows | selection exclusion filter |

### T1047 — Windows Management Instrumentation

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [MITRE BZAR Indicators for Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_dce_rpc_mitre_bzar_execution.yml) | MEDIUM | dce_rpc / zeek | 1 of op* |
| [Remote DCOM/WMI Lateral Movement](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/rpc_firewall/rpc_firewall_remote_dcom_or_wmi.yml) | HIGH | application / rpc_firewall | selection exclusion filter |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious WmiPrvSE Child Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_wmiprvse_susp_child_processes.yml) | HIGH | process_creation / windows | selection_parent and 1 of selection_children_* excluding 1 of filter_main_* |
| [Registry Manipulation via WMI Stdregprov](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_wmic_stdregprov_reg_modification.yml) | MEDIUM | process_creation / windows | all of selection_* |

### T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious DNS Query with B64 Encoded String](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/dns/net_dns_susp_b64_queries.yml) | MEDIUM | dns | selection exclusion filter |
| [WebDav Put Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_http_webdav_put_request.yml) | LOW | http / zeek | selection exclusion filter excluding exclusion filter |
| [Data Exfiltration with Wget](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_data_exfil_wget.yml) | MEDIUM | auditd / linux | selection exclusion filter |
| [WebDav Client Execution Via Rundll32.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_execution.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Suspicious Outbound SMTP Connections](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_susp_outbound_smtp_connections.yml) | MEDIUM | network_connection / windows | selection exclusion filter excluding 1 of filter_* |

### T1049 — System Network Connections Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [Use Get-NetTCPConnection - PowerShell Module](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml) | LOW | ps_module / windows | selection exclusion filter |
| [System Network Connections Discovery - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml) | LOW | process_creation / linux | selection exclusion filter excluding 1 of filter_* |
| [System Network Connections Discovery - MacOs](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_system_network_connections_discovery.yml) | INFORMATIONAL | process_creation / macos | selection exclusion filter |
| [HackTool - SharpView Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_sharpview.yml) | HIGH | process_creation / windows | selection exclusion filter |

### T1053.005 — Scheduled Task

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Persistence and Execution at Scale via GPO Scheduled Task](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml) | HIGH | security / windows | 1 of selection_* |
| [HackTool - Default PowerSploit/Empire Scheduled Task Creation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_powersploit_empire_default_schtasks.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Potential Persistence Via Microsoft Compatibility Appraiser](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_schtasks_persistence_windows_telemetry.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Suspicious Scheduled Task Creation via Masqueraded XML File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_schtasks_schedule_via_masqueraded_xml_file.yml) | MEDIUM | process_creation / windows | all of selection_* excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via Schtasks.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_schtasks_env_folder.yml) | MEDIUM | process_creation / windows | ( all of selection_1_* or all of selection_2_* ) excluding 1 of filter_optional_* |

### T1055.001 — Dynamic-link Library Injection

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential DLL Injection Or Execution Using Tracker.exe](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_lolbin_tracker.yml) | MEDIUM | process_creation / windows | all of selection_* excluding 1 of filter_* |
| [Renamed ZOHO Dctask64 Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_renamed_dctask64.yml) | HIGH | process_creation / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Renamed Mavinject.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_renamed_mavinject.yml) | HIGH | process_creation / windows | selection exclusion filter excluding exclusion filter |
| [HackTool - Potential CobaltStrike Process Injection](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cobaltstrike.yml) | HIGH | create_remote_thread / windows | selection exclusion filter |
| [Mavinject Inject DLL Into Running Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_lolbin_mavinject_process_injection.yml) | HIGH | process_creation / windows | selection exclusion filter excluding exclusion filter |

### T1056.001 — Keylogging

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Linux Keylogging with Pam.d](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml) | HIGH | auditd / linux | 1 of selection_* |
| [Powershell Keylogging](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_keylogging.yml) | MEDIUM | ps_script / windows | 1 of selection_* |
| [Potential Keylogger Activity](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_keylogger_activity.yml) | MEDIUM | ps_script / windows | selection exclusion filter |

### T1057 — Process Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [Suspicious Process Discovery With Get-Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml) | LOW | ps_script / windows | selection exclusion filter |
| [HackTool - PCHunter Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_pchunter.yml) | HIGH | process_creation / windows | 1 of selection_* |
| [System Info Discovery via Sysinfo Syscall](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/syscall/lnx_auditd_susp_discovery_sysinfo_syscall.yml) | LOW | auditd / linux | selection exclusion filter excluding 1 of filter_optional_* |
| [Recon Command Output Piped To Findstr.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_findstr_recon_pipe_output.yml) | MEDIUM | process_creation / windows | selection exclusion filter excluding 1 of filter_optional_* |

### T1059.001 — PowerShell

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [AWS EC2 Startup Shell Script Change](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml) | HIGH | cloudtrail / aws | selection_source |
| [HackTool - Default PowerSploit/Empire Scheduled Task Creation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_powersploit_empire_default_schtasks.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [HackTool - CrackMapExec Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution.yml) | HIGH | process_creation / windows | 1 of selection_* or all of part_localauth* |
| [Malicious PowerShell Commandlets - PoshModule](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_module/posh_pm_malicious_commandlets.yml) | HIGH | ps_module / windows | selection exclusion filter |
| [Execution of Powershell Script in Public Folder](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_public_folder.yml) | HIGH | process_creation / windows | selection exclusion filter |

### T1059.003 — Windows Command Shell

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [DNS Query by Finger Utility](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/dns_query/dns_query_win_finger.yml) | HIGH | dns_query / windows | selection exclusion filter |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [PUA - AdvancedRun Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_advancedrun.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [HackTool - Koadic Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_koadic.yml) | HIGH | process_creation / windows | all of selection_* |
| [HTML Help HH.EXE Suspicious Child Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml) | HIGH | process_creation / windows | selection exclusion filter |

### T1059.005 — Visual Basic

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious Scripting in a WMI Consumer](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/wmi_event/sysmon_wmi_susp_scripting.yml) | HIGH | wmi_event / windows | selection_destination |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [AppLocker Prevented Application or Script from Running](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml) | MEDIUM | applocker / windows | selection exclusion filter |
| [WScript or CScript Dropper - File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml) | HIGH | file_event / windows | selection exclusion filter |
| [Windows Shell/Scripting Processes Spawning Suspicious Programs](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_susp_program.yml) | HIGH | process_creation / windows | selection exclusion filter excluding 1 of filter_* |

### T1070 — Indicator Removal

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Clear Logs](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_clear_logs.yml) | HIGH | aaa / cisco | keywords |
| [SES Identity Has Been Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/aws/cloudtrail/aws_delete_identity.yml) | MEDIUM | cloudtrail / aws | selection exclusion filter |
| [Cisco File Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_file_deletion.yml) | MEDIUM | aaa / cisco | keywords |
| [Touch Suspicious Service File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml) | MEDIUM | process_creation / linux | selection exclusion filter |
| [Powershell Timestomp](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml) | MEDIUM | ps_script / windows | selection_ioc |

### T1070.003 — Clear Command History

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Clear Logs](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_clear_logs.yml) | HIGH | aaa / cisco | keywords |
| [Linux Command History Tampering](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/builtin/lnx_shell_clear_cmd_history.yml) | HIGH | linux | keywords |
| [RunMRU Registry Key Deletion - Registry](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_delete/registry_delete_runmru.yml) | HIGH | registry_delete / windows | selection exclusion filter |
| [RunMRU Registry Key Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_reg_delete_runmru.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious IO.FileStream](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_iofilestream.yml) | MEDIUM | ps_script / windows | selection exclusion filter |

### T1070.004 — File Deletion

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco File Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_file_deletion.yml) | MEDIUM | aaa / cisco | keywords |
| [File Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_file_deletion.yml) | INFORMATIONAL | process_creation / linux | selection exclusion filter |
| [Prefetch File Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_delete/file_delete_win_delete_prefetch.yml) | HIGH | file_delete / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Directory Removal Via Rmdir](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_cmd_rmdir_execution.yml) | LOW | process_creation / windows | all of selection_* |
| [File Deletion Via Del](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_cmd_del_execution.yml) | LOW | process_creation / windows | all of selection_* |

### T1070.006 — Timestomp

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Touch Suspicious Service File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml) | MEDIUM | process_creation / linux | selection exclusion filter |
| [Powershell Timestomp](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml) | MEDIUM | ps_script / windows | selection_ioc |
| [Unauthorized System Time Modification](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_susp_time_modification.yml) | LOW | security / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [File Time Attribute Change](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_change_file_time_attr.yml) | MEDIUM | process_creation / macos | selection exclusion filter |
| [File Time Attribute Change - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_change_file_time_attr.yml) | MEDIUM | auditd / linux | execve and touch and selection2 |

### T1071.001 — Web Protocols

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PwnDrp Access](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_pwndrop.yml) | CRITICAL | proxy | selection exclusion filter |
| [Telegram API Access](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_telegram_api.yml) | MEDIUM | proxy | selection exclusion filter excluding exclusion filter |
| [DNS Query To Visual Studio Code Tunnels Domain](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/dns_query/dns_query_win_vscode_tunnel_communication.yml) | MEDIUM | dns_query / windows | selection exclusion filter |
| [Change User Agents with WebRequest](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_invoke_webrequest_useragent.yml) | MEDIUM | ps_script / windows | all of selection_* |
| [Malware User Agent](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_ua_malware.yml) | HIGH | proxy | selection exclusion filter |

### T1074.001 — Local Data Staging

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Zip A Folder With PowerShell For Staging In Temp - PowerShell Script](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_zip_compress.yml) | MEDIUM | ps_script / windows | selection exclusion filter |
| [Zip A Folder With PowerShell For Staging In Temp  - PowerShell Module](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_module/posh_pm_susp_zip_compress.yml) | MEDIUM | ps_module / windows | selection exclusion filter |
| [Zip A Folder With PowerShell For Staging In Temp - PowerShell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_classic/posh_pc_susp_zip_compress.yml) | MEDIUM | powershell-classic / windows | selection exclusion filter |
| [Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_zip_compress.yml) | MEDIUM | process_creation / windows | selection exclusion filter |

### T1078 — Valid Accounts

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Temporary Access Pass Added To An Account](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/azure/audit_logs/azure_tap_added.yml) | HIGH | auditlogs / azure | selection exclusion filter |
| [Password Provided In Command Line Of Net.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_net_use_password_plaintext.yml) | MEDIUM | process_creation / windows | all of selection_* excluding 1 of filter_main_* |
| [Cisco BGP Authentication Failures](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/bgp/cisco_bgp_md5_auth_failed.yml) | LOW | bgp / cisco | keywords_bgp_cisco |
| [Atypical Travel](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/azure/identity_protection/azure_identity_protection_atypical_travel.yml) | HIGH | riskdetection / azure | selection exclusion filter |
| [Okta New Admin Console Behaviours](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/identity/okta/okta_new_behaviours_admin_console.yml) | HIGH | okta / okta | all of selection_* |

### T1082 — System Information Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [HackTool - WinPwn Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_winpwn.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [System Information Discovery - Auditd](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/lnx_auditd_system_info_discovery.yml) | LOW | auditd / linux | 1 of selection_* |
| [System Information Discovery Via Sysctl - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_sysctl_discovery.yml) | MEDIUM | process_creation / macos | all of selection_* |
| [Potential Product Class Reconnaissance Via Wmic.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_wmic_recon_product_class.yml) | MEDIUM | process_creation / windows | all of selection_* |

### T1083 — File and Directory Discovery

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [Linux Capabilities Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_capabilities_discovery.yml) | LOW | auditd / linux | selection exclusion filter |
| [PUA - TruffleHog Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_trufflehog.yml) | MEDIUM | process_creation / windows | selection_img or all of selection_cli_* |
| [Capabilities Discovery - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_capa_discovery.yml) | LOW | process_creation / linux | selection exclusion filter |
| [Potential Discovery Activity Using Find - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_susp_find_execution.yml) | MEDIUM | process_creation / linux | selection exclusion filter |

### T1090.001 — Internal Proxy

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PUA - Chisel Tunneling Tool Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_chisel.yml) | HIGH | process_creation / windows | selection_img or all of selection_param* |
| [RDP over Reverse SSH Tunnel WFP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml) | HIGH | security / windows | selection exclusion filter and ( sourceRDP or destinationRDP ) excluding 1 of exclusion filter* |
| [Renamed Cloudflared.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml) | HIGH | process_creation / windows | 1 of selection_* excluding 1 of filter_main_* |
| [Cloudflared Portable Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_cloudflared_portable_execution.yml) | MEDIUM | process_creation / windows | selection exclusion filter excluding 1 of filter_main_* |
| [HackTool - SharpChisel Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_sharp_chisel.yml) | HIGH | process_creation / windows | selection exclusion filter |

### T1090.002 — External Proxy

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [RDP over Reverse SSH Tunnel WFP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml) | HIGH | security / windows | selection exclusion filter and ( sourceRDP or destinationRDP ) excluding 1 of exclusion filter* |
| [Network Communication Initiated To Portmap.IO Domain](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_domain_portmap.yml) | MEDIUM | network_connection / windows | selection exclusion filter |

### T1098 — Account Manipulation

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [GCP Access Policy Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/gcp/audit/gcp_access_policy_deleted.yml) | MEDIUM | gcp.audit / gcp | selection exclusion filter |
| [Github Outside Collaborator Detected](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/github/audit/github_outside_collaborator_detected.yml) | MEDIUM | audit / github | selection exclusion filter |
| [ESXi Admin Permission Assigned To Account Via ESXCLI](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_esxcli_permission_change_admin.yml) | HIGH | process_creation / linux | selection exclusion filter |
| [Powerview Add-DomainObjectAcl DCSync AD Extend Right](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml) | HIGH | security / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Okta Identity Provider Created](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/identity/okta/okta_identity_provider_created.yml) | MEDIUM | okta / okta | selection exclusion filter |

### T1102.002 — Bidirectional Communication

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Telegram API Access](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_telegram_api.yml) | MEDIUM | proxy | selection exclusion filter excluding exclusion filter |
| [Telegram Bot API Request](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/dns/net_dns_susp_telegram_api.yml) | MEDIUM | dns | selection exclusion filter |
| [Github Self-Hosted Runner Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_github_self_hosted_runner.yml) | MEDIUM | process_creation / windows | all of selection_worker_* or all of selection_listener_* |

### T1105 — Ingress Tool Transfer

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Remote File Copy](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/builtin/lnx_file_copy.yml) | LOW | linux | tools and exclusion filter |
| [Remote File Download Via Findstr.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_findstr_download.yml) | MEDIUM | process_creation / windows | selection_findstr and all of selection_cli_download_* |
| [Insensitive Subfolder Search Via Findstr.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_findstr_subfolder_search.yml) | LOW | process_creation / windows | selection_findstr and all of selection_cli_search_* |
| [Hidden Flag Set On File/Directory Via Chflags - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_chflags_hidden_flag.yml) | MEDIUM | process_creation / macos | selection exclusion filter |
| [File Download Via Nscurl - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_nscurl_usage.yml) | MEDIUM | process_creation / macos | selection exclusion filter |

### T1106 — Native API

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [BPFDoor Abnormal Process ID or Lock File Accessed](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/path/lnx_auditd_bpfdoor_file_accessed.yml) | HIGH | auditd / linux | selection exclusion filter |
| [HackTool - WinPwn Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_winpwn.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [HackTool - HandleKatz Duplicating LSASS Handle](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml) | HIGH | process_access / windows | selection exclusion filter |
| [Potential WinAPI Calls Via PowerShell Scripts](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_win_api_susp_access.yml) | HIGH | ps_script / windows | 1 of selection_* |
| [HackTool - WinPwn Execution - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_hktl_winpwn.yml) | HIGH | ps_script / windows | selection exclusion filter |

### T1124 — System Time Discovery

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Discovery](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_discovery.yml) | LOW | aaa / cisco | keywords |
| [Use of W32tm as Timer](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_w32tm.yml) | HIGH | process_creation / windows | all of selection_* |
| [Discovery of a System Time](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_remote_time_discovery.yml) | LOW | process_creation / windows | 1 of selection_* |

### T1132.001 — Standard Encoding

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Gzip Archive Decode Via PowerShell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_decode_gzip.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [Suspicious FromBase64String Usage On Gzip Archive - Ps Script](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_frombase64string_archive.yml) | MEDIUM | ps_script / windows | selection exclusion filter |
| [DNS Exfiltration and Tunneling Tools Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_dns_exfiltration_tools_execution.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Suspicious FromBase64String Usage On Gzip Archive - Process Creation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_frombase64string_archive.yml) | MEDIUM | process_creation / windows | selection exclusion filter |

### T1134.002 — Create Process with Token

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PUA - AdvancedRun Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_advancedrun.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [Potential Meterpreter/CobaltStrike Activity](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_meterpreter_getsystem.yml) | HIGH | process_creation / windows | selection_img and 1 of selection_technique_* excluding 1 of filter_* |
| [Meterpreter or Cobalt Strike Getsystem Service Installation - Security](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_meterpreter_or_cobaltstrike_getsystem_service_install.yml) | HIGH | security / windows | selection_eid and 1 of selection_cli_* |
| [Suspicious Child Process Created as System](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml) | HIGH | process_creation / windows | selection exclusion filter excluding 1 of filter_* |
| [Meterpreter or Cobalt Strike Getsystem Service Installation - System](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml) | HIGH | system / windows | selection_id and 1 of selection_cli_* |

### T1140 — Deobfuscate/Decode Files or Information

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Ping Hex IP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_ping_hex_ip.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [PowerShell Decompress Commands](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_module/posh_pm_decompress_commands.yml) | INFORMATIONAL | ps_module / windows | selection_4103 |
| [MSHTA Execution with Suspicious File Extensions](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_mshta_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Linux Base64 Encoded Pipe to Shell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_base64_execution.yml) | MEDIUM | process_creation / linux | all of selection_* |
| [DNS-over-HTTPS Enabled by Registry](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_dns_over_https_enabled.yml) | MEDIUM | registry_set / windows | 1 of selection_* |

### T1189 — Drive-by Compromise

**Sigma Rules (3)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cross Site Scripting Strings](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/webserver_generic/web_xss_in_access_logs.yml) | HIGH | webserver | select_method and keywords excluding exclusion filter |
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection exclusion filter excluding exclusion filter |
| [Suspicious Browser Child Process - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_susp_browser_child_process.yml) | MEDIUM | process_creation / macos | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1202 — Indirect Command Execution

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Findstr Launching .lnk File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_findstr_lnk.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_dll_sdiageng_load_by_msdt.yml) | HIGH | image_load / windows | selection exclusion filter |
| [Custom File Open Handler Executes PowerShell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_custom_file_open_handler_powershell_execution.yml) | HIGH | registry_set / windows | selection exclusion filter |
| [Potentially Suspicious Child Processes Spawned by ConHost](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_conhost_susp_winshell_child_process.yml) | HIGH | process_creation / windows | all of selection_* |
| [Troubleshooting Pack Cmdlet Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_follina_execution.yml) | MEDIUM | ps_script / windows | selection exclusion filter |

### T1203 — Exploitation for Client Execution

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Antivirus Exploitation Framework Detection](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/category/antivirus/av_exploiting.yml) | CRITICAL | antivirus | selection exclusion filter |
| [Network Connection Initiated By Eqnedt32.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_eqnedt.yml) | HIGH | network_connection / windows | selection exclusion filter |
| [Download From Suspicious TLD - Whitelist](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_download_susp_tlds_whitelist.yml) | LOW | proxy | selection exclusion filter excluding exclusion filter |
| [Suspicious Invocation of Shell via Rsync](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml) | HIGH | process_creation / linux | selection exclusion filter excluding 1 of filter_main_* |
| [Audit CVE Event](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/application/microsoft-windows_audit_cve/win_audit_cve.yml) | CRITICAL | application / windows | selection exclusion filter |

### T1204.002 — Malicious File

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Flash Player Update from Suspicious Location](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/web/proxy_generic/proxy_susp_flash_download_loc.yml) | HIGH | proxy | selection exclusion filter excluding exclusion filter |
| [Suspicious Microsoft Office Child Process - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_office_susp_child_processes.yml) | HIGH | process_creation / macos | selection exclusion filter |
| [Suspicious Startup Folder Persistence](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml) | HIGH | file_event / windows | selection exclusion filter |
| [Windows MSIX Package Support Framework AI_STUBS Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_msix_ai_stub_execution.yml) | LOW | process_creation / windows | selection exclusion filter |
| [Microsoft Excel Add-In Loaded From Uncommon Location](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_office_excel_xll_susp_load.yml) | MEDIUM | image_load / windows | selection exclusion filter |

### T1218 — System Binary Proxy Execution

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential DLL Sideloading Using Coregen.exe](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_coregen.yml) | MEDIUM | image_load / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Rundll32 UNC Path Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml) | HIGH | process_creation / windows | all of selection_* |
| [COM Object Execution via Xwizard.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [Potentially Suspicious Rundll32.EXE Execution of UDL File](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rundll32_udl_exec.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Potentially Suspicious Wuauclt Network Connection](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml) | MEDIUM | network_connection / windows | selection exclusion filter excluding 1 of filter_main_* |

### T1218.005 — Mshta

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Remotely Hosted HTA File Executed Via Mshta.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_mshta_http.yml) | HIGH | process_creation / windows | all of selection_* |
| [Suspicious MSHTA Child Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_mshta_susp_child_processes.yml) | HIGH | process_creation / windows | all of selection exclusion filter* |
| [Suspicious JavaScript Execution Via Mshta.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_mshta_javascript.yml) | HIGH | process_creation / windows | all of selection_* |
| [Potential LethalHTA Technique Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [HackTool - CACTUSTORCH Remote Thread Creation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/create_remote_thread/create_remote_thread_win_hktl_cactustorch.yml) | HIGH | create_remote_thread / windows | selection exclusion filter |

### T1218.011 — Rundll32

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [SCR File Write Event](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_new_scr_file.yml) | MEDIUM | file_event / windows | selection exclusion filter excluding exclusion filter |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Rundll32 UNC Path Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml) | HIGH | process_creation / windows | all of selection_* |
| [Shell32 DLL Execution in Suspicious Directory](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [Unsigned DLL Loaded by Windows Utility](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_susp_unsigned_dll.yml) | MEDIUM | image_load / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1485 — Data Destruction

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Overwriting the File with Dev Zero or Null](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_dd_delete_file.yml) | LOW | auditd / linux | selection exclusion filter |
| [Potential Secure Deletion with SDelete](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml) | MEDIUM | security / windows | selection exclusion filter |
| [Deleted Data Overwritten Via Cipher.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_cipher_overwrite_deleted_data.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Azure Kubernetes Service Account Modified or Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/azure/activity_logs/azure_kubernetes_service_account_modified_or_deleted.yml) | MEDIUM | activitylogs / azure | selection exclusion filter |
| [Fsutil Suspicious Invocation](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_fsutil_usage.yml) | HIGH | process_creation / windows | all of selection_* |

### T1489 — Service Stop

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Azure Application Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/azure/activity_logs/azure_application_deleted.yml) | MEDIUM | activitylogs / azure | selection exclusion filter |
| [Potential Abuse of Linux Magic System Request Key](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/path/lnx_auditd_magic_system_request_key.yml) | MEDIUM | auditd / linux | selection exclusion filter |
| [Important Scheduled Task Deleted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/taskscheduler/win_taskscheduler_susp_schtasks_delete.yml) | HIGH | taskscheduler / windows | selection exclusion filter excluding exclusion filter |
| [Delete Important Scheduled Task](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_schtasks_delete.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Stop Windows Service Via PowerShell Stop-Service](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_stop_service.yml) | LOW | process_creation / windows | all of selection_* |

### T1491.001 — Internal Defacement

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Replace Desktop Wallpaper by Powershell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_susp_wallpaper.yml) | LOW | ps_script / windows | 1 of selection_* |
| [Potential Ransomware Activity Using LegalNotice Message](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_legalnotice_susp_message.yml) | HIGH | registry_set / windows | selection exclusion filter |
| [Potentially Suspicious Desktop Background Change Using Reg.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_reg_desktop_background_change.yml) | MEDIUM | process_creation / windows | all of selection_reg_* and selection_keys and 1 of selection_cli_reg_* |
| [Potentially Suspicious Desktop Background Change Via Registry](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_desktop_background_change.yml) | MEDIUM | registry_set / windows | selection_keys and 1 of selection_values_* excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1529 — System Shutdown/Reboot

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Denial of Service](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_dos.yml) | MEDIUM | aaa / cisco | keywords |
| [System Shutdown/Reboot - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_system_shutdown_reboot.yml) | INFORMATIONAL | auditd / linux | execve and (shutdowncmd or (init and initselection)) |
| [Potential Abuse of Linux Magic System Request Key](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/path/lnx_auditd_magic_system_request_key.yml) | MEDIUM | auditd / linux | selection exclusion filter |
| [Suspicious Execution of Shutdown](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_shutdown_execution.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [Suspicious Execution of Shutdown to Log Out](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_shutdown_logoff.yml) | MEDIUM | process_creation / windows | selection exclusion filter |

### T1542.003 — Bootkit

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Ransomware or Unauthorized MBR Tampering Via Bcdedit.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_bcdedit_susp_execution.yml) | MEDIUM | process_creation / windows | all of selection_* |

### T1543.003 — Windows Service

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Driver Load From A Temporary Directory](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/driver_load/driver_load_win_susp_temp_use.yml) | HIGH | driver_load / windows | selection exclusion filter |
| [PSEXEC Remote Execution File Artefact](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_sysinternals_psexec_service_key.yml) | HIGH | file_event / windows | selection exclusion filter |
| [New Service Creation Using PowerShell](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_create_service.yml) | LOW | process_creation / windows | selection exclusion filter |
| [Sysinternals PsService Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_sysinternals_psservice.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [New Kernel Driver Via SC.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_sc_new_kernel_driver.yml) | MEDIUM | process_creation / windows | selection exclusion filter excluding 1 of filter_optional_* |

### T1547.001 — Registry Run Keys / Startup Folder

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Persistence Attempt Via Run Keys Using Reg.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_reg_add_run_key.yml) | MEDIUM | process_creation / windows | selection exclusion filter |
| [Potential Suspicious Activity Using SeCEdit](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_secedit_execution.yml) | MEDIUM | process_creation / windows | selection_img and (1 of selection_flags_*) |
| [File Creation In Suspicious Directory By Msdt.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_msdt_susp_directories.yml) | HIGH | file_event / windows | selection exclusion filter |
| [Suspicious Startup Folder Persistence](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_susp_startup_folder_persistence.yml) | HIGH | file_event / windows | selection exclusion filter |
| [VBScript Payload Stored in Registry](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_vbs_payload_stored.yml) | HIGH | registry_set / windows | selection exclusion filter excluding 1 of exclusion filter* |

### T1547.009 — Shortcut Modification

**Sigma Rules (4)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [New Custom Shim Database Created](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_creation_new_shim_database.yml) | MEDIUM | file_event / windows | selection exclusion filter |
| [Windows Network Access Suspicious desktop.ini Action](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_net_share_obj_susp_desktop_ini.yml) | MEDIUM | security / windows | selection exclusion filter |
| [Creation Exe for Service with Unquoted Path](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_creation_unquoted_service_path.yml) | HIGH | file_event / windows | selection exclusion filter |
| [Desktop.INI Created by Uncommon Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_desktop_ini_created_by_uncommon_process.yml) | MEDIUM | file_event / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1553.002 — Code Signing

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Secure Deletion with SDelete](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_sdelete_potential_secure_deletion.yml) | MEDIUM | security / windows | selection exclusion filter |

### T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [WinDivert Driver Load](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/driver_load/driver_load_win_windivert.yml) | HIGH | driver_load / windows | selection exclusion filter |
| [Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing - Network](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_dns_kerberos_coercion_via_dns_object_spn_spoofing.yml) | HIGH | dns / zeek | selection exclusion filter |
| [Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/dns_query/dns_query_win_kerberos_coercion_via_dns_object_spoofing.yml) | HIGH | dns_query / windows | selection exclusion filter |
| [Attempts of Kerberos Coercion Via DNS SPN Spoofing](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_kerberos_coercion_via_dns_spn_spoofing.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Potential PetitPotam Attack Via EFS RPC Calls](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_dce_rpc_potential_petit_potam_efs_rpc_call.yml) | MEDIUM | dce_rpc / zeek | selection exclusion filter |

### T1560 — Archive Collected Data

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Stage Data](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_moving_data.yml) | LOW | aaa / cisco | keywords |
| [Disk Image Mounting Via Hdiutil - MacOS](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml) | MEDIUM | process_creation / macos | selection exclusion filter |
| [Files Added To An Archive Using Rar.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_rar_compress_data.yml) | LOW | process_creation / windows | selection exclusion filter |
| [Compress Data and Lock With Password for Exfiltration With 7-ZIP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_7zip_password_compression.yml) | MEDIUM | process_creation / windows | all of selection_* |
| [Compress Data and Lock With Password for Exfiltration With WINZIP](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_winzip_password_compression.yml) | MEDIUM | process_creation / windows | all of selection exclusion filter* |

### T1561.001 — Disk Content Wipe

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco File Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_file_deletion.yml) | MEDIUM | aaa / cisco | keywords |

### T1561.002 — Disk Structure Wipe

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco File Deletion](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_file_deletion.yml) | MEDIUM | aaa / cisco | keywords |

### T1562.001 — Disable or Modify Tools

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Cisco Disabling Logging](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/cisco/aaa/cisco_cli_disable_logging.yml) | HIGH | aaa / cisco | keywords |
| [Devcon Execution Disabling VMware VMCI Device](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_devcon_disable_vmci_driver.yml) | HIGH | process_creation / windows | all of selection_* |
| [PPL Tampering Via WerFaultSecure](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_werfaultsecure_abuse.yml) | HIGH | process_creation / windows | all of selection_* |
| [AWS GuardDuty Important Change](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml) | HIGH | cloudtrail / aws | selection_source |
| [ASLR Disabled Via Sysctl or Direct Syscall - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/lnx_auditd_disable_aslr_protection.yml) | HIGH | auditd / linux | 1 of selection_* |

### T1562.004 — Disable or Modify System Firewall

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Ufw Force Stop Using Ufw-Init](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/process_creation/proc_creation_lnx_disable_ufw.yml) | MEDIUM | process_creation / linux | 1 of selection_* |
| [A Rule Has Been Deleted From The Windows Firewall Exception List](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml) | MEDIUM | firewall-as / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [Windows Firewall Settings Have Been Changed](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml) | LOW | firewall-as / windows | selection exclusion filter |
| [The Windows Defender Firewall Service Failed To Load Group Policy](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/firewall_as/win_firewall_as_failed_load_gpo.yml) | LOW | firewall-as / windows | selection exclusion filter |
| [New Firewall Rule Added In Windows Firewall Exception List For Potential Suspicious Application](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml) | HIGH | firewall-as / windows | selection exclusion filter excluding 1 of filter_main_* |

### T1564.001 — Hidden Files and Directories

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Displaying Hidden Files Feature Disabled](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_hide_file.yml) | MEDIUM | registry_set / windows | selection exclusion filter |
| [Hidden Files and Directories](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/auditd/execve/lnx_auditd_hidden_files_directories.yml) | LOW | auditd / linux | all of selection_* |
| [PowerShell Logging Disabled Via Registry Key Tampering](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_powershell_logging_disabled.yml) | HIGH | registry_set / windows | selection exclusion filter |
| [Set Suspicious Files as System Files Using Attrib.EXE](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_attrib_system_susp_paths.yml) | HIGH | process_creation / windows | all of selection exclusion filter* excluding 1 of filter_optional_* |
| [Hiding Files with Attrib.exe](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml) | MEDIUM | process_creation / windows | all of selection_* excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1566.001 — Spearphishing Attachment

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [ISO Image Mounted](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/security/win_security_iso_mount.yml) | MEDIUM | security / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Suspicious HWP Sub Processes](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hwp_exploits.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Suspicious HH.EXE Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml) | HIGH | process_creation / windows | all of selection_* |
| [HTML Help HH.EXE Suspicious Child Process](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [ISO or Image Mount Indicator in Recent Files](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_iso_file_recent.yml) | MEDIUM | file_event / windows | selection exclusion filter |

### T1566.002 — Spearphishing Link

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Malicious Usage of CloudTrail System Manager](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/cloud/aws/cloudtrail/aws_cloudtrail_ssm_malicious_usage.yml) | HIGH | cloudtrail / aws | selection_event and 1 of selection_status_* |
| [Suspicious Execution via macOS Script Editor](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml) | MEDIUM | process_creation / macos | all of selection_* |

### T1571 — Non-Standard Port

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious DNS Z Flag Bit Set](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/network/zeek/zeek_dns_susp_zbit_flag.yml) | MEDIUM | dns / zeek | not z_flag_unset and most_probable_valid_domain excluding (exclude_tlds or exclude_query_types or exclude_responses or exclude_netbios) |
| [Potentially Suspicious Malware Callback Communication - Linux](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml) | HIGH | network_connection / linux | selection exclusion filter excluding 1 of filter_main_* |
| [Potentially Suspicious Malware Callback Communication](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_susp_malware_callback_port.yml) | HIGH | network_connection / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [Communication To Uncommon Destination Ports](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/network_connection/net_connection_win_susp_malware_callback_ports_uncommon.yml) | MEDIUM | network_connection / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [Testing Usage of Uncommonly Used Port](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_test_netconnection.yml) | MEDIUM | ps_script / windows | selection exclusion filter excluding exclusion filter |

### T1574.001 — DLL

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential 7za.DLL Sideloading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_7za.yml) | LOW | image_load / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Potential JLI.dll Side-Loading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_jli.yml) | HIGH | image_load / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |
| [Potential WWlib.DLL Sideloading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_wwlib.yml) | MEDIUM | image_load / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Potential Rcdll.DLL Sideloading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_rcdll.yml) | HIGH | image_load / windows | selection exclusion filter excluding exclusion filter |
| [Potential Wazuh Security Platform DLL Sideloading](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/image_load/image_load_side_load_wazuh.yml) | MEDIUM | image_load / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1587.001 — Malware

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [PUA - CsExec Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_pua_csexec.yml) | HIGH | process_creation / windows | any selection exclusion filter exclusion filter matches* |
| [VHD Image Download Via Browser](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_vhd_download_via_browsers.yml) | MEDIUM | file_event / windows | selection exclusion filter |
| [ProxyLogon MSExchange OabVirtualDirectory](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/builtin/msexchange/win_exchange_proxylogon_oabvirtualdir.yml) | CRITICAL | msexchange-management / windows | keywords_cmdlet and keywords_params |
| [Potential PsExec Remote Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_sysinternals_psexec_remote_execution.yml) | HIGH | process_creation / windows | selection exclusion filter excluding 1 of filter_main_* |
| [Uncommon File Created In Office Startup Folder](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/file/file_event/file_event_win_office_uncommon_file_startup.yml) | HIGH | file_event / windows | ((selection_word_paths excluding filter_exclude_word_ext) or (selection_excel_paths excluding filter_exclude_excel_ext)) excluding 1 of filter_main_* |

### T1588.002 — Tool

**Sigma Rules (5)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Suspicious Keyboard Layout Load](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_susp_keyboard_layout_load.yml) | MEDIUM | registry_set / windows | selection_registry |
| [Hacktool Execution - PE Metadata](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_execution_via_pe_metadata.yml) | HIGH | process_creation / windows | selection exclusion filter |
| [Hacktool Execution - Imphash](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_hktl_execution_via_imphashes.yml) | CRITICAL | process_creation / windows | selection exclusion filter |
| [Renamed SysInternals DebugView Execution](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.yml) | HIGH | process_creation / windows | selection exclusion filter excluding exclusion filter |
| [Usage of Renamed Sysinternals Tools - RegistrySet](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/registry/registry_set/registry_set_renamed_sysinternals_eula_accepted.yml) | HIGH | registry_set / windows | selection exclusion filter excluding 1 of filter_main_* excluding 1 of filter_optional_* |

### T1589.002 — Email Addresses

**Sigma Rules (1)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential Unconstrained Delegation Discovery Via Get-ADComputer - ScriptBlock](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_potential_unconstrained_delegation_discovery.yml) | MEDIUM | ps_script / windows | selection exclusion filter |

### T1591 — Gather Victim Org Information

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Bitbucket User Details Export Attempt Detected](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/bitbucket/audit/bitbucket_audit_user_details_export_attempt_detected.yml) | MEDIUM | audit / bitbucket | selection exclusion filter |
| [Bitbucket User Permissions Export Attempt](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml) | MEDIUM | audit / bitbucket | selection exclusion filter |

### T1620 — Reflective Code Loading

**Sigma Rules (2)**

| Rule | Level | Log Source | Condition |
|---|---|---|---|
| [Potential In-Memory Execution Using Reflection.Assembly](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/powershell/powershell_script/posh_ps_dotnet_assembly_from_file.yml) | MEDIUM | ps_script / windows | selection exclusion filter |
| [PowerShell Base64 Encoded Reflective Assembly Load](https://github.com/SigmaHQ/sigma/blob/2f84ca2f1652977cd59f48b6556dfc3f6f14fb5a/rules/windows/process_creation/proc_creation_win_powershell_base64_reflection_assembly_load.yml) | HIGH | process_creation / windows | selection exclusion filter |

## Indicators of Compromise (OTX: 40)

| Type | Value | Confidence | Threat Type | Malware Family | First Seen |
|---|---|---|---|---|---|
| hash_md5 | 3ceee0be85d24d911b9c02714817774c |  |  |  |  |
| hash_md5 | 5d29dfe2ea9ca8da3ff7a14fb20c5e86 |  |  |  |  |
| hash_md5 | 8f4fc2e10b6ec15a01e0af24529040dd |  |  |  |  |
| hash_md5 | ab4abee83ffd526f1975eb48dbdbc812 |  |  |  |  |
| hash_md5 | b48dc6abcd3aeff8618350ccbdc6b09a |  |  |  |  |
| hash_md5 | 143cb4f16dcfc16a02812718acd32c8f |  |  |  |  |
| hash_md5 | 1b8ad5872662a03f4ec08f6750c89abc |  |  |  |  |
| hash_md5 | 1ecd83ee7e4cfc8fed7ceb998e75b996 |  |  |  |  |
| hash_md5 | 2d2b88ae9f7e5b49b728ad7a1d220e84 |  |  |  |  |
| hash_md5 | 35f9cfe5110471a82e330d904c97466a |  |  |  |  |
| hash_sha1 | 3fdf856b6fbcb23e7c3372a3f53ce26c0fe6de77 |  |  |  |  |
| hash_sha1 | 000270fd7f5d5a020ac05c87afe138f80acb120a |  |  |  |  |
| hash_sha1 | 1207d3bad08688a694b6152c57aacfe705914170 |  |  |  |  |
| hash_sha1 | 1b247442e28d9d72cb0c1a6e7dfbcd092829ee6d |  |  |  |  |
| hash_sha1 | 22c19f8ae750b8d438fb872e9d9ac4ab64f62282 |  |  |  |  |
| hash_sha1 | 30511bce9f762c8b75ac0c0592d4aad17a588089 |  |  |  |  |
| hash_sha1 | 64574f7dec9ecbf2a763e0fff6267ee56bfa0a80 |  |  |  |  |
| hash_sha1 | 8cf4a6cf5905992e408f46cd0d8b120c720b31a3 |  |  |  |  |
| hash_sha1 | ae65ffcd83dab3fdafea3ff6915fce34e1307bce |  |  |  |  |
| hash_sha1 | e6f7596ebf7045fb206a313c7881ad0382fbde0d |  |  |  |  |
| hash_sha256 | e95c318d1b1906d57471bb524fff128356c160132d4230db04ab5898ec0eb145 |  |  |  |  |
| hash_sha256 | 1d0999ba3217cbdb0cc85403ef75587f747556a97dee7c2616e28866db932a0d |  |  |  |  |
| hash_sha256 | 53e9bca505652ef23477e105e6985102a45d9a14e5316d140752df6f3ef43d2d |  |  |  |  |
| hash_sha256 | 6dae368eecbcc10266bba32776c40d9ffa5b50d7f6199a9b6c31d40dfe7877d1 |  |  |  |  |
| hash_sha256 | 8fcd303e22b84d7d61768d4efa5308577a09cc45697f7f54be4e528bbb39435b |  |  |  |  |
| hash_sha256 | 9f177a6fb4ea5af876ef8a0bf954e37544917d9aaba04680a29303f24ca5c72c |  |  |  |  |
| hash_sha256 | e40a46e95ef792cf20d5c14a9ad0b3a95c6252f96654f392b4bc6180565b7b11 |  |  |  |  |
| hash_sha256 | e79bbb45421320be05211a94ed507430cc9f6cf80d607d61a317af255733fcf2 |  |  |  |  |
| hash_sha256 | eff3e37d0406c818e3430068d90e7ed2f594faa6bb146ab0a1c00a2f4a4809a5 |  |  |  |  |
| hash_sha256 | fee0081df5ca6a21953f3a633f2f64b7c0701977623d3a4ec36fff282ffe73b9 |  |  |  |  |
| ip | 103.15.232.168 |  |  |  |  |
| ip | 105.184.19.161 |  |  |  |  |
| ip | 105.184.229.17 |  |  |  |  |
| ip | 105.184.229.80 |  |  |  |  |
| ip | 105.184.231.17 |  |  |  |  |
| ip | 105.184.255.194 |  |  |  |  |
| ip | 105.225.112.221 |  |  |  |  |
| ip | 109.160.91.135 |  |  |  |  |
| ip | 109.162.196.130 |  |  |  |  |
| ip | 109.166.233.132 |  |  |  |  |

## Targeted Sectors

- Government
- Private sector

## Associated Malware / Tools

| Name | Type | Description |
|---|---|---|
| RawDisk | malware | RawDisk is a legitimate commercial driver from the EldoS Corporation that is used for interacting with files, disks,… |
| Proxysvc | malware | Proxysvc is a malicious DLL used by Lazarus Group in a campaign known as Operation GhostSecret. It has appeared to be… |
| BADCALL | malware | BADCALL is a Trojan malware variant used by the group Lazarus Group. (Citation: US-CERT BADCALL) |
| FALLCHILL | malware | FALLCHILL is a RAT that has been used by Lazarus Group since at least 2016 to target the aerospace, telecommunications,… |
| WannaCry | malware | WannaCry is ransomware that was first seen in a global attack during May 2017, which affected more than 150 countries.… |
| MagicRAT | malware | MagicRAT is a remote access tool developed in C++ and exclusively used by the Lazarus Group threat actor in operations.… |
| HOPLIGHT | malware | HOPLIGHT is a backdoor Trojan that has reportedly been used by the North Korean government.(Citation: US-CERT HOPLIGHT… |
| TYPEFRAME | malware | TYPEFRAME is a remote access tool that has been used by Lazarus Group. (Citation: US-CERT TYPEFRAME June 2018) |
| Dtrack | malware | Dtrack is spyware that was discovered in 2019 and has been used against Indian financial institutions, research… |
| HotCroissant | malware | HotCroissant is a remote access trojan (RAT) attributed by U.S. government entities to malicious North Korean… |
| HARDRAIN | malware | HARDRAIN is a Trojan malware variant reportedly used by the North Korean government. (Citation: US-CERT HARDRAIN March… |
| Dacls | malware | Dacls is a multi-platform remote access tool used by Lazarus Group since at least December 2019.(Citation: TrendMicro… |
| KEYMARBLE | malware | KEYMARBLE is a Trojan that has reportedly been used by the North Korean government. (Citation: US-CERT KEYMARBLE Aug… |
| TAINTEDSCRIBE | malware | TAINTEDSCRIBE is a fully-featured beaconing implant integrated with command modules used by Lazarus Group. It was first… |
| AuditCred | malware | AuditCred is a malicious DLL that has been used by Lazarus Group during their 2018 attacks.(Citation: TrendMicro… |
| netsh | malware | netsh is a scripting utility used to interact with networking components on local or remote systems. (Citation: TechNet… |
| ECCENTRICBANDWAGON | malware | ECCENTRICBANDWAGON is a remote access Trojan (RAT) used by North Korean cyber actors that was first identified in… |
| AppleJeus | malware | AppleJeus is a family of downloaders initially discovered in 2018 embedded within trojanized cryptocurrency… |
| route | malware | route can be used to find or change information within the local system IP routing table. (Citation: TechNet Route) |
| BLINDINGCAN | malware | BLINDINGCAN is a remote access Trojan that has been used by the North Korean government since at least early 2020 in… |
| ThreatNeedle | malware | ThreatNeedle is a backdoor that has been used by Lazarus Group since at least 2019 to target cryptocurrency, defense,… |
| Volgmer | malware | Volgmer is a backdoor Trojan designed to provide covert access to a compromised system. It has been used since at least… |
| Cryptoistic | malware | Cryptoistic is a backdoor, written in Swift, that has been used by Lazarus Group.(Citation: SentinelOne Lazarus macOS… |
| Responder | malware | Responder is an open source tool used for LLMNR, NBT-NS and MDNS poisoning, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue… |
| RATANKBA | malware | RATANKBA is a remote controller tool used by Lazarus Group. RATANKBA has been used in attacks targeting financial… |
| Bankshot | malware | Bankshot is a remote access tool (RAT) that was first reported by the Department of Homeland Security in December of… |
| Unidentified 101 (Lazarus?) | malware | Potential Lazarus sample. |
| Unidentified 090 (Lazarus) | malware | Recon/Loader malware attributed to Lazarus, disguised as Notepad++ shell extension. |
| SpectralBlur | malware |  |
| QUICKCAFE | malware | QUICKCAFE is an encrypted JavaScript downloader for QUICKRIDE.POWER that exploits the ActiveX M2Soft vulnerabilities.… |
| 3CX Backdoor | malware |  |
| Casso | malware |  |
| Interception | malware |  |
| Unidentified macOS 001 (UnionCryptoTrader) | malware |  |
| WatchCat | malware |  |
| Yort | malware |  |
| RedHat Hacker WebShell | malware |  |
| PowerBrace | malware |  |
| PowerSpritz | malware |  |
| BLINDTOAD | malware | BLINDTOAD is 64-bit Service DLL that loads an encrypted file from disk and executes it in memory. |
| BUFFETLINE | malware |  |
| CLEANTOAD | malware | CLEANTOAD is a disruption tool that will delete file system artifacts, including those related to BLINDTOAD, and will… |
| Klackring | malware | Microsoft describes that threat actor ZINC is using Klackring as a malware dropped by ComeBacker, both being used to… |
| PowerRatankba | malware | QUICKRIDE.POWER is a PowerShell variant of the QUICKRIDE backdoor. Its payloads are often saved to C:\windows\temp\ |
| RustBucket | malware |  |
| sRDI | malware | sRDI allows for the conversion of DLL files to position independent shellcode. It attempts to be a fully functional PE… |
| DarkComet | malware | DarkComet is one of the most famous RATs, developed by Jean-Pierre Lesueur in 2008. After being used in the Syrian… |
| FastCash | malware |  |
| HLOADER | malware |  |

## Recent Intelligence

> Synthesized from 1 vendor research articles using AI.

### Huntress Labs Blog — 2025-06-18  `MEDIUM relevance`

**[Inside the BlueNoroff Web3 macOS Intrusion Analysis](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis)**

BlueNoroff, a subgroup of the Lazarus Group, conducted a Web3-focused macOS intrusion campaign demonstrating the actor's continued targeting of cryptocurrency and blockchain-related entities. The operation employed a multi-stage attack chain leveraging macOS-specific malware and techniques to compromise Web3 developers and organizations, reflecting Lazarus Group's persistent focus on financial theft and high-value digital asset targets. This activity indicates the actor has expanded its operational sophistication to include macOS platforms alongside its historically documented Windows and Linux capabilities.

*Landscape context: This intrusion reflects an escalating trend of DPRK-nexus threat actors expanding beyond traditional financial targets into Web3 and cryptocurrency ecosystems, where fewer security controls and higher-value assets create attractive opportunities for state-sponsored theft. The shift toward macOS-specific attack chains indicates Lazarus Group's continuing effort to diversify targeting beyond Windows-dominant environments and exploit the assumption of lower security maturity on Apple platforms within developer and crypto-native communities.*


## Campaigns

- **Operation Dream Job**
  [Operation Dream Job](https://attack.mitre.org/campaigns/C0022) was a cyber espionage operation likely conducted by [Lazarus…
