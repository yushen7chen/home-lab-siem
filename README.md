\# Home Lab SIEM — Detection Engineering



A detection engineering lab built on Splunk with Windows 10 target 

and Kali Linux attacker VMs. Documents real attack simulations and 

custom detection rules mapped to MITRE ATT\&CK.



\## Lab Architecture



\- \*\*SIEM:\*\* Splunk Enterprise (local)

\- \*\*Target:\*\* Windows 10 VM (192.168.10.10)

\- \*\*Attacker:\*\* Kali Linux VM (192.168.10.20)

\- \*\*Log Sources:\*\* Windows Security, System, PowerShell Operational



\## Detection Rules



| Rule | ATT\&CK Technique | Severity | Format |

|------|-----------------|----------|--------|

| Suspicious PowerShell Execution | T1059.001 | High | Sigma + SPL |

| Account Discovery via Net Commands | T1087 | Medium | Sigma + SPL |

| System Information Discovery | T1082 | Low | Sigma + SPL |



\## Simulated Attacks



| Technique | Description | Detected |

|-----------|-------------|---------|

| T1059.001 | PowerShell execution with bypass flags | Yes |

| T1087 | Account discovery via net user / Get-LocalUser | Yes |

| T1082 | System information collection via systeminfo | Yes |

| T1057 | Process discovery via Get-Process | Yes |



\## Detection Methodology



Each detection rule follows this workflow:

1\. Identify attack technique from MITRE ATT\&CK

2\. Execute simulation to generate log artifacts

3\. Analyze logs in Splunk to identify detection opportunities

4\. Write SPL detection rule and save as Splunk Alert

5\. Convert to Sigma format for portability



\## Tools Used



\- Splunk Enterprise (SIEM)

\- Splunk Universal Forwarder (log collection)

\- MITRE ATT\&CK Framework (threat mapping)

\- Sigma (portable detection rule format)



\## Splunk SPL Rules



\### T1059.001 — Suspicious PowerShell Execution



index=main source="WinEventLog:Windows PowerShell" EventCode=400

OR (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)

| eval suspicious=if(match(Message,"(?i)(bypass|encoded|hidden|downloadstring|iex|invoke-expression|net user|Get-LocalUser)"),1,0)

| where suspicious=1

| table \_time, EventCode, Message

| sort -\_time



\### T1087 — Account Discovery



index=main so

