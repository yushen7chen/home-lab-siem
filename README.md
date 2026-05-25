\# Home Lab SIEM — Detection Engineering



A detection engineering lab built on Splunk Enterprise with isolated 

Windows 10 target and Kali Linux attacker VMs. Documents real attack 

simulations, custom SPL detection rules, and Sigma signatures mapped 

to MITRE ATT\&CK.



\*\*Author:\*\* Yushen Chen  

\*\*Last Updated:\*\* May 2026  

\*\*Framework:\*\* MITRE ATT\&CK v14  



\---



\## Lab Architecture

Host Machine

├── Windows 10 VM (192.168.10.10) — Target

│   ├── Splunk Enterprise 9.x (SIEM)

│   └── Splunk Universal Forwarder (log collection)

└── Kali Linux VM (192.168.10.20) — Attacker

└── Isolated Internal Network (labnet)



| Component | Details |

|-----------|---------|

| SIEM | Splunk Enterprise 9.x |

| Target | Windows 10 Pro VM |

| Attacker | Kali Linux VM |

| Network | Isolated Internal Network 192.168.10.0/24 |

| Hypervisor | VirtualBox |



\---



\## Log Sources Configured



| Source | Event IDs | Purpose |

|--------|-----------|---------|

| WinEventLog:Security | 4688, 4624, 4625 | Process creation, logon events |

| WinEventLog:Windows PowerShell | 400, 403 | PowerShell engine lifecycle |

| WinEventLog:Microsoft-Windows-PowerShell/Operational | 4104 | Script block logging |



\---



\## Simulated ATT\&CK Techniques



| ATT\&CK ID | Technique | Tactic | Severity | Detected |

|-----------|-----------|--------|----------|---------|

| T1059.001 | PowerShell Execution | Execution | High | Yes |

| T1087 | Account Discovery | Discovery | Medium | Yes |

| T1082 | System Information Discovery | Discovery | Low | Yes |

| T1057 | Process Discovery | Discovery | Low | Yes |

| Composite | Reconnaissance Chain | Execution + Discovery | High | Yes |

| T1046 | Network Service Discovery | Discovery | High | Yes |



\---



\## Detection Rules



\### Splunk SPL Rules



\*\*T1059.001 — Suspicious PowerShell Execution\*\*

```spl

index=main source="WinEventLog:Windows PowerShell" EventCode=400

OR (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)

| eval suspicious=if(match(Message,"(?i)(bypass|encoded|hidden|downloadstring|iex|invoke-expression|net user|Get-LocalUser)"),1,0)

| where suspicious=1

| table \_time, EventCode, Message

| sort -\_time

```



\*\*T1087 — Account Discovery\*\*

```spl

index=main source="WinEventLog:Windows PowerShell"

| search Message="\*net user\*" OR Message="\*Get-LocalUser\*" OR Message="\*Get-LocalGroup\*"

| table \_time, EventCode, Message

| sort -\_time

```



\*\*T1082 — System Information Discovery\*\*

```spl

index=main source="WinEventLog:Windows PowerShell"

| search Message="\*systeminfo\*" OR Message="\*Get-ComputerInfo\*"

| table \_time, EventCode, Message

| sort -\_time

```



\*\*T1057 — Process Discovery\*\*

```spl

index=main source="WinEventLog:Windows PowerShell"

| search Message="\*Get-Process\*" OR Message="\*tasklist\*"

| table \_time, EventCode, Message

| sort -\_time

```



\*\*Composite — Reconnaissance Chain (Highest Value)\*\*

```spl

index=main source="WinEventLog:Windows PowerShell"

| eval t1059=if(match(Message,"(?i)(bypass|encoded|iex)"),1,0)

| eval t1087=if(match(Message,"(?i)(net user|Get-LocalUser|Get-LocalGroup)"),1,0)

| eval t1082=if(match(Message,"(?i)(systeminfo|Get-ComputerInfo)"),1,0)

| eval t1057=if(match(Message,"(?i)(Get-Process|tasklist)"),1,0)

| eval recon\_score=t1059+t1087+t1082+t1057

| where recon\_score >= 2

| stats max(recon\_score) as score, values(Message) as commands by \_time span=5m

| where score >= 2

| sort -score

```

**Note:** T1046 was simulated from an external Kali Linux attacker VM 
(192.168.10.20) via Nmap — all other techniques executed locally 
on the target to simulate post-exploitation activity.

\### Sigma Rules



Portable detection rules in Sigma format — usable with any SIEM:



| File | Technique | Level |

|------|-----------|-------|

| \[T1059\_suspicious\_powershell.yml](./sigma-rules/T1059\_suspicious\_powershell.yml) | T1059.001 | High |

| \[T1087\_account\_discovery.yml](./sigma-rules/T1087\_account\_discovery.yml) | T1087 | Medium |

| \[T1082\_system\_info\_discovery.yml](./sigma-rules/T1082\_system\_info\_discovery.yml) | T1082 | Low |

| \[T1057\_process\_discovery.yml](./sigma-rules/T1057\_process\_discovery.yml) | T1057 | Low |

| \[T1059\_T1087\_T1082\_T1057\_recon\_chain.yml](./sigma-rules/T1059\_T1087\_T1082\_T1057\_recon\_chain.yml) | Composite | High |



\---



\## Threat Detection Report



Full analysis including attack timelines, false positive analysis, 

and mitigation recommendations:



\[THREAT-DETECTION-REPORT.md](./THREAT-DETECTION-REPORT.md)



\*\*Report covers:\*\*

\- Attack simulation methodology

\- Log evidence for each technique

\- False positive analysis per detection rule

\- Composite reconnaissance chain detection

\- Production implementation recommendations



\---



\## Key Findings



\*\*1. Default Windows logging is insufficient\*\*  

Windows 10 default audit policy does not capture PowerShell 

command content. Enabling Script Block Logging (Event ID 4104) 

is required for meaningful detection coverage.



\*\*2. Composite detection dramatically reduces false positives\*\*  

Individual technique detections have high false positive rates. 

Correlating multiple techniques in the same session (recon score ≥ 2) 

produces high-confidence, low-noise alerts.



\*\*3. PowerShell Operational log is the highest-value source\*\*  

Event ID 4104 captures actual commands executed, making it 

the most actionable log source for PowerShell-based attacks.



\---



\## Setup Guide



\### Prerequisites

\- VirtualBox

\- Windows 10 ISO

\- Kali Linux ISO

\- Splunk Enterprise (free license)

\- Splunk Universal Forwarder



\### Network Configuration

Windows 10 VM: 192.168.10.10 (Internal Network: labnet)

Kali Linux VM: 192.168.10.20 (Internal Network: labnet)



\### Enable PowerShell Logging (Windows 10 VM)

```powershell

\# Enable Script Block Logging

reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG\_DWORD /d 1 /f



\# Enable Process Creation Command Line

reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine\_Enabled /t REG\_DWORD /d 1 /f

```



\### Splunk Universal Forwarder inputs.conf

\[WinEventLog://Security]

disabled = 0

index = main

\[WinEventLog://System]

disabled = 0

index = main

\[WinEventLog://Microsoft-Windows-PowerShell/Operational]

disabled = 0

index = main

\[WinEventLog://Windows PowerShell]

disabled = 0

index = main



\---



\## Tools \& References



\- \[Splunk Enterprise](https://www.splunk.com)

\- \[MITRE ATT\&CK Framework](https://attack.mitre.org)

\- \[Sigma Rules](https://github.com/SigmaHQ/sigma)

\- \[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

\- \[OWASP LLM Top 10](https://github.com/yushen7chen/owasp-llm-top10)



\---



\## Related Projects



\- \[OWASP LLM Top 10 Research Repository](https://github.com/yushen7chen/owasp-llm-top10)

\- \[AI Agent Trust Boundary Monitor](https://github.com/yushen7chen/agent-trust-monitor)

