\# Threat Detection Report

\## Home Lab SIEM — Detection Engineering Exercise



\*\*Author:\*\* Yushen Chen  

\*\*Date:\*\* May 2026  

\*\*Environment:\*\* Splunk Enterprise + Windows 10 VM  

\*\*Framework:\*\* MITRE ATT\&CK v14  



\---



\## Executive Summary



This report documents a detection engineering exercise conducted 

in an isolated home lab environment. Four MITRE ATT\&CK techniques 

commonly associated with post-exploitation reconnaissance were 

simulated against a Windows 10 target system. Custom detection 

rules were developed in Splunk SPL and converted to Sigma format 

for cross-platform portability.



All four techniques were successfully detected via Windows 

PowerShell Operational event logs ingested into Splunk Enterprise.



\*\*Key Finding:\*\* Default Windows audit policy is insufficient 

for detecting PowerShell-based reconnaissance. Enabling PowerShell 

Operational logging (Event ID 4104) significantly improves 

detection coverage with minimal performance impact.



\---



\## Environment



| Component | Details |

|-----------|---------|

| SIEM | Splunk Enterprise 9.x (local) |

| Target OS | Windows 10 Pro (VM) |

| Attacker OS | Kali Linux (VM) |

| Network | Isolated Internal Network (192.168.10.0/24) |

| Log Sources | WinEventLog:Security, WinEventLog:Windows PowerShell, WinEventLog:Microsoft-Windows-PowerShell/Operational |

| Detection Framework | MITRE ATT\&CK v14 |



\---



\## Techniques Simulated



| # | ATT\&CK ID | Technique | Tactic | Detected |

|---|-----------|-----------|--------|---------|

| 1 | T1059.001 | PowerShell Execution | Execution | Yes |

| 2 | T1087 | Account Discovery | Discovery | Yes |

| 3 | T1082 | System Information Discovery | Discovery | Yes |

| 4 | T1057 | Process Discovery | Discovery | Yes |



\---



\## Detailed Findings



\### Finding 1 — T1059.001: PowerShell Execution



\*\*Tactic:\*\* Execution  

\*\*Severity:\*\* High  

\*\*Detection Status:\*\* Detected  



\*\*Attack Description:\*\*  

PowerShell was executed with the `-ExecutionPolicy Bypass` flag, 

a common technique used by attackers to circumvent PowerShell 

execution policy restrictions. This allows unsigned scripts to 

run without restriction.



\*\*Simulation Command:\*\*

powershell.exe -ExecutionPolicy Bypass -Command

"Get-LocalUser; Get-Process; net user"



\*\*Log Evidence:\*\*  

\- Source: WinEventLog:Windows PowerShell  

\- Event ID: 400 (Engine Lifecycle)  

\- Event ID: 4104 (Script Block Logging)  

\- Key indicator: "bypass" string in PowerShell engine parameters  



\*\*Attack Timeline:\*\*

\[T+00:00] PowerShell process launched with bypass flag

\[T+00:01] Script block logged in PowerShell Operational log

\[T+00:03] Log forwarded to Splunk via Universal Forwarder

\[T+00:05] SPL detection rule triggered

\[T+00:05] Alert recorded in Splunk Triggered Alerts



\*\*SPL Detection Rule:\*\*

index=main source="WinEventLog:Windows PowerShell" EventCode=400

OR (source="WinEventLog:Microsoft-Windows-PowerShell/Operational"

EventCode=4104)

| eval suspicious=if(match(Message,

"(?i)(bypass|encoded|hidden|downloadstring|iex|invoke-expression)"),1,0)

| where suspicious=1

| table \_time, EventCode, Message

| sort -\_time



\*\*False Positive Analysis:\*\*  

\- Legitimate software installers occasionally use `-ExecutionPolicy Bypass`  

\- Recommend allowlisting known installer paths (e.g. C:\\Windows\\Installer)  

\- Net false positive rate in test environment: 0%  



\*\*Mitigation Recommendations:\*\*  

1\. Enable PowerShell Constrained Language Mode for standard users  

2\. Implement application allowlisting via AppLocker or WDAC  

3\. Alert on `-ExecutionPolicy Bypass` from non-approved paths  

4\. Require PowerShell script signing for all production scripts  



\---



\### Finding 2 — T1087: Account Discovery



\*\*Tactic:\*\* Discovery  

\*\*Severity:\*\* Medium  

\*\*Detection Status:\*\* Detected  



\*\*Attack Description:\*\*  

Attackers commonly enumerate local user accounts and groups 

immediately after gaining initial access to understand the 

privilege landscape of the compromised system.



\*\*Simulation Commands:\*\*

net user

net localgroup administrators

Get-LocalUser

Get-LocalGroup



\*\*Log Evidence:\*\*  

\- Source: WinEventLog:Windows PowerShell  

\- Event ID: 400, 4104  

\- Key indicators: "net user", "Get-LocalUser", "Get-LocalGroup"  



\*\*Attack Timeline:\*\*

\[T+00:00] net user executed — enumerates all local accounts

\[T+00:01] Get-LocalUser executed — PowerShell equivalent

\[T+00:03] Commands logged in PowerShell Operational log

\[T+00:05] Splunk alert triggered



\*\*SPL Detection Rule:\*\*

index=main source="WinEventLog:Windows PowerShell"

| search Message="net user" OR Message="Get-LocalUser"

OR Message="Get-LocalGroup"

| table \_time, EventCode, Message

| sort -\_time



\*\*False Positive Analysis:\*\*  

\- IT administrators routinely run account enumeration commands  

\- Recommend baselining normal admin activity and alerting on 

&#x20; deviations (e.g. execution outside business hours, from 

&#x20; non-admin accounts)  



\*\*Mitigation Recommendations:\*\*  

1\. Implement just-in-time (JIT) privileged access  

2\. Alert on account enumeration from non-admin accounts  

3\. Monitor for bulk account queries in short time windows  



\---



\### Finding 3 — T1082: System Information Discovery



\*\*Tactic:\*\* Discovery  

\*\*Severity:\*\* Low  

\*\*Detection Status:\*\* Detected  



\*\*Attack Description:\*\*  

Attackers collect detailed system information to understand 

the target environment, identify security software, and plan 

lateral movement or privilege escalation.



\*\*Simulation Commands:\*\*

systeminfo

Get-ComputerInfo



\*\*Log Evidence:\*\*  

\- Source: WinEventLog:Windows PowerShell  

\- Event ID: 400, 4104  

\- Key indicators: "systeminfo", "Get-ComputerInfo"  



\*\*SPL Detection Rule:\*\*

index=main source="WinEventLog:Windows PowerShell"

| search Message="systeminfo" OR Message="Get-ComputerInfo"

| table \_time, EventCode, Message

| sort -\_time



\*\*False Positive Analysis:\*\*  

\- High false positive rate — systeminfo used legitimately 

&#x20; by IT support and monitoring tools  

\- Recommend correlating with other discovery techniques 

&#x20; in same session before alerting  

\- Low severity standalone; high severity when combined 

&#x20; with T1059.001 or T1087 in same session  



\*\*Mitigation Recommendations:\*\*  

1\. Use this detection as correlation signal, not standalone alert  

2\. Build a composite detection: T1082 + T1087 in same 5-minute 

&#x20;  window = High severity alert  



\---



\### Finding 4 — T1057: Process Discovery



\*\*Tactic:\*\* Discovery  

\*\*Severity:\*\* Low  

\*\*Detection Status:\*\* Detected  



\*\*Attack Description:\*\*  

Attackers enumerate running processes to identify security 

software (AV, EDR), understand the system's purpose, and 

find targets for credential harvesting or injection.



\*\*Simulation Commands:\*\*

Get-Process

Get-Process | Select-Object Name, Id | Out-File C:\\recon.txt



\*\*Log Evidence:\*\*  

\- Source: WinEventLog:Windows PowerShell  

\- Event ID: 4104  

\- Key indicator: "Get-Process" in script block log  



\*\*SPL Detection Rule:\*\*

index=main source="WinEventLog:Windows PowerShell"

| search Message="Get-Process" OR Message="tasklist"

| table \_time, EventCode, Message

| sort -\_time



\*\*False Positive Analysis:\*\*  

\- Very high false positive rate standalone  

\- Get-Process used extensively by monitoring and admin tools  

\- Value is in correlation: process discovery + file write 

&#x20; (Out-File) in same session indicates systematic reconnaissance  



\*\*Mitigation Recommendations:\*\*  

1\. Alert on process discovery combined with file output commands  

2\. Monitor for recon.txt or similar named output files in 

&#x20; unexpected locations  



\---



\## Composite Detection — Reconnaissance Chain



The highest-value detection is not any single technique 

but the combination of all four in a single session, 

indicating a systematic reconnaissance chain.



\*\*Composite SPL Rule:\*\*

index=main source="WinEventLog:Windows PowerShell"

| eval t1059=if(match(Message,"(?i)(bypass|encoded|iex)"),1,0)

| eval t1087=if(match(Message,"(?i)(net user|Get-LocalUser|Get-LocalGroup)"),1,0)

| eval t1082=if(match(Message,"(?i)(systeminfo|Get-ComputerInfo)"),1,0)

| eval t1057=if(match(Message,"(?i)(Get-Process|tasklist)"),1,0)

| eval recon\_score=t1059+t1087+t1082+t1057

| where recon\_score >= 2

| stats max(recon\_score) as score,

values(Message) as commands

by \_time span=5m

| where score >= 2

| sort -score



\*\*Interpretation:\*\*  

\- Score 1: Low — single discovery technique, likely benign  

\- Score 2: Medium — two techniques in 5 minutes, investigate  

\- Score 3-4: High — systematic reconnaissance, respond immediately  



\---



\## Key Lessons Learned



\*\*1. Default Windows logging is insufficient\*\*  

Windows 10 default audit policy does not enable process 

creation command line logging or PowerShell script block logging. 

Both must be explicitly enabled for meaningful detection coverage.



\*\*2. PowerShell Operational logs are high-value\*\*  

Event ID 4104 (Script Block Logging) provides the actual 

commands executed, making it the most valuable log source 

for PowerShell-based attack detection.



\*\*3. Individual technique detection has high false positive rates\*\*  

Each technique in isolation generates significant false positives. 

Composite detection rules correlating multiple techniques 

dramatically improve signal-to-noise ratio.



\*\*4. Log forwarding introduces delay\*\*  

Splunk Universal Forwarder introduces approximately 2-5 minute 

delay between event generation and Splunk ingestion. 

Real-time alerting must account for this latency.



\---



\## Detection Coverage Summary



| Technique | Log Source | Event IDs | FP Rate | Confidence |

|-----------|-----------|-----------|---------|------------|

| T1059.001 | PS Operational | 400, 4104 | Low | High |

| T1087 | PS Operational | 400, 4104 | Medium | Medium |

| T1082 | PS Operational | 400, 4104 | High | Low |

| T1057 | PS Operational | 4104 | High | Low |

| Composite | PS Operational | 400, 4104 | Low | High |



\---



\## Recommendations for Production Implementation



1\. \*\*Enable PowerShell logging via GPO\*\* across all endpoints  

2\. \*\*Implement composite detection\*\* rather than individual 

&#x20;  technique alerts to reduce alert fatigue  

3\. \*\*Baseline normal behavior\*\* before deploying alerts — 

&#x20;  understand what legitimate admin activity looks like  

4\. \*\*Add EDR telemetry\*\* to supplement Windows event logs 

&#x20;  for process-level visibility  

5\. \*\*Tune alert thresholds\*\* based on environment — 

&#x20;  a developer workstation generates more PowerShell 

&#x20;  activity than a standard user machine  



\---



\## Appendix — Sigma Rules



All detection rules available in Sigma format:  

\[sigma-rules/](./sigma-rules/)



\## Appendix — Lab Setup



Full lab configuration documented in:  

\[README.md](./README.md)

