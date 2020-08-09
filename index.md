# Introduction
HostIntrusion.com is an educational resource primarily focused on developing skills and knowledge of host based intrusions. These intrusions have been inspired by real-life documented OSINT reports.

**Intended audience:** SOC analysts, researchers and network defenders - to detect adversary attacks against enterprise IT systems.

**Prerequisites:** Essential: host and network topologies, infrastructure components/configurations. Basic understanding of Windows and Linux OS, familiarisation of log sources, and knowledge of attack methods is recommended. 

**License:** GNU General Public License v3

**Disclaimer:** Please handle artifacts with care, and do not use on production systems. Whilst care has been taken to minimise use of malicious artifacts, there could be traces i.e. commands/scripts embedded in logs etc.

# Getting Started
The focus of Host Intrusion is primarily on host based artifacts - including logs, and others such as host based agent data and process dumps. There are other artifacts such as network logs (PCAPS and IDS), which provide detailed insights into network behaviour i.e. C2, interactions etc. From a DFIR perspective, disk images and memory captures also provide detailed evidence of host level activity (i.e. user and system). All of these artifacts provide the network defender with a rich insights across both the host and network - however the reality is quite different; i.e. lack of network level monitoring/collection, tool configuration, or lack of skilled personnel.

Audit logs provide a minimum level of security monitoring that can be implemented using vendor best practices. Detection of adversary behaviour using audit logs is largely dependent on the source (i.e. product and configuration), traditionally, audit logs haven’t always provided the low-level signals (i.e. command-line/API interactions etc). 

The exercises below aim to walkthrough some of adversary attacks, highlight some of the challenges (gaps) and how other artifacts could be correlated to establish facts and inform conclusions.

# Host Intrusion
An host intrusion could be detected by several means, a SIEM alert could be generated in response to an event (i.e. AV alert, configuration change etc), a user could report unusual activity (i.e performance, account lock out etc), or through a pro-active investigation (i.e. hunting for evidence of suspicious activity via IoCs). 

The exercises will focus on log sources from a variety of sources, including web servers, domain controllers, sysmon, auditd etc to correlate activity relating to the intrusion, methods of analysis and presenting as part of a incident report.

An APT actor could achieve access via a variety of means. Remote access is traditionally favoured i.e. email, web browser, VPN etc, as opposed to physical or close access i.e. WiFi access, USB drop etc. There are a number of frameworks that can assist the network defender to characterise the stage of the compromise/incident, these include the LockHeed Martin Cyber Kill Chain, MITRE ATT&CK, and Mandiant Attack Lifecycle illustrated below.

![mandiant](/cyber_attack_lifecycle.jpg)

# Exercises
The following exercises aim to walkthrough some scenarios featuring reported attacks (TTPS or tooling). The purpose of these exercises is to expose you to the different types of host artifacts, triage approach and how to determine the host compromise based on available data. Secondly, the exercises have deliberately introduced constraints through improper configuration i.e. logging, clock sync etc, representing real-world challenges.

+ [07-2020-WebShell](/exercise-webshell//webshell)

# Tools
A selection of tools for viewing/querying log files via the CLI.
+ [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
+ [PowerShell](https://wiki.sans.blue/Tools/pdfs/Get-WinEvent.pdf)
+ [Python-EVTX](https://github.com/williballenthin/python-evtx)
+ [Microsoft LogParser](https://www.microsoft.com/en-us/download/details.aspx?id=24659)

# Samples
Link to a Git repo containing a variety of artifacts mapped to MITRE ATT&CK technique IDs. These are small snippets of log entries for example, that are based on known and reported TTPs. Please note, some of these techniques could be dual use i.e. used for legitimate as well as malicious purposes.

+ [MITRE ATT&CK Mapped Artifacts](https://github.com/hostintrusion/MITRE-Technique-Samples/)

# Good Practices
Authority resources that provide good practices from host configuration through to incident response.
+ [NIST Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
+ [NCSC Introduction to Logging](https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes)
+ [NCSC Logging Made Easy](https://www.ncsc.gov.uk/information/logging-made-easy)
+ [ACSC Windows Event Logging and Forwarding](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)

# Recommended Books

# References
Curated list of references grouped by theme, a mix of primer, look-ups, configurations and vendor recommendations.
### Primer
+ [UK Cyber Body of Knowledge](Security Operations &Incident ManagementKnowledge Area)

### Microsoft Windows
+ [Microsoft - Events to Monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
+ [NSA - Recommended Events to Collect](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events)
+ [Windows EVTX Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
+ [UltimateWindowsSecurity - EventID Lookup](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
+ [Microsoft - Event Logs](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc722404(v=ws.11)?redirectedfrom=MSDN)
+ [SANS - Event IDS](https://wiki.sans.blue/Tools/pdfs/WindowsEventLogsTable.pdf)

### Linux

### Configuration
+ [CIS Benchmarks](https://github.com/cismirror/benchmarks)

### Threat
+ [Mitre ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
+ [ActiveCountermeasures - Log Analysis](https://www.activecountermeasures.com/log-analysis-part-1-enterprise-logging-approaches/)
+ [UK Home Office Cyber - Detecting the Unknown](https://hodigital.blog.gov.uk/wp-content/uploads/sites/161/2020/03/Detecting-the-Unknown-A-Guide-to-Threat-Hunting-v2.0.pdf)
+ [Mandiant - Anatomy of an APT](https://www.fireeye.com/current-threats/anatomy-of-a-cyber-attack.html)
+ [Lockheed Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)

# What Next?
