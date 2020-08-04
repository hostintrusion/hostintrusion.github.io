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

# Recommended Books

# Exercises

# Tools
+ [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)

# Samples

# Good Practices
+ [NIST Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
+ [NCSC Introduction to Logging](https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes)
+ [NCSC Logging Made Easy](https://www.ncsc.gov.uk/information/logging-made-easy)
+ [ACSC Windows Event Logging and Forwarding](https://www.cyber.gov.au/acsc/view-all-content/publications/windows-event-logging-and-forwarding)

# Learning Resources

# References
### Microsoft Windows
+ [Microsoft - Events to Monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
+ [NSA - Recommended Events to Collect](https://github.com/nsacyber/Event-Forwarding-Guidance/tree/master/Events)
+ [Windows EVTX Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
+ [UltimateWindowsSecurity - EventID Lookup](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

### Linux

### Configuration
+ [CIS Benchmarks](https://github.com/cismirror/benchmarks)

### Threat
+ [Mitre ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
+ [ActiveCountermeasures - Log Analysis](https://www.activecountermeasures.com/log-analysis-part-1-enterprise-logging-approaches/)
