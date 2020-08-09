# Exercise: WebShell
**Date:** 04/08/2020

There are 3 x log files. One web log, windows security audit log, and a sysmon log. The logs are in the following zip file:

+[WebShell Intrusion Logs](https://github.com/hostintrusion/scenarios/blob/master/2020-07-Webshell_compromise.zip)

The SIEM generated an alert in response to an attempt to create a user to a local administrator group. The action appeared to have failed as there was no event in the security log. The SIEM alert detected the following activity:

*"net1 localgroup administrators appusr /add"*

SysMon 06/07/2020 12:57:23, EventRecID: 1087. It has been confirmed that this activity wasn't legitimate.

## Objective
Using the log files can you determine and undertake the following:

+ Attacker IP addresses?
+ Attacker User Agent string?
+ What was the vulnerable web page?
+ Name of malicious file uploaded?
+ What tools were uploaded onto the server?
+ What was the utility of the tools?
+ Were any changes made to the server i.e. config changes to accounts etc?
+ We noticed a lot of random http requests in the log. What tool was used?
+ Any recommendations to harden the host?
+ What information was gathered?
+ Method of attack (ATT&CK technique)
+ Establish time line of events
+ What IoCs could be used?
+ What SIEM correlation rules could be used to detect the attack earlier?
+ Produce an incident report detailing the attack and recommendations.

## Solution
[Exercise write-up](webshell-solution.md)

# References
The following advisories may assist:
+ [ACSC - Advisory 2020-008: Copy-paste compromises - tactics, techniques and procedures used to target multiple Australian networks](https://www.cyber.gov.au/acsc/view-all-content/advisories/advisory-2020-008-copy-paste-compromises-tactics-techniques-and-procedures-used-target-multiple-australian-networks)
+ [NSA - Detect and Prevent Web Shell Malware](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)
