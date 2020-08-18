# Exercise: Quasar
**Date:** 18/08/2020

There are 2 x log files. The logs are in the following zip file:

+ [Quasar Intrusion Logs](https://github.com/hostintrusion/scenarios/blob/master/2020-08-Quasar.zip)

During routine maintenance on host DC-1 IPv4 192.168.112\[.\]140, an observant system administrated spotted an unrecognised folder on C: drive. Further analysis of the folder and its content, revealed the following.



The activity (folder creation) occurred out of hours, and quick analysis of the events has determined that doesn’t appear to be a legitimate action. It is suspected that there is a compromise.

## Objective
Using the log files can you determine and undertake the following:

+ What was the name of the malicious document?
+ What was the name of the malware?
+ What is the temporary file name?
+ Where does the malware persist?
+ What is the MD5 hash for the malware (binary)?
+ How does the malware automatically start?
+ What IPv4 address and port does the malware connect to? 
+ What domains are contacted?
+ What commands are invoked by the attacker on DC2 host?
+ What is the name of the file created on DC-2?
+ What did the attacker use the file created on DC-2 for?
+ What commands are invoked by the attacker on DC1 host?
+ What was the purpose of invoking the process starting with 'v'?
+ What was the adversary IP address used to connect via FTP?
+ What folder was used for staging?
+ List the MITRE ATT&CK TTPs
+ Produce a timeline of the events
+ Document any limitations or gaps or issues
+ Document any attacker mistakes

## Solution
[Exercise write-up](quasar-solution.md)

# References
The following advisories may assist:
+ [US CERT - Quasar Open-Source Remote Administration Tool](https://us-cert.cisa.gov/ncas/analysis-reports/AR18-352A)
+ [PAExec](https://www2.poweradmin.com/paexec/)
+ [TrustWave - NTDS](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/)
+ [Microsoft - Vol Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
+ [UltimateWindowsSecurity - Extracting Password Hashes from the Ntds.dit File](https://www.ultimatewindowssecurity.com/blog/default.aspx?d=10/2017)
