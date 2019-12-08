# threat-intelligence-analysis
threat intelligence analysis. Secondary analysis of threat intelligence reports.

The goal of this work is to produce output reports with key data extracted. This data can then then be quickly consumed by your internal teams.

## NMC Security Ltd services
NMC Security Ltd provides services that include the analysis of threat intelligence report and the extraction of key data. As part of these services there is an option for the customer to publish these reports to help the wider community.

## Git hub project content
This secondary analysis output includes the following data types:

### Threat Intelligence Analysis:
Link to original report, name of the report, date
### Executive Summary:
A text description of the original threat intelligence analysis.
### Threat Actor:
The adversary attributes.
### Tactics and Techniques:
Mitre ATT&CK https://attack.mitre.org/techniques/enterprise/ https://attack.mitre.org/techniques/mobile/ and https://attack.mitre.org/techniques/pre/
### Mitigations:
Mitre ATT&CK https://attack.mitre.org/mitigations/enterprise/ and https://attack.mitre.org/mitigations/mobile/
### Indicators of Compromise:
Inlcudes IP adresses, FQDNs, file hash values, string values
### Detections:
Direct links to SIGMA https://github.com/Neo23x0/sigma YARA https://github.com/Yara-Rules or https://github.com/Neo23x0/signature-base , Virus Total https://www.virustotal.com/gui/home/search IBM Threat Exchange https://exchange.xforce.ibmcloud.com/ based on identified indicators from the Indicators of Compromise: section
### Summary:
A text description of the secondary analysis.
### Appendix:
A structured collection of the secondary analysis.

## Contribution
NMC Security Ltd activity invites the security community to contribute to the effort to extract key data form primary threat analysis; into a structure that is suitable to be imported into enterprise threat models, quickly consumed by internal teams or just quickly read.

The primary threat intelligence report must be publicly available (linked) within the output or added to the input folder of this repository (Traffic Light Protocol: White).

---

# Threat Intelligence Analysis Content
Original Ref link | Name | Threat Intelligence Analysis Link
--- | --- | ---
https://www.ncsc.gov.uk/news/trickbot-banking-trojan | NCSC_Trickbot_Brief_User_Guide.pdf | https://github.com/nmcsecurity/threat-intelligence-analysis/blob/master/output/NCSC_trickbot_banking_trojan.md
https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/ | a-look-into-fysbis-sofacys-linux-backdoor | https://github.com/nmcsecurity/threat-intelligence-analysis/blob/master/output/unit42_APT28_fysbis.md