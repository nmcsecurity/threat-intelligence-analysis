# threat-intelligence-analysis
threat intelligence analysis. Secondary analysis of threat intelligence reports.

The goal of this work is to product an output reports with key data extracted. This data can then be quickly consumed by you internal teams.

## MNC Security Ltd services
MNC Security Ltd provides services that include the analysis of threat intelligence report and the retraction of key data. As part of these services there is an option for the customer to publish these reports to help the wider communities.

## Git hub project content
This secondary analysis output includes the following data types:

### Threat Intelligence Analysis:
Link to original report, name of the report, date
### Executive Summary:
A text description of the original threat intelligence analysis
### Threat Actor:
The adversary attributes
### Tactics and Techniques:
Mitre ATT&CK https://attack.mitre.org/techniques/enterprise/ https://attack.mitre.org/techniques/mobile/ and https://attack.mitre.org/techniques/pre/
### Mitigations:
Mitre ATT&CK https://attack.mitre.org/mitigations/enterprise/ and https://attack.mitre.org/mitigations/mobile/
### Indicators of Compromise:
Inlcudes IP adresses, FQDNs, file hash values, string values
### Detections:
Direct links to SIGMA https://github.com/Neo23x0/sigma YARA https://github.com/Neo23x0/signature-base , Virus Total https://www.virustotal.com/gui/home/search IBM Threat Exchange https://exchange.xforce.ibmcloud.com/ based on identified Indicators of Compromise: section
### Summary:
A text description of the secondary analysis
### Appendix:
A structured collection of the secondary analysis

## Contribution
NMC Security Ltd activity invites the security community to contribute to the effort to extract key data form primary threat analysis; into a structure the is suitable to be imported into enterprise threat models, internal teams or quickly read.

The primary threat intelligence report must be publicly available (linked) within the output or added to the input folder of this repository (Traffic Light Protocol: White).