# Threat Intelligence Analysis
Type | Detail
--- | ---
Ref Link: | The URL of the original Threat Intelligence
Ref Name: | The name of the original Threat Intelligence
Date: | The date of the original Threat Intelligence
# Executive Summary
What the Company or website are known for. Company or website has provided what level of threat intelligence. The target of the threat intelligence. The Executive action or recommendations. The scope of the recommendation based on targeting.
Default text: Information to be confirmed.

---

## Threat Actor
Identify the Threat Actor if possible. Identify the Threat Actor’s attributes
Default text: Information to be confirmed.
Negative Text: The Threat Actor cannot be identified from the threat intelligence.

---

## Tactics and Techniques
A single taxonomy or a combination of all can be used. Then use Tactics as the subheading followed by techniques.
Default text: Information to be confirmed.
Negative Text for Tactic subheadings: No techniques can be identified from the report content.
### PreATT&CK
https://attack.mitre.org/matrices/pre/
### MobileATT&CK
https://attack.mitre.org/matrices/mobile/
### EnterpriseATT&CK
https://attack.mitre.org/matrices/enterprise/
### NSA/CSS Technical Cyber Threat Framework v2
https://www.nsa.gov/Portals/70/documents/what-we-do/cybersecurity/professional-resources/ctr-nsa-css-technical-cyber-threat-framework.pdf

---

## Mitigations
A single security control framework or a combination of all can be used. All mitigations must be preventive security controls. If a mitigation has a default setting of allow/monitor instead of block/prevent it must also be noted. Anti Malware can only be added if the blocking is reliable against per sector campaign and per target campaign and not just the samples (see subsection File Hash) or would have actively blocked wave 1 of any campaign.
Default text: Information to be confirmed.
Negative Text: No Mitigation can be identified from the report content.
### EnterpiseATT&CK
https://attack.mitre.org/mitigations/enterprise/
### MobileATT&CK
https://attack.mitre.org/mitigations/mobile/
### CIS Controls List
https://www.cisecurity.org/controls/cis-controls-list/
### NCSC Cloud Security Principles
https://www.ncsc.gov.uk/collection/cloud-security?curPage=/collection/cloud-security/implementing-the-cloud-security-principles
### UK Cyber Essentials
https://cyberessentials.online/cyber-essentials/
### Australian Government Information Security Manual
https://www.cyber.gov.au/ism
### NIST cyberframework
https://www.nist.gov/cyberframework
### NIST Publications
https://www.nist.gov/publications/search?ta%5B0%5D=248731


---

## Indicators of Compromise
### IP Addresses
The total number of Internet Protocol version 4 or version 6 that has been included in the appendix.
Default text: Information to be confirmed.
Negative Text: No IP address information can be identified from the report content.
### FQDN
The total number of Fully Qualified Domain Name or Domain information that has been included in the appendix.
Default text: Information to be confirmed.
Negative Text: No Domain information can be identified from the report content.
### File Hash
The total number of hash values that has been included in the appendix. 
Default text: Information to be confirmed.
Negative Text: No file hash information can be identified from the report content.
### Strings
The total number of string values that has been included in the appendix.
Default text: Information to be confirmed.
Negative Text: No string information can be identified from the report content.

---

## Detections
All Detections are non preventive security controls. The effectiveness of the detection during the per sector campaign or a per target campaign must be evaluated 
Default text: Information to be confirmed.
Negative Text: Detection can be identified from the report content.

---

## Summary
This is a summary of the original threat intelligence covering all sections.
Default text: Information to be confirmed.

---

## Appendix
This is the primary focus of the secondary analysis. the information is provide in human readable table and machine readable CSV format.
Default text: Information to be completed.
## Appendix Table
Section | Detail | Reference
--- | --- | ---
Executive Summary | NULL | NULL
Threat Actor | name | reference URL
Threat Actor | attribute | reference URL
Tactics and Techniques tactic | techniques or description | reference URL
Mitigation | description | reference
Indicators of Compromise description | Date | detail or reference
Detections description | detall | reference URL
Summary | NULL | NULL

## Appendix CSV
```

Executive Summary, NULL, NULL
Threat Actor, name, reference URL
Threat Actor, attribute, reference URL
Tactics and Techniques tactic, techniques or description, reference URL
Mitigation, description, reference
Indicators of Compromise description, Date, detail or reference
Detections description, detall,  reference URL
Summary, NULL, NULL

