# Threat Intelligence Analysis
Ref Link: https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Ref Name: NCSC_Trickbot_Brief_User_Guide.pdf
Date: 27th September 2018
# Executive Summary
Although the National Cyber Security Center (NCSC) provide security advice to UK citizens, small, medium, large enterprises and Government, this busy readers guide’s target audience is unclear as it includes mitigations only within the capability of large enterprises and Government. What is clear is Tickbot is a serious threat and it is recommended that everyone reviews their security controls and verifies that they are effective.
---
## Threat Actor
The threat actors that use the trickbot malware have not been directly identified within the report. Several targets have been identified and the primary mission has been identified as accessing online accounts including banking. A secondary mission has been alluded to as identity fraud, which will not be included in the appendix, due to the uses weak wording; in this case "can".
---
## Tactics and Techniques
### Initial Access
Although well crafted email based phishing has been identified within the report, Spearphishing Link, Spearphishing Attachment or Spearphishing via Service has not been directly identified. When cross referencing known Trickbot techniques Spearphishing attachment has the highest probability of the initial access technique and has therefore been added to the appendix.
### Execution
No techniques can be identified from the report content.
### Command and control
Although connections over the Internet was in the report no protocols were identified, when cross referencing with other known analysis of trickbot both Standard Application Layer Protocol and Commonly Used Port have been identified and therefore added to the appendix.
### Credential Access
The statement “Steal sensitive information, including banking login details and memorable 
information, by manipulating web-browsing sessions”, bullet points “Steal saved online account passwords, cookies and web history” and “Steal login credentials for infected devices”;  has been analysed as Credentials from Web Browsers.
### Discovery
Although the System Service Discovery technique was not directly identified in the report, it has been crossed referenced and added to the appendix, as known technique from within the discovery tactic
### Persistence
No techniques can be identified from the report content.
### Defense Evasion
No techniques can be identified from the report content.
### Privilege Escalation
No techniques can be identified from the report content.
### Lateral Movement
Although the term “Spread by infecting other devices on the victim’s network” is included in the report, the only lateral movement techniques directly identified was Remote File Copy to download “Remote Access Tools, VNC clients, or ransomware” and Web Session Cookie.
### Collection
No techniques can be identified from the report content.
### Exfiltration
No techniques can be identified from the report content.
### Impact
No techniques can be identified from the report content.
---
## Mitigations
Several direct links to NCSC own published guidance is included in the report and has therefore been included in the appendix, but the analysis of these link to identify mitigations are out of scope. Mitigations that can be retracted from the report are Execution Prevention (whitelisting), Antivirus/Antimalware, Update Software, Network Segmentation, Multi-factor Authentication.In addition Network Intrusion Prevention has been identified form security monitoring capability (analyse network intrusions).
## Indicators of Compromise: inlcudes IP adresses, FQDNs, file hash values, string values
### IP Addresses
No IoC of this type identified in the report.
### FQDN
No IoC of this type identified in the report.
### File Hash
No IoC of this type identified in the report.
### Strings
No IoC of this type identified in the report.
---
## Detections
No detections identified in the report.
## Summary: at text description of the sencondary analysis
Several mitigations were in fact incident response, these included; “consider changing passwords”,”review bank and credit card statements for suspicious activity” and “Advise any employees who have accessed online banking facilities from the affected network to do likewise”. No new techniques can be added to the understanding of Trickbot from this report. Few mitigations identified are effective against wave 1 of a new threat actor campaign or not within the defense capability of known targets i.e “.. small and medium sized businesses, and individuals”. The mitigation of Antivirus/Antimalware can not be evaluated against per target or campaign wave targat list as no sample file has been identified.
===
# Appendix
## Appendix Table
Section | Detail | Reference
--- | --- | ---
Executive Summary | NULL | NULL
Threat Actor | Targets small businesses. | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor | Targets medium sized businesses. | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor | Targets individuals. | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor | Targets Personally Identifiable Information (PII). | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor | Targets online accounts. | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor | Targets online bank accounts | https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Tactics and Techniques | Trickbot Primary Mitre ATT&CK Ref | https://attack.mitre.org/software/S0266/
Tactics and Techniques initial access | Spearphishing attachment | https://attack.mitre.org/techniques/T1193/
Tactics and Techniques command and control | Commonly Used Port | https://attack.mitre.org/techniques/T1043/
Tactics and Techniques command and control | Standard Application Layer Protocol | https://attack.mitre.org/techniques/T1071/
Tactics and Techniques collection | Man in the Browser | https://attack.mitre.org/techniques/T1185/
Tactics and Techniques discovery | System Information Discovery | https://attack.mitre.org/techniques/T1082/
Tactics and Techniques discovery | System Network Configuration Discovery |https://attack.mitre.org/techniques/T1016/
Tactics and Techniques discovery | System Service Discovery | https://attack.mitre.org/techniques/T1007/
Tactics and Techniques credential access | Credentials from Web Browsers | https://attack.mitre.org/techniques/T1503/
Tactics and Techniques lateral movement | Remote File Copy | https://attack.mitre.org/techniques/T1105/
Tactics and Techniques lateral movement | Web Session Cookie | https://attack.mitre.org/techniques/T1506/
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/mitigating-malware 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/preventing-lateral-movement  
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/10-steps-network-security 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/10-steps-monitoring 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/eud-security-guidance-windows-10-1709 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/macro-securitymicrosoft-office 
Mitigation | Referenced link | https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services 
Mitigation | Execution Prevention | https://attack.mitre.org/mitigations/M1038/
Mitigation | Antivirus/Antimalware | https://attack.mitre.org/mitigations/M1049/
Mitigation | Update Software | https://attack.mitre.org/mitigations/M1051/
Mitigation | Network Segmentation | https://attack.mitre.org/mitigations/M1030/
Mitigation | Multi-factor Authentication | https://attack.mitre.org/mitigations/M1032/
Mitigation | Network Intrusion Prevention | https://attack.mitre.org/mitigations/M1031/
Indicators of Compromise  IP Addresses | NULL | NULL
Indicators of Compromise FQDN | NULL | NULL
Indicators of Compromise File HASH | NULL | NULL
Indicators of Compromise String | NULL | NULL
Detections | NULL | NULL
Summary | NULL NULL
## Appendix CSV
```

Section, Detail, Reference
Executive Summary, NULL, NULL
Threat Actor, Targets small businesses., https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor, Targets medium sized businesses., https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor, Targets individuals., https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor, Targets Personally Identifiable Information (PII)., https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor, Targets online accounts., https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Threat Actor, Targets online bank accounts, https://www.ncsc.gov.uk/news/trickbot-banking-trojan
Tactics and Techniques, Trickbot Primary Mitre ATT&CK Ref, https://attack.mitre.org/software/S0266/
Tactics and Techniques initial access, Spearphishing attachment, https://attack.mitre.org/techniques/T1193/
Tactics and Techniques command and control, Commonly Used Port, https://attack.mitre.org/techniques/T1043/
Tactics and Techniques command and control, Standard Application Layer Protocol, https://attack.mitre.org/techniques/T1071/
Tactics and Techniques collection, Man in the Browser, https://attack.mitre.org/techniques/T1185/
Tactics and Techniques discovery, System Information Discovery, https://attack.mitre.org/techniques/T1082/
Tactics and Techniques discovery, System Network Configuration Discovery,https://attack.mitre.org/techniques/T1016/
Tactics and Techniques discovery, System Service Discovery, https://attack.mitre.org/techniques/T1007/
Tactics and Techniques credential access, Credentials from Web Browsers, https://attack.mitre.org/techniques/T1503/
Tactics and Techniques lateral movement, Remote File Copy, https://attack.mitre.org/techniques/T1105/
Tactics and Techniques lateral movement, Web Session Cookie, https://attack.mitre.org/techniques/T1506/
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/mitigating-malware 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/preventing-lateral-movement  
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/10-steps-network-security 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/10-steps-monitoring 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/eud-security-guidance-windows-10-1709 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/macro-securitymicrosoft-office 
Mitigation, Referenced link, https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services 
Mitigation, Execution Prevention, https://attack.mitre.org/mitigations/M1038/
Mitigation, Antivirus/Antimalware, https://attack.mitre.org/mitigations/M1049/
Mitigation, Update Software, https://attack.mitre.org/mitigations/M1051/
Mitigation, Network Segmentation, https://attack.mitre.org/mitigations/M1030/
Mitigation, Multi-factor Authentication, https://attack.mitre.org/mitigations/M1032/
Mitigation, Network Intrusion Prevention, https://attack.mitre.org/mitigations/M1031/
Indicators of Compromise  IP Addresses, NULL, NULL
Indicators of Compromise FQDN, NULL, NULL
Indicators of Compromise File HASH, NULL, NULL
Indicators of Compromise String, NULL, NULL
Detections, NULL, NULL
Summary, NULL, NULL

```