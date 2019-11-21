# Threat Intelligence Analysis
Type | Detail
--- | --- 
Ref Link: | https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Ref Name: | a-look-into-fysbis-sofacys-linux-backdoor
Date: | 12th February 2016
# Executive Summary
Unit 42 has provided a technical analysis of APT28/Sofacy Linux command and control agent and highlighted a capability the includes Apple devices. As identified in the report APT28/Sofacy targets government and defense with zero-day exploits to both Java and Microsoft Office applications, with the initial access vectors likely to be Spearphishing attachment, Drive-by Compromise or Exploit Public-Facing Application. It is therefore recommend that if you are within the target profile security control relating to Linux, MacOS and Apple iOS be verified as effective.

---

## Threat Actor
The threat actor has been clearly identified in the report and included in the appendix as APT28. Several threat actor attributes have also been identified with the “with focus on” elements being included in the appendix.Targets included government, defense and various Eastern European government.The “integrating legitimate company references” has also been added as the command and control FQDN, connections demonstrate.

---

## Tactics and Techniques
### PreATT&CK
Buy domain name was identified in the report and added to the appendix.
### Initial Access
Spear-phishing attacks with zero-day exploits of Java or Microsoft Office and “compromising legitimate websites to stage watering-hole attacks” has resulted in Spearphishing attachment, Exploit Public-Facing Application and Drive-by Compromise being added to the appendix.
### Execution
Native binaries are executed from the command and control agent and therefore Command-Line Interface has been added to the appendix.
### Command and control
This report clearly identifies Standard Application Layer Protocol and Commonly Used Port and therefore they have added to the appendix.
### Credential Access
The keylogging screenshot has been analysed as Input Capture and added to the appendix.
### Discovery
Local reconnaissance to determine which flavor of Linux the malware is running has been analysed as System Information Discovery and added to the appendix.
### Persistence
The statement “This is followed by a number of Linux shell command style commands related to the malware establishing persistence” and the “mkdir /usr/lib/sys-defender” command lines are included in the report. With additional cross references the Systemd services technique has been added to the appendix 
### Defense Evasion
No techniques can be identified from the report content.
### Privilege Escalation
No techniques can be identified from the report content.
### Lateral Movement
No techniques can be identified from the report content.
### Collection
No techniques can be identified from the report content.
### Exfiltration
No techniques can be identified from the report content.
### Impact
No techniques can be identified from the report content.

---

## Mitigations
Palo Alto's Intrusion Prevention System rule, which has been included in the appendix.

---

## Indicators of Compromise
### IP Addresses
Four IPv4 addresses have been identified in the report and included in the appendix.
### FQDN
Three domains have been identified in the report and included in the appendix.
### File Hash
Nine hash values from three files have been identified in the report and included in the appendix. In addition the hash value ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91, which was Submitted to virustotal on 2019-11-11 10:17:42 has also been included in the appendix
### Strings
Although several screenshots includes the execution of code they have not been added to the appendix due to the required effort. As there are three samples available under the File Hash sections, it is recommended the any required deep analysis starts there. The two command line strings have been extracted and included in the appendix.

--- 

## Detections
Several positive detection has been included in the appendix from virus total and the corresponding yara-rule. The IP and FQDN entries have been included from xforce exchange, but is unlikely any of them would have meet alerting thresholds during the active campaign..

--- 

## Summary
Several detections and a single vendor specific mitigation is included in this report. This report has also been use in the Mitre ATT&CK framework as a reference of Fysbis. As there has been a recent submission the virus total which suggests this remote control agent is still being used in 2919.

--- 

# Appendix
## Appendix Table
Section | Detail | Reference
--- | --- | ---
Executive Summary | NULL | NULL
Threat Actor | ATP28 | https://attack.mitre.org/groups/G0007/
Threat Actor | Targets defense | https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor | Targets government | https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor | Targets Eastern European government | https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor | integrating legitimate company references | https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Tactics and Techniques | Fysbis Primary Mitre Ref | https://attack.mitre.org/software/S0410/
Tactics and Techniques | Buy domain name | https://attack.mitre.org/techniques/T1328/
Tactics and Techniques Initial access | Spearphishing attachment | https://attack.mitre.org/techniques/T1193/
Tactics and Techniques Initial access | Drive-by Compromise | https://attack.mitre.org/techniques/T1189/
Tactics and Techniques Initial access | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/
Tactics and Techniques execution | Command-Line Interface | https://attack.mitre.org/techniques/T1059/
Tactics and Techniques command and control | Commonly Used Port | https://attack.mitre.org/techniques/T1043/
Tactics and Techniques command and control | Standard Application Layer Protocol | https://attack.mitre.org/techniques/T1071/
Tactics and Techniques discovery | System Information Discovery | https://attack.mitre.org/techniques/T1082/
Tactics and Techniques credential access | Input Capture | https://attack.mitre.org/techniques/T1056/
Tactics and Techniques persistent | Systemd service | https://attack.mitre.org/techniques/T1501/
Mitigation | Palo Alto networks IPS signature | 14917
Indicators of Compromise  IP Addresses | Date 2015 | 198.105.125.74
Indicators of Compromise  IP Addresses | Date 2014 | 193.169.244.190
Indicators of Compromise  IP Addresses | Date 2014 | 111.90.148.148
Indicators of Compromise  IP Addresses | Date 2015 | 104.207.130.126
Indicators of Compromise FQDN | Date 2014 | azureon-line.com
Indicators of Compromise FQDN | Date 2015 | mozilla-plugins.com
Indicators of Compromise FQDN | Date 2015 | Mozillaplagins.com
Indicators of Compromise File HASH | MD5 | 364ff454dcf00420cff13a57bcb78467
Indicators of Compromise File HASH | SHA-256 | 8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb
Indicators of Compromise File HASH | ssdeep | 3072:n+1R4tREtGN4qyGCXdHPYK9l0H786O26BmMAwyWMn/qwwiHNl:n+1R43QcILXdF0w6IBmMAwwCwwi
Indicators of Compromise File HASH | MD5 | 075b6695ab63f36af65f7ffd45cccd39
Indicators of Compromise File HASH | SHA-256 | 02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592
Indicators of Compromise File HASH | ssdeep | 3072:9ZAxHANuat3WWFY9nqjwbuZf454UNqRpROIDLHaSeWb3LGmPTrIW33HxIajF:9ZAxHANJAvbuZf454UN+rveQLZPTrV3Z
Indicators of Compromise File HASH | MD5 | e107c5c84ded6cd9391aede7f04d64c8
Indicators of Compromise File HASH | SHA-256 | fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61
Indicators of Compromise File HASH | ssdeep | 6144:W/D5tpLWtr91gmaVy+mdckn6BCUdc4mLc2B9:4D5Lqgkcj+
Indicators of Compromise File HASH | SHA-252 | ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91
Indicators of Compromise String | Command line | "ls /etc "pipe" egrep -e"fedora*"pipe"debian*"pipe"gentoo*"pipe"mandriva*"pipe"mandrake*"pipe"meego*"pipe"redhat*"pipe"lsb-*|sun-*"pipe"SUSE*"pipe"release""
Indicators of Compromise String | Command line | mkdir /usr/lib/sys-defender
Detections xforce exchange | 198.105.125.74 | https://exchange.xforce.ibmcloud.com/ip/198.105.125.74
Detections xforce exchange | 193.169.244.190 | https://exchange.xforce.ibmcloud.com/ip/193.169.244.190
Detections xforce exchange | 111.90.148.148 | https://exchange.xforce.ibmcloud.com/ip/111.90.148.148
Detections xforce exchange | 104.207.130.126 | https://exchange.xforce.ibmcloud.com/ip/104.207.130.126
Detections xforce exchange | azureon-line.com | https://exchange.xforce.ibmcloud.com/url/azureon-line.com
Detections xforce exchange | mozilla-plugins.com | https://exchange.xforce.ibmcloud.com/url/mozilla-plugins.com
Detections xforce exchange | Mozillaplagins.com | https://exchange.xforce.ibmcloud.com/url/Mozillaplagins.com
Detections virustotal | 364ff454dcf00420cff13a57bcb78467 | https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/detection
Detections virustotal | 8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb | https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/details
Detections virustotal | 3072:n+1R4tREtGN4qyGCXdHPYK9l0H786O26BmMAwyWMn/qwwiHNl:n+1R43QcILXdF0w6IBmMAwwCwwi | https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/details
Detections virustotal | e107c5c84ded6cd9391aede7f04d64c8 | ttps://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal | 02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592 | https://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal | 3072:9ZAxHANuat3WWFY9nqjwbuZf454UNqRpROIDLHaSeWb3LGmPTrIW33HxIajF:9ZAxHANJAvbuZf454UN+rveQLZPTrV3Z | https://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal | e107c5c84ded6cd9391aede7f04d64c8 https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal | fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61 | https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal | 6144:W/D5tpLWtr91gmaVy+mdckn6BCUdc4mLc2B9:4D5Lqgkcj+ | https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal | ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91 |https://www.virustotal.com/gui/file/ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91/detection
Detections yara-rules | APT_Sofacy_Fysbis.yar | https://github.com/Yara-Rules/rules/blob/master/malware/APT_Sofacy_Fysbis.yar
Summary | NULL |NULL

## Appendix CSV
```

Executive Summary, NULL, NULL
Threat Actor, ATP28, https://attack.mitre.org/groups/G0007/
Threat Actor, Targets defense, https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor, Targets government, https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor, Targets Eastern European government, https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Threat Actor, integrating legitimate company references, https://unit42.paloaltonetworks.com/a-look-into-fysbis-sofacys-linux-backdoor/
Tactics and Techniques, Fysbis Primary Mitre Ref, https://attack.mitre.org/software/S0410/
Tactics and Techniques, Buy domain name, https://attack.mitre.org/techniques/T1328/
Tactics and Techniques Initial access, Spearphishing attachment, https://attack.mitre.org/techniques/T1193/
Tactics and Techniques Initial access, Drive-by Compromise, https://attack.mitre.org/techniques/T1189/
Tactics and Techniques Initial access, Exploit Public-Facing Application, https://attack.mitre.org/techniques/T1190/
Tactics and Techniques execution, Command-Line Interface, https://attack.mitre.org/techniques/T1059/
Tactics and Techniques command and control, Commonly Used Port, https://attack.mitre.org/techniques/T1043/
Tactics and Techniques command and control, Standard Application Layer Protocol, https://attack.mitre.org/techniques/T1071/
Tactics and Techniques discovery, System Information Discovery, https://attack.mitre.org/techniques/T1082/
Tactics and Techniques credential access, Input Capture, https://attack.mitre.org/techniques/T1056/
Tactics and Techniques persistent, Systemd service, https://attack.mitre.org/techniques/T1501/
Mitigation, Palo Alto networks IPS signature, 14917
Indicators of Compromise  IP Addresses, Date 2015, 198.105.125.74
Indicators of Compromise  IP Addresses, Date 2014, 193.169.244.190
Indicators of Compromise  IP Addresses, Date 2014, 111.90.148.148
Indicators of Compromise  IP Addresses, Date 2015, 104.207.130.126
Indicators of Compromise FQDN, Date 2014, azureon-line.com
Indicators of Compromise FQDN, Date 2015, mozilla-plugins.com
Indicators of Compromise FQDN, Date 2015, Mozillaplagins.com
Indicators of Compromise File HASH, MD5, 364ff454dcf00420cff13a57bcb78467
Indicators of Compromise File HASH, SHA-256, 8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb
Indicators of Compromise File HASH, ssdeep, 3072:n+1R4tREtGN4qyGCXdHPYK9l0H786O26BmMAwyWMn/qwwiHNl:n+1R43QcILXdF0w6IBmMAwwCwwi
Indicators of Compromise File HASH, MD5, 075b6695ab63f36af65f7ffd45cccd39
Indicators of Compromise File HASH, SHA-256, 02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592
Indicators of Compromise File HASH, ssdeep, 3072:9ZAxHANuat3WWFY9nqjwbuZf454UNqRpROIDLHaSeWb3LGmPTrIW33HxIajF:9ZAxHANJAvbuZf454UN+rveQLZPTrV3Z
Indicators of Compromise File HASH, MD5, e107c5c84ded6cd9391aede7f04d64c8
Indicators of Compromise File HASH, SHA-256, fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61
Indicators of Compromise File HASH, ssdeep, 6144:W/D5tpLWtr91gmaVy+mdckn6BCUdc4mLc2B9:4D5Lqgkcj+
Indicators of Compromise File HASH, SHA-252, ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91
Indicators of Compromise String, Command line, "ls /etc | egrep -e"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release""
Indicators of Compromise String, Command line, mkdir /usr/lib/sys-defender
Detections xforce exchange, 198.105.125.74, https://exchange.xforce.ibmcloud.com/ip/198.105.125.74
Detections xforce exchange, 193.169.244.190, https://exchange.xforce.ibmcloud.com/ip/193.169.244.190
Detections xforce exchange, 111.90.148.148, https://exchange.xforce.ibmcloud.com/ip/111.90.148.148
Detections xforce exchange, 104.207.130.126, https://exchange.xforce.ibmcloud.com/ip/104.207.130.126
Detections xforce exchange, azureon-line.com, https://exchange.xforce.ibmcloud.com/url/azureon-line.com
Detections xforce exchange, mozilla-plugins.com, https://exchange.xforce.ibmcloud.com/url/mozilla-plugins.com
Detections xforce exchange, Mozillaplagins.com, https://exchange.xforce.ibmcloud.com/url/Mozillaplagins.com
Detections virustotal, 364ff454dcf00420cff13a57bcb78467, https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/detection
Detections virustotal, 8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb, https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/details
Detections virustotal, 3072:n+1R4tREtGN4qyGCXdHPYK9l0H786O26BmMAwyWMn/qwwiHNl:n+1R43QcILXdF0w6IBmMAwwCwwi, https://www.virustotal.com/gui/file/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb/details
Detections virustotal, e107c5c84ded6cd9391aede7f04d64c8, https://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal, 02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592, https://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal, 3072:9ZAxHANuat3WWFY9nqjwbuZf454UNqRpROIDLHaSeWb3LGmPTrIW33HxIajF:9ZAxHANJAvbuZf454UN+rveQLZPTrV3Z, https://www.virustotal.com/gui/file/02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592/detection
Detections virustotal, e107c5c84ded6cd9391aede7f04d64c8, https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal, fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61, https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal, 6144:W/D5tpLWtr91gmaVy+mdckn6BCUdc4mLc2B9:4D5Lqgkcj+, https://www.virustotal.com/gui/file/fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61/detection
Detections virustotal, ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91, https://www.virustotal.com/gui/file/ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91/detection
Detections yara-rules, APT_Sofacy_Fysbis.yar, https://github.com/Yara-Rules/rules/blob/master/malware/APT_Sofacy_Fysbis.yar
Summary, NULL, NULL

```