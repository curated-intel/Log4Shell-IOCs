# Log4Shell-IOCs

Members of the Curated Intelligence Trust Group have compiled a list of IOC feeds and threat reports focused on the recent Log4Shell exploit targeting CVE-2021-44228 in Log4j

#### Analyst Comments:

- 2021-12-13
  - IOCs shared by these feeds are `LOW-TO-MEDIUM CONFIDENCE` we strongly recommend `NOT` adding them to a blocklist
  - These could potentially be used for `THREAT HUNTING` and could be added to a `WATCHLIST`
  - Curated Intel members at various organisations recommend to `FOCUS ON POST-EXPLOITATION ACTIVITY` by threats leveraging Log4Shell (ex. threat actors, botnets)
  - IOCs include JNDI requests (LDAP, but also DNS and RMI), cryptominers, DDoS bots, as well as Meterpreter or Cobalt Strike
  - Critical IOCs to monitor also include attacks using DNS-based exfiltration of environment variables (e.g. keys or tokens) - see [here](https://twitter.com/captainGeech42/status/1470055184449613829)
- 2021-12-14
  - Curated Intel members profiled active exploitation threats
- 2021-12-15
  - Curated Intel members parsed `MEDIUM CONFIDENCE FEEDS` to be `MISP COMPATIBLE` using [KPMG's MISP implementation](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/Threat%20Hunt%20Feed%20-%20Medium%20Confidence)

### `Indicators of Compromise (IOCs)`
| Source | URL |
| --- | --- |
| GreyNoise (1) | https://gist.github.com/gnremy/c546c7911d5f876f263309d7161a7217 |
| Malwar3Ninja's GitHub | https://github.com/Malwar3Ninja/Exploitation-of-Log4j2-CVE-2021-44228/blob/main/Threatview.io-log4j2-IOC-list |
| Tweetfeed.live by @0xDanielLopez | https://twitter.com/0xdaniellopez/status/1470029308152487940?s=21 |
| Azure Sentinel | https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv |
| URLhaus | https://urlhaus.abuse.ch/browse/tag/log4j/ |
| Malware Bazaar | https://bazaar.abuse.ch/browse/tag/log4j/ |
| ThreatFox | https://threatfox.abuse.ch/browse/tag/log4j/ |
| Cronup | https://github.com/CronUp/Malware-IOCs/blob/main/2021-12-11_Log4Shell_Botnets |
| RedDrip7 | https://github.com/RedDrip7/Log4Shell_CVE-2021-44228_related_attacks_IOCs |
| AbuseIPDB | `Google/Bing Dorks`  site:abuseipdb.com "log4j", site:abuseipdb.com "log4shell", site:abuseipdb.com "jndi" |
| CrowdSec | https://gist.github.com/blotus/f87ed46718bfdc634c9081110d243166 |
| Andrew Grealy, CTCI | https://docs.google.com/spreadsheets/d/e/2PACX-1vT1hFu_VlZazvc_xsNvXK2GJbPBCDvhgjfCTbNHJoP6ySFu05sIN09neV73tr-oYm8lo42qI_Y0whNB/pubhtml# |
| Bad Packets | https://twitter.com/bad_packets/status/1469225135504650240 |
| NCSC-NL | https://github.com/NCSC-NL/log4shell/tree/main/iocs |
| Costin Raiu, Kaspersky | https://twitter.com/craiu/status/1470341085734051840?s=21 |
| Kaspersky | https://securelist.com/cve-2021-44228-vulnerability-in-apache-log4j-library/105210/ |
| SANS Internet Storm Center | https://isc.sans.edu/diary/Log4Shell+exploited+to+implant+coin+miners/28124 |
| @cyber__sloth | https://twitter.com/cyber__sloth/status/1470353289866850305?s=21 |
| SuperDuckToes | https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8 |
| Nozomi Networks | https://www.nozominetworks.com/blog/critical-log4shell-apache-log4j-zero-day-attack-analysis/ |
| Miguel Jiménez | https://hominido.medium.com/iocs-para-log4shell-rce-0-day-cve-2021-44228-98019dd06f35 |
| CERT Italy | https://cert-agid.gov.it/download/log4shell-iocs.txt |
| RISKIQ | https://community.riskiq.com/article/57abbfcf/indicators |
| Infoblox | https://blogs.infoblox.com/cyber-threat-intelligence/cyber-campaign-briefs/log4j-exploit-harvesting/ |
| Juniper Networks | https://blogs.juniper.net/en-us/security/apache-log4j-vulnerability-cve-2021-44228-raises-widespread-concerns |

### `Threat Reports`
| Threat                | Type                           | Profile: Malpedia                                                                                                    | Profile: MITRE ATT&CK                                                                     | Activity                                                                                                                                                   |
| --------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cobalt Strike         | Attack tool usage              | [Cobalt Strike (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike) | [Cobalt Strike, Software S0154 - MITRE ATT&CK®](https://attack.mitre.org/software/S0154/) | [Command and Control, Tactic TA0011 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/tactics/TA0011/)                                                |
| Orcus RAT             | Attack tool usage              | [Orcus RAT (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.orcus_rat)         | N/A                                                                                       | [Command and Control, Tactic TA0011 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/tactics/TA0011/)                                                |
| Meterperter           | Attack tool usage              | [Meterpreter (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter)     | N/A                                                                                       | [Command and Control, Tactic TA0011 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/tactics/TA0011/)                                                |
| BillGates / Elknot    | Botnet expansion (DDoS)        | [BillGates (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.billgates)         | N/A                                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1583/005/)                     |
| Bashlite (aka Gafgyt) | Botnet expansion (DDoS)        | [Bashlite (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite)           | N/A                                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1583/005/)                     |
| Mirai (AKA Katana)    | Botnet expansion (DDoS, miner) | [Mirai (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai)                 | N/A                                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1583/005/)                     |
| Muhstik (AKA Tsunami) | Botnet expansion (DDoS, miner) | [Tsunami (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.tsunami)             | N/A                                                                                       | [Resource Hijacking, Technique T1496 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1496/)                                             |
| Kinsing               | Botnet expansion (miner)       | [Kinsing (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.kinsing)             | [Kinsing, Software S0599 - MITRE ATT&CK®](https://attack.mitre.org/software/S0599/)       | [Resource Hijacking, Technique T1496 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1496/)                                             |
| m8220                 | Botnet expansion (miner)       | N/A                                                                                                                  | N/A                                                                                       | [Resource Hijacking, Technique T1496 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1496/)                                             |
| Swrort                | Downloader usage (stager)      | [Swrort Stager (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/ps1.swrort)        | N/A                                                                                       | [Ingress Tool Transfer, Technique T1105 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1105/)                                                                                        |
| SitesLoader           | Downloader usage (stager)      | N/A                                                                                                                  | N/A                                                                                       | [Ingress Tool Transfer, Technique T1105 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1105/)                                          |
| Kirabash              | Infostealer usage              | N/A                                                                                                                  | N/A                                                                                       | [OS Credential Dumping: /etc/passwd and /etc/shadow, Sub-technique T1003.008 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1003/008/) |
| XMRig                 | Mining tool usage              | N/A                                                                                                                  | N/A                                                                                       | [Resource Hijacking, Technique T1496 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1496/)                                             |
| Zgrab                 | Network scanner tool usage     | N/A                                                                                                                  | N/A                                                                                       | [Network Service Scanning, Technique T1046 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1046/)                                       |
| New Ransomware        | Ransomware usage               | N/A                                                                                                                  | N/A                                                                                       | [Data Encrypted for Impact, Technique T1486 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1486/)                                      |
| Khonsari Ransomware   | Ransomware usage               | N/A                                                                                                                  | N/A                                                                                       | [Data Encrypted for Impact, Technique T1486 - Enterprise - MITRE ATT&CK®](https://attack.mitre.org/techniques/T1486/)                                      |
