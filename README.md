# Log4Shell-IOCs

Members of the Curated Intelligence Trust Group have compiled a list of IOC feeds and threat reports focused on the recent Log4Shell exploit targeting CVE-2021-44228 in Log4j. ([Blog](https://www.curatedintel.org/2021/08/welcome.html) | [Twitter](https://twitter.com/CuratedIntel) | [LinkedIn](https://www.linkedin.com/company/curatedintelligence/))

#### Analyst Comments:

- 2021-12-13
  - IOCs shared by these feeds are `LOW-TO-MEDIUM CONFIDENCE` we strongly recommend `NOT` adding them to a blocklist
  - These could potentially be used for `THREAT HUNTING` and could be added to a `WATCHLIST`
  - Curated Intel members at various organisations recommend to `FOCUS ON POST-EXPLOITATION ACTIVITY` by threats leveraging Log4Shell (ex. threat actors, botnets)
  - IOCs include JNDI requests (LDAP, but also DNS and RMI), cryptominers, DDoS bots, as well as Meterpreter or Cobalt Strike
  - Critical IOCs to monitor also include attacks using DNS-based exfiltration of environment variables (e.g. keys or tokens), a Curated Intel member shared an [example](https://twitter.com/captainGeech42/status/1470055184449613829)
- 2021-12-14
  - Curated Intel members profiled [active exploitation](https://github.com/curated-intel/Log4Shell-IOCs#threat-profiling) threats
- 2021-12-15
  - Curated Intel members parsed `MEDIUM CONFIDENCE FEEDS` to be `MISP COMPATIBLE` with the help of the [KPMG-Egyde CTI Team](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/KPMG_Log4Shell_Feeds)
  - Curated Intel members profiled active [threat groups (nation states and organized crime)](https://github.com/curated-intel/Log4Shell-IOCs/blob/main/README.md#threat-groups)
- 2021-12-16
  - Curated Intel members confirmed the previously unnamed "[New Ransomware](https://twitter.com/80vul/status/1470272820571963392)" is actually "[TellYouThePass Ransomware](https://www.curatedintel.org/2021/12/tellyouthepass-ransomware-via-log4shell.html)", mostly targeting Chinese infrastructure
- 2021-12-17
  - Curated Intel members parsed `VETTED IOCs` with the help of the [Equinix Threat Analysis Center (ETAC)](https://github.com/curated-intel/Log4Shell-IOCs/blob/main/ETAC_Log4Shell_Analysis/ETAC_Vetted_Log4Shell_IOCs.csv)
  - ETAC has also [shared a diagram](https://github.com/curated-intel/Log4Shell-IOCs/blob/main/ETAC_Log4Shell_Analysis/ETAC_Identified_Threats_Log4Shell.jpg) of threat actors, malware, and botnets, leveraging Log4Shell in the wild
- 2021-12-20
  - ETAC has added [MITRE ATT&CK TTPs](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/ETAC_Log4Shell_Analysis/ETAC_Log4Shell_ThreatActor_TTPs) of Threat Actors leveraging Log4Shell
  - Curated Intel members parsed `ALIENVAULT OTX MENTIONS` to be `MISP COMPATIBLE` with the help of the [KPMG-Egyde CTI Team](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/KPMG_Log4Shell_Feeds/MISP-CSV_AlienVaultOTX_Unfiltered)
- 2021-12-21
  - Curated Intel members parsed `VULNERABLE PRODUCT LISTS` to be `CSV+XLSX COMPATIBLE` with an [automated workflow](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/CI_Log4Shell_Products), pulling from [NCSC-NL](https://raw.githubusercontent.com/NCSC-NL/log4shell/main/software/README.md) + [CISA](https://github.com/cisagov/log4j-affected-db/blob/develop/README.md) + [SwitHak](https://gist.githubusercontent.com/SwitHak/b66db3a06c2955a9cb71a8718970c592/raw/2616607b598f9eba8b82ff14e14022a8de70ca49/20211210-TLP-WHITE_LOG4J.md)
- 2021-12-22
  - Curated Intel members added very basic `FALSE-POSITIVE FILTERING` for [threat hunting feed](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/KPMG_Log4Shell_Feeds) outputs, using selected [MISP warning lists](https://github.com/MISP/misp-warninglists), primarily to remove false-positives of large DNS resolvers (among others)
- 2021-12-29
  - Added Securonix Autonomous Threat Sweep vetted IoC's and TTP's

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
| Juniper Networks (1) | https://blogs.juniper.net/en-us/security/apache-log4j-vulnerability-cve-2021-44228-raises-widespread-concerns |
| Cyble | https://blog.cyble.com/2021/12/13/log4j-rce-0-day-vulnerability-in-java-actively-exploited/ | 
| Securonix | https://github.com/Securonix/AutonomousThreatSweep/tree/main/Log4Shell |

### `Threat Reports`

| Source | Threat | URL |
| --- | --- | --- |
| @GelosSnake | Kinsing | https://twitter.com/GelosSnake/status/1469341429541576715 |
| @an0n_r0| Kinsing | https://twitter.com/an0n_r0/status/1469420399662350336?s=20 |
| @zom3y3 | Muhstik | https://twitter.com/zom3y3/status/1469508032887414784 |
| 360 NetLab (1) | Mirai, Muhstik | https://blog.netlab.360.com/threat-alert-log4j-vulnerability-has-been-adopted-by-two-linux-botnets/ |
| MSTIC (1) | Cobalt Strike | https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/ |
| Cronup | Kinsing, Katana-Mirai, Tsunami-Muhstik | https://twitter.com/1zrr4h/status/1469734728827904002?s=21 |
| Cisco Talos | Kinsing, Mirai | https://blog.talosintelligence.com/2021/12/apache-log4j-rce-vulnerability.html |
| Profero | Kinsing | https://medium.com/proferosec-osm/log4shell-massive-kinsing-deployment-9aea3cf1612d |
| CERT.ch | Kinsing, Mirai, Tsunami | https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/ |
| IronNet | Mirai, Cobalt Strike | https://www.ironnet.com/blog/log4j-new-software-supply-chain-vulnerability-unfolding-as-this-holidays-cyber-nightmare |
| @CuratedIntel | TellYouThePass Ransomware | https://www.curatedintel.org/2021/12/tellyouthepass-ransomware-via-log4shell.html |
| @Laughing_Mantis | Log4j Worm | https://twitter.com/Laughing_Mantis/status/1470168079137067008 |
| Lacework | Kinsing, Mirai | https://www.lacework.com/blog/lacework-labs-identifies-log4j-attackers/ |
| 360 NetLab (2) | Muhstik, Mirai, BillGates (Elknot), XMRig, m8220, SitesLoader, Meterpreter | https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/ |
| Trend Micro | Cobalt Strike, Kirabash, Swrort, Kinsing, Mirai | https://www.trendmicro.com/en_us/research/21/l/patch-now-apache-log4j-vulnerability-called-log4shell-being-acti.html |
| BitDefender | Khonsari Ransomware, Orcus RAT, XMRig, Muhstik | https://businessinsights.bitdefender.com/technical-advisory-zero-day-critical-vulnerability-in-log4j2-exploited-in-the-wild |
| MSTIC (2) | PHOSPHORUS, HAFNIUM, Initial Access Brokers, DEV-0401 | https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/ |
| Cado Security (1) | Mirai, Muhstik, Kinsing | https://www.cadosecurity.com/analysis-of-initial-in-the-wild-attacks-exploiting-log4shell-log4j-cve-2021-44228/ |
| Cado Security (2) | Khonsari Ransomware | https://www.cadosecurity.com/analysis-of-novel-khonsari-ransomware-deployed-by-the-log4shell-vulnerability/ |
| Valtix | Kinsing, Zgrab | https://valtix.com/blog/log4shell-observations/ |
| Fastly | Gafgyt | https://www.fastly.com/blog/new-data-and-insights-into-log4shell-attacks-cve-2021-44228 |
| Check Point | StealthLoader | https://research.checkpoint.com/2021/stealthloader-malware-leveraging-log4shell/ |
| Juniper Networks (2) | XMRig | https://blogs.juniper.net/en-us/threat-research/log4j-vulnerability-attackers-shift-focus-from-ldap-to-rmi |
| AdvIntel | Conti | https://www.advintel.io/post/ransomware-advisory-log4shell-exploitation-for-initial-access-lateral-movement |
| @JakubKroustek | NanoCore RAT | https://twitter.com/JakubKroustek/status/1471621708989837316 |
| MSTIC (3) | Meterpreter, Bladabindi (njRAT), HabitsRAT, Webtoos | https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/#ransomware-update | 
| Cryptolaemus | Dridex, Meterpreter | https://www.bleepingcomputer.com/news/security/log4j-vulnerability-now-used-to-install-dridex-banking-malware/ |
| CyberSoldiers | Dridex | https://github.com/CyberSoldiers/IOCs/blob/main/log4j_IoCs/Dridex_log4j |
| Cluster25 | Dridex | https://github.com/Cluster25/feed/blob/main/log4shell/dridex/ioc |
| FortiGuard | Mirai-based "Worm" | https://www.fortiguard.com/threat-signal-report/4346/mirai-malware-that-allegedly-propagates-using-log4shell-spotted-in-the-wild |
| CyStack | Kworker backdoor | https://cystack.net/research/the-attack-on-onus-a-real-life-case-of-the-log4shell-vulnerability |

### `Payload Examples`

| Source | URL |
| --- | --- |
| GreyNoise (2) | https://gist.github.com/nathanqthai/01808c569903f41a52e7e7b575caa890 |
| Cloudflare | https://blog.cloudflare.com/actual-cve-2021-44228-payloads-captured-in-the-wild/ |
| yt0ng | https://gist.github.com/yt0ng/8a87f4328c8c6cde327406ef11e68726 |
| eromang | https://github.com/eromang/researches/tree/main/CVE-2021-44228 |
| VX-Underground | https://samples.vx-underground.org/samples/Families/Log4J%20Malware/ |
| Malware-Traffic-Analysis (PCAP) | https://www.malware-traffic-analysis.net/2021/12/14/index.html |
| rwincey| https://github.com/rwincey/CVE-2021-44228-Log4j-Payloads |

### `Threat Profiling`
| Threat                    | Type                           | Profile: Malpedia                                                                                                    | Profile: MITRE ATT&CK                                                     | Activity                                                                                                                      |
| ------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Dridex              | Banking Trojan             | [Dridex (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex)     | [Didex, Software S0384](https://attack.mitre.org/software/S0384/)                                                                       | [Command and Control, Tactic TA0011](https://attack.mitre.org/tactics/TA0011/)                                                |
| Cobalt Strike             | Attack tool usage              | [Cobalt Strike (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike) | [Cobalt Strike, Software S0154](https://attack.mitre.org/software/S0154/) | [Command and Control, Tactic TA0011](https://attack.mitre.org/tactics/TA0011/)                                                |
| Meterpreter               | Attack tool usage              | [Meterpreter (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter)     | N/A                                                                       | [Command and Control, Tactic TA0011](https://attack.mitre.org/tactics/TA0011/)                                                |
| Orcus RAT                 | Attack tool usage              | [Orcus RAT (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.orcus_rat)         | N/A                                                                       | [Remote Access Software, Technique T1219](https://attack.mitre.org/techniques/T1219/)                                                |
| NanoCore RAT              | Attack tool usage              | [NanoCore RAT (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.nanocore)       | [NanoCore, Software S0336](https://attack.mitre.org/software/S0336/)      | [Remote Access Software, Technique T1219](https://attack.mitre.org/techniques/T1219/)                                                |
| njRAT / Bladabindi              | Attack tool usage              | [njRAT (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat)       | [njRAT, Software S0385](https://attack.mitre.org/software/S0385/)      | [Remote Access Software, Technique T1219](https://attack.mitre.org/techniques/T1219/)                                                |
| HabitsRAT             | Attack tool usage              | [HabitsRAT (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.habitsrat)       | N/A     | [Remote Access Software, Technique T1219](https://attack.mitre.org/techniques/T1219/)                                                |
| BillGates / Elknot        | Botnet expansion (DDoS)        | [BillGates (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.billgates)         | N/A                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005](https://attack.mitre.org/techniques/T1583/005/)                     |
| Bashlite (aka Gafgyt)     | Botnet expansion (DDoS)        | [Bashlite (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite)           | N/A                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005](https://attack.mitre.org/techniques/T1583/005/)                     |
| Mirai (AKA Katana)        | Botnet expansion (DDoS, miner) | [Mirai (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai)                 | N/A                                                                       | [Acquire Infrastructure: Botnet, Sub-technique T1583.005](https://attack.mitre.org/techniques/T1583/005/)                     |
| Muhstik (AKA Tsunami)     | Botnet expansion (DDoS, miner) | [Tsunami (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.tsunami)             | N/A                                                                       | [Resource Hijacking, Technique T1496](https://attack.mitre.org/techniques/T1496/)                                             |
| Kinsing                   | Botnet expansion (miner)       | [Kinsing (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/elf.kinsing)             | [Kinsing, Software S0599](https://attack.mitre.org/software/S0599/)       | [Resource Hijacking, Technique T1496](https://attack.mitre.org/techniques/T1496/)                                             |
| m8220                     | Botnet expansion (miner)       | N/A                                                                                                                  | N/A                                                                       | [Resource Hijacking, Technique T1496](https://attack.mitre.org/techniques/T1496/)                                             |
| Swrort                    | Downloader usage (stager)      | [Swrort Stager (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/ps1.swrort)        | N/A                                                                       | [Ingress Tool Transfer, Technique T1105](https://attack.mitre.org/techniques/T1105/)                                          |
| SitesLoader               | Downloader usage (stager)      | N/A                                                                                                                  | N/A                                                                       | [Ingress Tool Transfer, Technique T1105](https://attack.mitre.org/techniques/T1105/)                                          |
| Kirabash                  | Infostealer usage              | N/A                                                                                                                  | N/A                                                                       | [OS Credential Dumping: /etc/passwd and /etc/shadow, Sub-technique T1003.008](https://attack.mitre.org/techniques/T1003/008/) |
| XMRig                     | Mining tool usage              | N/A                                                                                                                  | N/A                                                                       | [Resource Hijacking, Technique T1496](https://attack.mitre.org/techniques/T1496/)                                             |
| Zgrab                     | Network scanner tool usage     | N/A                                                                                                                  | N/A                                                                       | [Network Service Scanning, Technique T1046](https://attack.mitre.org/techniques/T1046/)                                       |
| TellYouThePass Ransomware | Ransomware usage               | N/A                                                                                                                  | N/A                                                                       | [Data Encrypted for Impact, Technique T1486](https://attack.mitre.org/techniques/T1486/)                                      |
| Khonsari Ransomware       | Ransomware usage               | N/A                                                                                                                  | N/A                                                                       | [Data Encrypted for Impact, Technique T1486](https://attack.mitre.org/techniques/T1486/)                                      |
| Conti Ransomware          | Ransomware usage               | [Conti (Malware Family) (fraunhofer.de)](https://malpedia.caad.fkie.fraunhofer.de/details/win.conti)                 | [Conti, Software S0575](https://attack.mitre.org/software/S0575/)         | [Data Encrypted for Impact, Technique T1486](https://attack.mitre.org/techniques/T1486/)                                      |
| NightSky Ransomware       | Ransomware usage               | N/A | N/A        | [Data Encrypted for Impact, Technique T1486](https://attack.mitre.org/techniques/T1486/)                                      |

### `Threat Groups`
| Grouping        | Actor | Mentioned Alias | Other Alias [EternalLiberty](https://github.com/StrangerealIntel/EternalLiberty/blob/main/EternalLiberty.csv)                                 | Threat Report                                                                                                                                          | Note                                                                                                                                                                                                          |
| --------------- | ----- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| State actor    | China | HAFNIUM         | N/A                                                                                                                                                         | [MSTIC (2)](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/) | Attacking infrastructure to extend their typical targeting. In these attacks, HAFNIUM-associated systems were observed using a DNS service typically associated with testing activity to fingerprint systems. |
| State actor | Iran  | PHOSPHORUS      | APT35, TEMP.Beanie, TA 453, NewsBeef, CharmingKitten, G0003, CobaltIllusion, TG-2889, Timberworm, C-Major, Group 41, Tarh Andishan, Magic Hound, Newscaster | [MSTIC (2)](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/) | Iranian actor that has been deploying ransomware, acquiring and making modifications of the Log4j exploit.                                                                                                    |
| Organized Cybercrime | Russia | Wizard Spider | Trickbot Gang, FIN12, GOLD BLACKBURN, Grim Spider | [AdvIntel](https://www.advintel.io/post/ransomware-advisory-log4shell-exploitation-for-initial-access-lateral-movement) | Wizard Spider is the developer of the Conti Ransomware-as-a-Service (RaaS) operation which has a high number of affiliates, and a Conti affiliate has leveraged Log4Shell in Log4j2 in the wild |
| Organized Cybercrime | Russia | EvilCorp | Indrik Spider, GOLD DRAKE | [Cryptolaemus](https://www.bleepingcomputer.com/news/security/log4j-vulnerability-now-used-to-install-dridex-banking-malware/) | EvilCorp are the developers of the Dridex Trojan, which began life as a banking malware but has since shifted to support the delivery of ransomware, which has included BitPaymer, DoppelPaymer, Grief, and WastedLocker, among others. Dridex is now being dropped following the exploitation of vulnerable Log4j instances |
| State actor | China | Aquatic Panda | N/A | [CrowdStrike](https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/) | AQUATIC PANDA is a China-based targeted intrusion adversary with a dual mission of intelligence collection and industrial espionage. It has likely operated since at least May 2020. AQUATIC PANDA operations have primarily focused on entities in the telecommunications, technology and government sectors. AQUATIC PANDA relies heavily on Cobalt Strike, and its toolset includes the unique Cobalt Strike downloader tracked as FishMaster. AQUATIC PANDA has also been observed delivering njRAT payloads to targets. |
| Ransomware Operator | China | DEV-0401 | N/A | [MSTIC (2)](https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/) | Attackers started exploiting the CVE-2021-44228 vulnerability in internet-facing systems running VMware Horizon. An investigation shows that successful intrusions in these campaigns led to the deployment of the NightSky ransomware. These attacks are performed by a China-based ransomware operator that MSTIC is tracking as DEV-0401. DEV-0401 has previously deployed multiple ransomware families including LockFile, AtomSilo, and Rook, and has similarly exploited Internet-facing systems running Confluence (CVE-2021-26084) and on-premises Exchange servers (CVE-2021-34473). |
