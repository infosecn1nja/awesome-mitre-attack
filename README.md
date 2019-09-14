# Awesome Mitre ATT&CK™ Framework

> <img width="250" src="https://assets-global.website-files.com/5bc662b786ecfc12c8d29e0b/5bfdce88cd3820f7c5c21e02_mitre.png"/>

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> A curated list of awesome resources related to Mitre ATT&CK™ Framework


## Contents
- [Red and Purple Team](#red-and-purple-team)
  - [Resources](#resources)
  - [Tools](#tools)
    - [Red Team](#red-team)
    - [Purple Team](#purple-team)
    - [Adversary Emulation](#adversary-emulation)
- [Threat Hunting](#threat-hunting)
  - [Resources](#resources-1)
  - [Tools](#tools-1)
- [Threat Intelligence](#threat-intelligence)
  - [Resources](#resources-2)
  - [Tools](#tools-2)
- [Community](#community)  
------

## Red and Purple Team
### Resources
- [MITRE ATT&CK™ Evaluations Round 1 - APT3](https://attackevals.mitre.org/methodology/round1/)
- [Getting Started with ATT&CK: Adversary Emulation and Red Teaming](https://medium.com/mitre-attack/getting-started-with-attack-red-29f074ccf7e3)
- [Adversary Emulation Plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
- [The Threat Emulation Problem](https://blog.cobaltstrike.com/2016/02/17/the-threat-emulation-problem/)
- [Why we love threat emulation exercises (and how to get started with one of your own)](https://expel.io/blog/why-we-love-threat-emulation-exercises/)
- [MITRE ATT&CKcon 2018: From Automation to Analytics: Simulating the Adversary to Create Better Detections, David Herrald and Ryan Kovar, Splunk](https://www.slideshare.net/attackcon2018/mitre-attckcon-2018-from-automation-to-analytics-simulating-the-adversary-to-create-better-detections-david-herrald-and-ryan-kovar-splunk)
- [Living Off The Land Binaries and Scripts (and also Libraries)](https://lolbas-project.github.io/)
- [Purple Teaming with Vectr, Cobalt Strike, and MITRE ATT&CK](https://www.digitalshadows.com/blog-and-research/purple-teaming-with-vectr-cobalt-strike-and-mitre-attck/)
- [Red Team Use of MITRE ATT&CK](https://medium.com/@malcomvetter/red-team-use-of-mitre-att-ck-f9ceac6b3be2)
- [Purple Teaming with ATT&CK - x33fcon 2018](https://www.slideshare.net/ChristopherKorban/purple-teaming-with-attck-x33fcon-2018)
- [Live Adversary Simulation: Red and Blue Team Tactics](https://www.rsaconference.com/writable/presentations/file_upload/hta-t06_live_adversary_simulation-red_and_blue_team_tactics.pdf)
- [MITRE ATT&CKcon 2018: Playing Devil’s Advocate to Security Initiatives with ATT&CK, David Middlehurst, Trustwave](https://www.slideshare.net/attackcon2018/mitre-attckcon-2018-playing-devils-advocate-to-security-initiatives-with-attck-david-middlehurst-trustwave)
- [MITRE ATT&CKcon 2018: From Red VS Blue to Red ♥ Blue, Olaf Hartong and Vincent Van Mieghem, Deloitte](https://www.slideshare.net/attackcon2018/mitre-attckcon-2018-from-red-vs-blue-to-red-blue-olaf-hartong-and-vincent-van-mieghem-deloitte)
- [PowerShell for Practical Purple Teaming](https://www.slideshare.net/nikhil_mittal/powershell-for-practical-purple-teaming)
- [Signal the ATT&CK: Part 1](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-1.html)
- [Signal the ATT&CK: Part 2](https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/signal-att-and-ck-part-2.html)

### Tools

#### Red Team
- [Cobalt Strike](https://www.cobaltstrike.com/) - Software for Adversary Simulations and Red Team Operations
- [PoshC2](https://github.com/nettitude/PoshC2_Python) - PoshC2 is a proxy aware C2 framework that utilises Powershell and/or equivalent (System.Management.Automation.dll) to aid penetration testers with red teaming, post-exploitation and lateral movement. 
- [Empire](https://github.com/EmpireProject/Empire) - Post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent.
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/) - Collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment.
- [Invoke-PSImage](https://github.com/peewpw/Invoke-PSImage) - Invoke-PSImage takes a PowerShell script and embeds the bytes of the script into the pixels of a PNG image.

#### Purple Team
- [RE:TERNAL](https://github.com/d3vzer0/reternal-quickstart) - RE:TERNAL is a centralised purple team simulation platform. Reternal uses agents installed on a simulation network to execute various known red-teaming techniques in order to test blue-teaming capabilities.
- [Purple Team ATT&CK Automation](https://github.com/praetorian-inc/purple-team-attack-automation) - Praetorian's public release of our Metasploit automation of MITRE ATT&CK™ TTPs
- [VECTR](https://github.com/SecurityRiskAdvisors/VECTR) - VECTR is a tool that facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios
- [Mordor](https://github.com/Cyb3rWard0g/mordor) - The Mordor project provides pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files for easy consumption. 

#### Adversary Emulation

- [MITRE CALDERA](https://github.com/mitre/caldera) - CALDERA is an automated adversary emulation system, built on the MITRE ATT&CK™ framework.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Small and highly portable detection tests based on MITRE's ATT&CK.
- [Metta](https://github.com/uber-common/metta) - An information security preparedness tool to do adversarial simulation.
- [Red Team Automation (RTA)](https://github.com/endgameinc/RTA) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.

------

## Threat Hunting
### Resources
- [MITRE ATT&CKcon 2018: Hunters ATT&CKing with the Data, Roberto Rodriguez, SpecterOps and Jose Luis Rodriguez, Student](https://www.slideshare.net/attackcon2018/mitre-attckcon-2018-hunters-attcking-with-the-data-robert-rodriguez-specterops-and-jose-luis-rodriguez-student)
- [Testing the Top MITRE ATT&CK Techniques: PowerShell, Scripting, Regsvr32](https://redcanary.com/blog/testing-the-top-mitre-attck-techniques-powershell-scripting-regsvr32/)
- [Ten Ways Zeek Can Help You Detect the TTPs of MITRE ATT&CK](https://m.youtube.com/watch?v=DfTbSc_q2F8)
- [SEC1244 - Cops and Robbers: Simulating the Adversary to Test Your Splunk Security Analytics](https://static.rainfocus.com/splunk/splunkconf18/sess/1522696002986001hj1a/finalPDF/Simulating-the-Adversary-Test-1244_1538791048709001YJnK.pdf)
- [Mapping your Blue Team to MITRE ATT&CK™](https://www.siriussecurity.nl/blog/2019/5/8/mapping-your-blue-team-to-mitre-attack)
- [Quantify Your Hunt: Not Your Parent’s Red Teaming Redux](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536351477.pdf)
- [Post-Exploitation Hunting with ATT&CK & Elastic](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1533071345.pdf)
- [ThreatHunter-Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook)
- [How MITRE ATT&CK helps security operations](https://www.slideshare.net/votadlos/how-mitre-attck-helps-security-operations)
- [MITRE Cyber Analytics Repository](https://car.mitre.org/)
- [MITRE ATT&CK Windows Logging Cheat Sheets](https://github.com/MalwareArchaeology/ATTACK)
- [Defensive Gap Assessment with MITRE ATT&CK](https://www.cybereason.com/blog/defensive-gap-assessment-with-mitre-attck)
- [Prioritizing the Remediation of Mitre ATT&CK Framework Gaps](https://blog.netspi.com/prioritizing-the-remediation-of-mitre-attck-framework-gaps/)
- [Finding Related ATT&CK Techniques](https://medium.com/mitre-attack/finding-related-att-ck-techniques-f1a4e8dfe2b6)
- [Getting Started with ATT&CK: Detection and Analytics](https://medium.com/mitre-attack/getting-started-with-attack-detection-a8e49e4960d0)
- [2019 Threat Detection Report](https://redcanary.com/resources/guides/threat-detection-report/)
- [A Process is No One : Hunting for Token Manipulation](https://specterops.io/assets/resources/A_Process_is_No_One.pdf)

#### Tools
- [osquery-attck](https://github.com/teoseller/osquery-attck) - Mapping the MITRE ATT&CK Matrix with Osquery
- [ATTACKdatamap](https://github.com/olafhartong/ATTACKdatamap) - A datasource assessment on an event level to show potential coverage or the MITRE ATT&CK framework
- [Splunk Mitre ATT&CK App](https://github.com/olafhartong/ThreatHunting) - A Splunk app mapped to MITRE ATT&CK to guide your threat hunts
- [auditd-attack](https://github.com/bfuzzy1/auditd-attack/tree/master/auditd-attack) - A Linux Auditd rule set mapped to MITRE's Attack Framework
- [DeTTACT](https://github.com/rabobank-cdc/DeTTACT) - DeTT&CT aims to assist blue teams using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours.
- [HELK](https://github.com/Cyb3rWard0g/HELK) - A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
- [Sigma](https://github.com/Neo23x0/sigma) - Generic Signature Format for SIEM Systems
- [atomic-threat-coverage](https://github.com/krakow2600/atomic-threat-coverage) - Automatically generated actionable analytics designed to combat threats based on MITRE's ATT&CK.
- [CyberMenace](https://github.com/PM0ney/CyberMenace) - A one stop shop hunting app in Splunk that can ingest Zeek, Suricata, Sysmon, and Windows event data to find malicious indicators of compromise relating to the MITRE ATT&CK Matrix.
- [Wayfinder](https://github.com/egaus/wayfinder) - Artificial Intelligence Agent to extract threat intelligence TTPs from feeds of malicious and benign event sources and automate threat hunting activities.
- [pyattck](https://github.com/swimlane/pyattck) - A python package to interact with the Mitre ATT&CK Framework. You can find documentation [here](https://pyattck.readthedocs.io/en/latest/)

------

## Threat Intelligence
### Resources
- [FIRST CTI Symposium: Turning intelligence into action with MITRE ATT&CK™](https://www.slideshare.net/KatieNickels/first-cti-symposium-turning-intelligence-into-action-with-mitre-attck)
- [Getting Started with ATT&CK: Threat Intelligence](https://medium.com/mitre-attack/getting-started-with-attack-cti-4eb205be4b2f)
- [Using ATT&CK to Advance Cyber Threat Intelligence — Part 1](https://medium.com/mitre-attack/using-att-ck-to-advance-cyber-threat-intelligence-part-1-c5ad14d59724)
- [Using ATT&CK to Advance Cyber Threat Intelligence — Part 2](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/using-attck-to-advance-cyber-threat-0)
- [ATT&CKing the Status Quo: ThreatBased Adversary Emulation with MITRE
ATT&CK™](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1536260992.pdf)

### Tools
- [cti](https://github.com/mitre/cti) - Cyber Threat Intelligence Repository expressed in STIX 2.0
- [TALR](https://github.com/SecurityRiskAdvisors/TALR) - A public repository for the collection and sharing of detection rules in STIX format. 

## Community
- [EU ATT&CK Community](https://www.attack-community.org/)
- [MITRE ATT&CKcon 2018](https://attack.mitre.org/resources/attackcon/)
------

## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, Rahmat Nurfauzi &#34;@infosecn1nja&#34; has waived all copyright and related or neighboring rights to this work.
