# Blue Team Investigations Portfolio

This repository documents my practical experience in Digital Forensics and Incident Response (DFIR). The following projects demonstrate my methodology for investigating security incidents ranging from social engineering to network compromise and endpoint malware.

*Note: To comply with platform integrity rules, this portfolio outlines the investigative process and tools used but does not disclose specific flags or raw answers.*

---

## Project 1: Phishing Analysis
**Platform:** Blue Team Labs Online
**Challenge:** Phishing Analysis 2
**Validation:** [View Achievement](https://blueteamlabs.online/achievement/share/challenge/137983/24)

### Scenario
Investigation of a reported suspicious email targeting corporate credentials. The objective was to analyze raw email artifacts to identify the sender, the attack vector, and indicators of compromise (IOCs).

### Methodology
* **Environment Isolation:** Conducted all analysis within a secure virtual machine (Kali Linux) to prevent accidental execution of malicious payloads.
* **Header Analysis:** Inspected SMTP headers using text editors to trace the `Received` chain and identify the true originating IP address.
* **Payload De-obfuscation:** Identified Base64 encoding within the email body. Decoded the content to reveal the hidden HTML structure.
* **IOC Extraction:** Located the malicious "Call to Action" button in the HTML code and extracted the obfuscated URL used for credential harvesting (typosquatting domain).

---

## Project 2: Network Forensics
**Platform:** Blue Team Labs Online
**Challenge:** Network Analysis - Web Shell
**Validation:** [View Achievement](https://blueteamlabs.online/achievement/share/challenge/137983/12)

### Scenario
Forensic analysis of a packet capture (.pcap) file following a web server compromise. The goal was to reconstruct the attack path and determine the scope of the breach.

### Methodology
* **Traffic Filtering:** Used Wireshark to isolate HTTP and TCP traffic originating from suspicious IP addresses.
* **Reconnaissance Detection:** Identified a TCP SYN scan pattern by analyzing port sequencing and flag behavior.
* **Tool Identification:** Analyzed HTTP User-Agent strings to identify specific vulnerability scanning tools used by the attacker (e.g., Gobuster).
* **Attack Reconstruction:** Followed TCP streams to observe the upload of a malicious web shell. Decoded the HTTP requests to identify the commands executed by the attacker on the server (Command Injection).

---

## Project 3: Endpoint Forensics
**Platform:** Blue Team Labs Online
**Challenge:** Browser Forensics - Cryptominer
**Validation:** [View Achievement](https://blueteamlabs.online/achievement/share/challenge/137983/2)

### Scenario
Investigation of an endpoint experiencing severe performance degradation. The hypothesis was unauthorized cryptojacking activity via a browser-based vector.

### Methodology
* **Database Inspection:** Utilized DB Browser for SQLite to parse browser profile data, specifically the `History` and `Extensions` databases.
* **Artifact Correlation:** Correlated timestamped browsing history with the installation time of browser extensions.
* **Threat Identification:** Identified a specific malicious extension associated with a known cryptomining domain.
* **Signature Verification:** Calculated the extension's unique identifier and hash to confirm its malicious nature against threat intelligence sources.
