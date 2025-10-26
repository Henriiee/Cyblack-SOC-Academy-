# Email & Phishing Analysis Sprint – Microsoft Impersonation Attack

This repository presents our **Email Phishing Investigation & Forensics** project, conducted during the **CyBlack SOC Academy Internship (Sprint 3)**.  
It demonstrates how we analyzed a **Microsoft impersonation phishing email**, validated authentication mechanisms, and identified attacker infrastructure using real-world SOC techniques.

---

## 🔍 Project Overview
The investigation focused on an email impersonating Microsoft’s Account Team.  
Our team analyzed email headers, verified **SPF**, **DKIM**, and **DMARC** authentication, and performed threat intelligence lookups to trace the true sending infrastructure.  
Findings revealed a spoofed domain, complete authentication failures, and an IP address linked to a known **malicious host in Germany**.

---

## 🧠 Key Highlights
- **SPF, DKIM, and DMARC** authentication checks failed — confirming spoofing  
- IP geolocation linked to **GHOSTNET GmbH**, a known malicious hosting provider  
- Identified **social engineering elements** and **credential harvesting intent**  
- Developed a **quantitative risk score** model (classified as *Critical Risk*)  

---

## 🧰 Tools & Techniques
- **Sublime Text** – for raw header parsing  
- **AbuseIPDB & WHOIS** – for threat validation  
- **DMARC Analyzer** – for authentication failure checks  
- **Manual Risk Scoring Framework** – for impact analysis  

---

## 🧩 Repository Contents
| File | Description |
|------|--------------|
| [`presentation/Email_Phishing_Investigation_&_Forensics.pdf`](./Email_Phishing_Investigation_&_Forensics.pdf) | Presentation slides used during project defense |
| [`POC/images`](./POC) | Screenshots of key analysis stages (SPF failure, IP trace, WHOIS results) |

---

## 🧭 Methodology (Proof of Concept)

### 1. Email Header Extraction
The phishing email was analyzed by extracting raw headers and viewing them in **Sublime Text** to identify routing paths and metadata such as:
- Return-Path  
- Received-SPF results  
- Authentication-Results (SPF, DKIM, DMARC)  
- Source IP and Message-ID  

---

### 2. Authentication Check
Each authentication mechanism was inspected for validation:

| Protocol | Result | Observation |
|-----------|---------|-------------|
| SPF | Fail | Sender IP not authorized by microsoft.com |
| DKIM | Fail | No valid DKIM signature present |
| DMARC | Fail | Domain policy not aligned with Microsoft |

Failures across all three authentication checks confirmed that the email did not originate from Microsoft’s infrastructure.

---

### 3. IP and Domain Analysis
The sending IP was traced using **WHOIS** and **IP geolocation** tools.  
It originated from a **German hosting provider (GHOSTNET GmbH)** known for malicious campaigns.  
We further verified this using **AbuseIPDB**, which confirmed the IP was blacklisted and associated with spam and phishing behavior.

---

### 4. Risk Assessment
We applied a **quantitative risk model** to evaluate the phishing threat based on:
- Authentication failures  
- Source reputation  
- Attack intent (credential theft)  

The attack was classified as **Critical Risk**, with a confidence score of over 95%.

---

### 5. Visual Proof (Screenshots)
Supporting evidence can be found in the [`POC/images`](./POC) folder:
- SPF/DKIM/DMARC failure snapshots  
- WHOIS lookup results  
- Blacklist verification on AbuseIPDB  
- Risk scoring model visualization  

---

## 🎓 Supporting Certifications
Completed relevant courses on [Let's Defend](https://letsdefend.io/):
- Malware Analysis Fundamentals  
- Phishing Email Analysis  
- Investigate Web Attack  

---

## ⚖️ Copyright & Usage
© 2025 CyBlack SOC Academy Team 3 (Co-owned by Henrietta Coker and Team Members).  
This repository is shared for **educational and portfolio purposes only**.  
No part of this content may be reused, modified, or redistributed without written permission from all co-owners.

---

## 🧩 Acknowledgment
Special thanks to **CyBlack SOC Academy** for mentorship and guidance throughout this project and for providing a platform to develop practical SOC and forensic analysis skills.

