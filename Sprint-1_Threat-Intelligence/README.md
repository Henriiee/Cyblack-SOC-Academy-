#  Threat Intelligence Task – StealBit Malware Analysis

This repository contains the results of my Threat Intelligence group task, where I led a team to identify, analyze, and report a malicious file hash linked to the **StealBit malware**, an exfiltration tool used by the **LockBit ransomware group**.

---

##  Project Overview
As **Group Leader**, I coordinated the team, delegated responsibilities, and consolidated findings into both a detailed report and presentation slides for management review.

We analyzed 31 file hashes to identify malicious activity and discovered one infected sample associated with **StealBit**, known for data theft and supporting ransomware operations.

---

##  Key Objectives
- Identify malicious hashes using **VirusTotal** and Python scripting.  
- Investigate the **StealBit malware** and its link to the LockBit ransomware group.  
- Document findings in a **Threat Intelligence Report** and **executive presentation**.  
- Practice structured team coordination and report preparation.  

---

##  Steps Taken
1. Used `check_hashes.py` to analyze all 31 hashes through the **VirusTotal API**.  
2. Identified one malicious hash associated with **StealBit**.  
3. Researched StealBit’s behavior, role in ransomware attacks, and LockBit operations.  
4. Drafted a **YARA rule** for potential detection.  
5. Developed a **PowerPoint presentation** summarizing our findings and recommendations.  

---

##  Key Findings
- **Malware Identified:** StealBit (Data Exfiltration Tool).  
- **Associated Threat Group:** LockBit Ransomware.  
- **Category:** Data Theft / Exfiltration Malware used in Ransomware Campaigns.  
- **Malicious SHA-256 Hash:** `107d9fce05ff8296d0417a5a830d180cd46aa120ced8360df3ebfd15cb550636`  

---

##  Skills and Tools
- **Tools:** VirusTotal, Python, YARA, PowerPoint, PDF Reporting  
- **Skills Gained:** Threat analysis, IOC investigation, reporting, leadership, presentation design  

---

##  Learning References
I also deepened my understanding of SOC operations and threat intelligence through **LetsDefend** courses:
- IT Security Basic for Corporate  
- VirusTotal for SOC Analyst  
- How to Investigate a SIEM Alert  
- Cyber Threat Intelligence  

---

##  Files Included
| Folder | Description |
|---------|--------------|
| `/presentation` | Executive Summary Presentation |
| `/scripts` | Python script used for hash scanning |
| `/iocs` | Indicators of Compromise  |

---

##  Summary
This project enhanced my understanding of **cyber threat analysis**, **malware behavior**, and **executive reporting** while strengthening my **team leadership and communication** skills in a cybersecurity context.

