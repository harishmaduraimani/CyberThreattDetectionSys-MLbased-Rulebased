# 🛡️ Intelligent Cyber Threat Detection System
## 📌 Overview

The **Intelligent Cyber Threat Detection System** is a modular cybersecurity project designed to detect and analyze potential threats such as malware, phishing URLs, network vulnerabilities, and suspicious login behavior.

This system combines:
- 🔍 **Rule-Based Detection**
- 🤖 **Basic Machine Learning Concepts**

to provide a **risk-based analysis** of system security.

## 🎯 Objectives

- Understand core cybersecurity concepts through implementation  
- Build a modular detection engine  
- Simulate real-world cyber threat scenarios  
- Integrate rule-based and intelligent detection methods  

## 🧠 System Architecture
User Input (File / URL / IP / Login)
-
Feature Extraction
-
Rule-Based Detection Layer
-
Machine Learning (Optional)
-
Risk Scoring Engine
-
Final Threat Output
-


---

## 🚀 Features

### 📁 File Malware Detection
- Uses **SHA-256 hashing**
- Detects known malicious files using signature matching  

---

### 🌐 Phishing URL Detection
- Extracts URL features:
  - Length  
  - Special characters  
  - Protocol (HTTP/HTTPS)  
- Identifies suspicious patterns  

---

### 🖥️ Port Scanner
- Scans common ports (21, 22, 80, 443)  
- Detects open ports and potential vulnerabilities  

---

### 🔐 Login Attack Detection
- Monitors login attempts  
- Detects brute-force attacks based on:
  - Attempt count  
  - Failed attempts  

---

### 🧠 Risk Scoring Engine
- Aggregates all module outputs  
- Calculates final risk level:
  - 🟢 Low  
  - 🟡 Medium  
  - 🔴 High  

---
---

## ⚙️ Technologies Used

| Category        | Tools/Technologies |
|----------------|------------------|
| Programming    | Python           |
| Security       | Hashlib (SHA-256)|
| Networking     | Socket           |
| Machine Learning | Scikit-learn (optional) |
| Frontend (Future) | HTML, CSS, JavaScript |
| Backend (Future) | Flask |

---

## 🚀 Installation & Setup

### 1. Clone Repository
git clone <your-repo-link>
cd cyber-threat-system

---

## sample:

⚠️ Phishing Suspected
Open Ports: [80, 443]
⚠️ Malware Detected
⚠️ Brute Force Suspected

FINAL → 🔴 HIGH RISK

## Author
Harish Maduraimani
B.E. Electronics and Communication Engineering
