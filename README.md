🛡️ Intelligent Cyber Threat Detection System
 Overview
This project is a cybersecurity detection system that identifies potential threats such as malware, phishing URLs, network vulnerabilities and suspicious login activity. It combines rule-based techniques with basic machine learning concepts to analyze inputs and generate a risk score.

🎯 Features
📁 File Malware Detection
Uses hashing (SHA-256) to detect suspicious files
🌐 Phishing URL Detection
Analyzes URL patterns and features
🖥️ Port Scanner
Identifies open ports and possible vulnerabilities
🔐 Login Attack Detection
Detects brute-force login attempts
🧠 Risk Scoring Engine
Combines all results into a final risk level
Output: Low / Medium / High

🧱 Project Structure
cyber-threat-system/
│
├── main.py
├── detectors/
│   ├── file_detector.py
│   ├── url_detector.py
│   ├── port_detector.py
│   ├── login_detector.py
│
├── risk_engine.py
├── logs.txt

⚙️ Technologies Used
Python
Hashlib (for hashing)
Socket (for network scanning)
Basic Machine Learning (Scikit-learn - optional)

🚀 How to Run
1. Clone the repository
git clone <your-repo-link>
cd cyber-threat-system
2. Install dependencies
pip install -r requirements.txt
3. Run the project
python main.py

🧪 Example Inputs
URL: http://secure-login-bank.xyz
IP: 127.0.0.1
Login Attempts: 10
Failed Attempts: 8

📊 Output Example
⚠️ Phishing Suspected
Open Ports: [80, 443]
⚠️ Malware Detected
⚠️ Brute Force Suspected

FINAL → 🔴 HIGH RISK
🧠 Concepts Covered
Hashing (SHA-256)
Network Security (Ports, IP)
Threat Detection
Basic AI/ML Concepts
Secure System Design

⚠️ Limitations
Uses simple rule-based detection
Cannot detect zero-day attacks
Limited dataset for ML

🔮 Future Improvements
Add advanced ML models
Real-time network monitoring
Web-based dashboard (Flask + HTML/JS)
Cloud deployment

👨‍💻 Author
Harish Maduraimani
