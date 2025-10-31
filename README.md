🛡️ File Integrity & Malware Scanner
A Python-powered static analysis tool for safe USB and file triage

Built to simulate how real-world forensics teams scan, classify, and verify digital evidence — without executing a single file.

🔍 Key Features

Recursive Scanning – Walks through every directory and file automatically.

Risk Classification – Flags files as CLEAN, SUSPICIOUS, or UNKNOWN.

Colorized CLI Output – Clear, easy-to-read terminal reports.

JSON Report Generation – All results stored in a clean, structured format.

Digital Signing (ECDSA) – Each report is signed for integrity verification.

Report Verification Tool – Detects any tampering post-scan.

🧠 Why This Matters (Cybersecurity Relevance)

This project introduces:

Static Malware Analysis — Investigating file metadata safely.

Digital Forensics Workflow — Logging evidence and ensuring report integrity.

Public-Key Cryptography — Real ECDSA signing + verification.

Practical Security Engineering — Color-coded triage, structured data, verifiable output.

⚙️ Tech Stack
Component	Purpose
Python 3.10+	Core scripting language
colorama	Terminal color formatting
cryptography	Digital signatures (ECDSA)
mimetypes	File type recognition
json, os	File I/O and data handling
🧾 Usage
# 1. Scan files
python3 scanner.py <directory_to_scan> <output_report.json>

# 2. Verify report authenticity
python3 verify_report.py <output_report.json>

🧩 Learning Outcomes

Build a forensic-style scanner that simulates early-stage malware detection.

Understand how signatures protect integrity in cybersecurity workflows.

Learn structured reporting, an essential skill for SOC analysts and malware researchers.

💡 Next Steps / Enhancements

🧬 File hashing (SHA-256)

🧰 Integration with YARA rules

🧩 Basic web dashboard (Flask)

🔒 File quarantine for flagged samples

👨‍💻 Author

Tanjot — Student at MIET
Exploring cybersecurity by building real-world tools, one script at a time.

🚀 2️⃣ LinkedIn Post Template (for maximum visibility)

Copy-paste this when you post your project — it’s written for attention, clarity, and credibility 👇

🛡️ Built My First Cybersecurity Tool — File Integrity & Malware Scanner!

This Python project simulates the forensic triage process used by cybersecurity teams — scanning USBs or folders safely without executing files.

🔍 What it does:

Recursively scans every file in a directory

Classifies them as CLEAN, SUSPICIOUS, or UNKNOWN

Generates a digitally signed JSON report (ECDSA) to ensure integrity

Verifies signatures to detect tampering

⚙️ Tech Stack: Python, Colorama, Cryptography (ECDSA), Mimetypes, JSON

💡 Built this to strengthen my fundamentals in:

Static malware analysis

Digital forensics workflows

Cryptographic integrity verification

Next steps:
→ Add SHA-256 hashing
→ Integrate YARA rules for deeper file inspection

Repo: 🔗 [GitHub.com/<Tanjot-Singh>/File-Integrity-Scanner]
#CyberSecurity #Python #Forensics #MalwareAnalysis #CyberForensics #InfoSec #StudentProjects
