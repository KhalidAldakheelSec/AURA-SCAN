# ⚡ AURA SCAN — Universal Security Scanner

> A lightweight desktop tool for detecting sensitive data leaks and security threats inside local files and folders.
---

## 📌 What is AURA SCAN?

AURA SCAN is a Python-based cybersecurity desktop application that scans local files and folders for exposed sensitive data such as API keys, hardcoded passwords, database credentials, and phishing indicators — using Regular Expressions (Regex) for pattern matching.

Built for developers and security enthusiasts who want to quickly audit their projects before sharing or deploying them.

---

## ✅ Features

- 🔍 Scan a single file or an entire folder recursively
- 🎯 17 built-in threat detection patterns
- 🔴🟡🟢 Severity classification (High / Medium / Low)
- ⚡ Real-time progress bar during scanning
- 🔎 File extension filter (e.g. `.py`, `.js`, `.env`)
- 🧹 Live severity filter (toggle results without rescanning)
- 💾 Export results as `.txt` or `.csv` report
- 📊 Sortable results table
- 🖥️ Dark-themed GUI built with CustomTkinter

---

## 🎯 Detected Threats

**🔴 High**
AWS Access Key, AWS Secret Key, Google API Key, OpenAI API Key, GitHub Token, Stripe Secret Key, Hardcoded Passwords, Database URLs, Telegram Bot Token, Private Key Blocks

**🟡 Medium**
JWT Tokens, Hardcoded Secret Variables, Suspicious Lookalike Domains, Phishing Language

**🟢 Low**
IP-Based URLs, Email Addresses, Internal Network IPs

---

## 🚀 Usage

### Option 1 — Run directly
Download `Aura_Scan.exe` from Releases and run it. No installation needed.

### Option 2 — Run from source
```bash
pip install customtkinter
python Aura_Scan.py
```

---

## ⚠️ Disclaimer

This tool is intended for educational and personal use only.
Use it only on files and projects you own or have explicit permission to audit.

---

## 👤 Author
**Khalid Aldakheel**
github.com/KhalidAldakheelSec
