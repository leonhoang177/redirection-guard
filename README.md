# 🛡️ Redirection Guard

> A lightweight, AI-powered Chrome extension and scanning toolkit designed to detect malicious web redirects and phishing attempts in real time.

---

## 🚀 Setup & Installation

Updating...

---

## 🧠 System Architecture

The **Redirection Guard** system follows a modular pipeline designed for scalability and transparency:

```
User Interface → Redirection Monitor → Threat Detector → Apply Policy
```

This flow enables proactive detection of redirect-based phishing threats, ensuring each browser navigation is analyzed, classified, and handled according to defined security policies.

---

## ⚙️ Components

- **🌍 URL Scanner:**  
  A TypeScript-based utility that gathers, enriches, and normalizes URL metadata from trusted sources (e.g., VirusTotal, PhishTank, Tranco). It outputs structured datasets for model training and validation.

- **🧩 Chrome Extension:**  
  A lightweight Manifest V3 browser extension that performs real-time redirect monitoring and phishing risk assessment directly within the user’s browser. It provides instant alerts and safe-browsing recommendations.

- **🤖 Machine Learning Model:**  
  Developed using **Google Colab**, this model learns from both lexical and metadata-based URL features to predict malicious redirections with high precision. Exported artifacts integrate seamlessly into the extension for offline inference.

---

## 📜 License

MIT License © 2025 Ethical-Phishers Team

---

## 🤝 Acknowledgements

- Developed by **Leon, Mike, and Patel**
- Supervisor: **Dr. Doowon Kim**, Assistant Professor at the University of Tennessee, Knoxville.
- Special thanks to open-source communities supporting web security research and to the maintainers of PhishTank, Tranco, and VirusTotal APIs.

---
