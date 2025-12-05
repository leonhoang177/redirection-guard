# 🛡️ Redirection Guard – Chrome Extension

**Redirection Guard** is a lightweight, AI-powered browser extension designed to detect and block redirect-based phishing attempts in real time.  
This extension is part of a larger research project focused on improving web security through intelligent redirection monitoring.

---

## 🚀 Installation & Setup Guide

Follow these steps to set up and load the extension in Chrome:

### 1️⃣ Clone the Entire Project

```bash
git clone https://github.com/<your-username>/redirection-guard.git
cd redirection-guard/extensionV5
```

### 2️⃣ Install pnpm (if not already installed)

You’ll need **pnpm** to manage dependencies efficiently.  
Install it globally using npm:

```bash
npm install -g pnpm
```

### 3️⃣ Install Dependencies

Use **pnpm** to install all required packages:

```bash
pnpm install
```

### 4️⃣ Build the Extension

Compile the TypeScript code and bundle files for production:

```bash
pnpm run build
```

### 5️⃣ Load the Extension into Chrome

1. Open **Google Chrome**.
2. Navigate to **chrome://extensions/**.
3. Enable **Developer mode** (top-right corner).
4. Click **“Load unpacked”**.
5. Select the **`extension`** folder from the cloned project.

### 6️⃣ Use the Extension

Once loaded, the **Redirection Guard** icon will appear in your Chrome toolbar.  
Click it to open the popup and start monitoring redirects in real time.

---

## 📝 Notes

- Ensure you’ve built the extension before loading it in Chrome.
- Rebuild using `pnpm run build` after any source code updates.
- The extension runs fully locally — no browsing data is sent externally.

---

## 📜 License

This project is licensed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.

---

## 🤝 Acknowledgements

Developed by **Leon Hoang**, **Sid**, and **Mike**.
Supervised by **Dr. Doowon Kim**, University of Tennessee, Knoxville.

Special thanks to the open-source community and the maintainers of **PhishTank**, **Tranco**, and **VirusTotal** APIs for supporting cybersecurity research.

---
