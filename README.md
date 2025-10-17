# ⚙️ Redirection Guard – Chrome Extension

This directory contains the **Redirection Guard Chrome Extension**, a lightweight browser tool designed to detect and block redirect-based phishing attempts in real time.

---

## 🚀 Installation & Setup Guide

Follow the steps below to set up and load the extension into Chrome:

### 1️⃣ Clone the Entire Project

```bash
git clone https://github.com/<your-username>/redirection-guard.git
cd redirection-guard/extension
```

### 2️⃣ Install pnpm (if not already installed)

You’ll need **pnpm** to manage the workspace efficiently.  
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

Compile the TypeScript and bundle the files:

```bash
pnpm run build
```

### 5️⃣ Load the Extension into Chrome

1. Open **Google Chrome**.
2. Go to **chrome://extensions/**.
3. Enable **Developer mode** (top-right corner).
4. Click **“Load unpacked”**.
5. Select the **`extension`** folder from the cloned project.

### 6️⃣ Use the Extension

Once loaded, you’ll see the **Redirection Guard** icon in your Chrome toolbar.  
Click it to open the popup and start protecting your browsing session.

---

## 🧠 Notes

- Make sure you’ve built the extension before loading it.
- Rebuild (`pnpm run build`) after any code changes.
- The extension operates fully locally — no data is sent externally.

---

## 🧩 Folder Overview

```
extension/
├─ src/              # Source code (TypeScript)
├─ assets/           # Model and icons
├─ dist/             # Compiled build output
├─ manifest.json     # Chrome extension manifest (MV3)
└─ README.md         # Setup and usage guide
```

---

## 🛡️ Project

Part of the **Redirection Guard** research project by **Leon Hoang** and collaborators under the supervision of **Dr. Doowon Kim**, University of Tennessee.

---
