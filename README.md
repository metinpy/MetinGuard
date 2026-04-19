# 🛡️ CyberEye v6.1 - The Total Fortress

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?logo=python&logoColor=white" alt="Python Version"/>
  <img src="https://img.shields.io/badge/Aiogram-3.x-green.svg?logo=telegram&logoColor=white" alt="Aiogram"/>
  <img src="https://img.shields.io/badge/Playwright-Async-orange.svg?logo=playwright&logoColor=white" alt="Playwright"/>
  <img src="https://img.shields.io/badge/AI-Gemini_1.5_Flash-purple.svg?logo=google&logoColor=white" alt="Gemini AI"/>
</div>
<br>

**CyberEye** is an autonomous **Telegram Cyber Security Bot** that integrates advanced artificial intelligence and cyber threat intelligence tools, primarily focusing on protecting e-commerce platforms and users against phishing and malware distribution.

It analyzes suspicious websites sent by users in a secure virtual sandbox, evaluates the findings using AI, and automatically reports detected phishing/fraud pages to the national response center (**USOM**) and the relevant hosting provider via automated abuse emails.

---

## 🌟 Key Features

### 🧠 AI-Powered Social Engineering Analysis (Gemini 1.5)
By analyzing the source code and visible text of the website, it detects "Social Engineering" tactics. It identifies if the site creates a false sense of urgency or promises fake rewards/giveaways, generating a concise professional summary of the threat.

### 📸 Persistent Virtual Browser Engine
To prevent performance degradation, it utilizes a single-instance **Playwright Chromium** engine running headless in the background. For each request, it:
- Captures a live screenshot of the target site.
- Detects hidden credential-harvesting elements (e.g., `<input type="password">`).

### 👁️ Computer Vision (OCR) Brand Impersonation Detection
Phishing sites often hide logos as images (PNG/JPG) rather than HTML text to bypass traditional scrapers. Thanks to **Tesseract OCR** integration, logos inside the screenshot are extracted and read. If a recognized institution's name appears in the image but doesn't match the domain, it immediately raises a "Visual Brand Impersonation" red flag.

### 🇹🇷 E-Commerce Whitelisting (False-Positive Prevention)
To prevent false alarms, major e-commerce and social media applications in Turkey (e.g., sahibinden, letgo, trendyol) are placed under a special whitelist protection. For these verified domains, heavy operations (Whois, VirusTotal scans) are bypassed to ensure maximum performance and zero false positives.

### ✉️ Autonomous Takedown System
When a malicious site is detected, the bot automatically extracts the hosting provider's abuse contact from Whois records. Upon pressing the **🚨 OTOMATİK İHBAR ET (REPORT ABUSE)** button on the bot:
1. **USOM (National Cyber Incident Response Center):** Sends an official incident report drafted by AI in Turkish.
2. **Hosting Provider (Abuse):** Sends an English DMCA / Phishing Takedown request, drafted by AI, along with the captured screenshot as irrefutable evidence.

### 🛡️ Additional Armor Layers
- **SSRF Protection:** Prevents the bot from being redirected to internal networks (localhost/127.0.0.1).
- **Typosquatting Detection:** Identifies fake domains like "g00gle.com" using the Levenshtein distance algorithm.
- **Threat Intel Integration:** Performs concurrent queries via VirusTotal and Google Safe Browsing APIs.
- **Domain & SSL Age Analysis:** Calculates the precise age of the domain and SSL certificate, mitigating timezone mismatches and exposing newly registered fraudulent domains.

---

## 🚀 Installation

**1. Clone the Repository:**
```bash
git clone https://github.com/metinpy/CyberEye.git
cd CyberEye
```

**2. Install Dependencies:**
```bash
pip install -r requirements.txt
playwright install chromium
```
*(Note: For the OCR feature to work on Windows, [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) must be installed, and the `tesseract_cmd` path in the code must match your system.)*

**3. Set Environment Variables:**
Create a `.env` file in the project directory and insert your API keys:
```env
BOT_TOKEN=your_telegram_bot_token
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
SENDER_EMAIL=your_sender_gmail_address
SENDER_PASSWORD=your_gmail_app_password
```

**4. Run the Bot:**
```bash
python bot.py
```

---

## 🛠️ Technology Stack
- **Core:** Python 3.8+, Asyncio
- **Bot Framework:** Aiogram 3.x
- **Browser Automation:** Playwright Async
- **Artificial Intelligence:** Google Generative AI (Gemini Flash)
- **Computer Vision:** PyTesseract, Pillow
- **Network & Security:** Aiohttp, Python-Whois, Tldextract, SSL, Mmh3

---

## ⚠️ Disclaimer
This project is developed solely for cybersecurity research and community benefit. The developer accepts no legal responsibility for any illegal or malicious use of this software.

<br>
<p align="center">
  <i>Developer: <b>metin.py</b></i> 🇹🇷
</p>
