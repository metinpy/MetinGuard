# 🛡️ MetinGuard The Total Fortress

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Aiogram](https://img.shields.io/badge/aiogram-3.4.1-green.svg)](https://docs.aiogram.dev/en/latest/)
[![Playwright](https://img.shields.io/badge/Playwright-Async-orange.svg)](https://playwright.dev/python/)

**MetinGuard**, oltalama (phishing) ve zararlı yazılım (malware) dağıtan web sitelerini otonom olarak tespit eden, analiz eden ve ilgili kurumlara (USOM, Hosting Abuse) saniyeler içinde ihbar eden gelişmiş bir **Telegram Siber Güvenlik Botudur.**

## 🌟 Öne Çıkan Özellikler

- 🤖 **Yapay Zeka Destekli Sosyal Mühendislik Analizi:** Google Gemini 1.5 Flash entegrasyonu ile sitenin içeriğini okur, aciliyet hissi veya sahte ödül gibi oltalama taktiklerini saptar.
- 📸 **Kalıcı (Persistent) Playwright Motoru:** RAM dostu mimarisiyle arka planda başsız (headless) tarayıcı sekmesi açar, şüpheli sitelerin canlı ekran görüntüsünü çeker ve HTML yapısında gizlenmiş şifre çalma kutularını (`<input type="password">`) tespit eder.
- 👁️ **OCR (Görüntü İşleme) ile Marka Taklidi Tespiti:** Tesseract OCR kullanarak, metin yerine "resim" olarak gizlenmiş sahte kurum logolarını okur. Domain ile resimdeki logoyu karşılaştırarak marka ihlallerini anında yakalar.
- 🌍 **Global Threat Intelligence (Tehdit İstihbaratı):** Eş zamanlı (async) olarak Google Safe Browsing, VirusTotal ve USOM (Ulusal Siber Olaylara Müdahale Merkezi) veritabanlarını sorgular.
- 🛡️ **Gelişmiş Zırh Katmanları:** SSRF (Server-Side Request Forgery) koruması, Levenshtein algoritması ile Typosquatting tespiti, otomatik yönlendirme (redirect) takibi ve SSL Sertifika / Domain Yaşı (Whois) analizleri.
- ✉️ **Otonom İhbar Sistemi (Takedown):** Zararlı bulunan siteler için, Whois verilerinden sitenin sunucu barındırıcısını bulur. Gemini AI tarafından yazılmış özel bir DMCA/Phishing ihbar e-postasını (kanıtlarıyla birlikte) otomatik olarak USOM'a ve Hosting firmasına gönderir.

## 🚀 Kurulum

**1. Depoyu Klonlayın:**
```bash
git clone https://github.com/KULLANICI_ADIN/MetinGuard.git
cd MetinGuard
```

**2. Gerekli Kütüphaneleri Yükleyin:**
```bash
pip install -r requirements.txt
playwright install chromium
```
*(Not: OCR özelliğinin çalışması için sisteminizde [Tesseract](https://github.com/UB-Mannheim/tesseract/wiki) yüklü olmalıdır.)*

**3. Ortam Değişkenlerini Ayarlayın:**
Proje dizininde `.env` isimli bir dosya oluşturun ve API anahtarlarınızı girin:
```env
BOT_TOKEN=telegram_bot_tokeniniz
GOOGLE_SAFE_BROWSING_API_KEY=google_api_keyiniz
VIRUSTOTAL_API_KEY=virustotal_api_keyiniz
GEMINI_API_KEY=gemini_api_keyiniz
SENDER_EMAIL=ihbar_gönderecek_gmail_adresiniz
SENDER_PASSWORD=gmail_uygulama_sifreniz
```

**4. Botu Başlatın:**
```bash
python bot.py
```

## 🛠️ Kullanılan Teknolojiler
- **Core:** Python (Asyncio)
- **Bot Framework:** Aiogram 3.x
- **Tarayıcı Otomasyonu:** Playwright
- **Yapay Zeka:** Google Generative AI (Gemini)
- **Görüntü İşleme:** PyTesseract, Pillow
- **Ağ Analizi:** Aiohttp, Python-Whois, Tldextract

## ⚠️ Yasal Uyarı
Bu proje tamamen kamu yararına (Siber Güvenlik araştırmaları) amacıyla geliştirilmiştir. Geliştirici, yazılımın kötüye kullanılmasından dolayı hiçbir sorumluluk kabul etmez.

---
*Geliştirici: **metin.py*** 🇹🇷
"# MetinGuard-PhishSlayer" 
"# MetinGuard-PhishSlayer" 
"# MetinGuard-PhishSlayer" 
