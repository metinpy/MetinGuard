# 🛡️ MetinGuard v6.1 - The Total Fortress

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?logo=python&logoColor=white" alt="Python Version"/>
  <img src="https://img.shields.io/badge/Aiogram-3.x-green.svg?logo=telegram&logoColor=white" alt="Aiogram"/>
  <img src="https://img.shields.io/badge/Playwright-Async-orange.svg?logo=playwright&logoColor=white" alt="Playwright"/>
  <img src="https://img.shields.io/badge/AI-Gemini_1.5_Flash-purple.svg?logo=google&logoColor=white" alt="Gemini AI"/>
</div>
<br>

**MetinGuard**, gelişmiş yapay zeka ve siber tehdit istihbaratı araçlarını bir araya getiren, Türkiye e-ticaret siteleri odaklı ve otonom bir **Telegram Siber Güvenlik Botudur.** 

Kullanıcıların gönderdiği şüpheli web sitelerini güvenli bir sanal ortamda (Sandbox) tarar, bulguları yapay zeka ile analiz eder ve tespit edilen dolandırıcılık/oltalama sayfalarını otomatik olarak **USOM'a** ve ilgili barındırma (hosting) firmasına ihbar eder.

---

## 🌟 Öne Çıkan Özellikler

### 🧠 Yapay Zeka Destekli İçerik Analizi (Gemini 1.5)
Sitenin kaynak kodlarındaki metinleri okuyarak "Sosyal Mühendislik" taktiklerini tespit eder. Sitenin aciliyet hissi yaratıp yaratmadığını veya sahte ödül/kampanya vaat edip etmediğini algılayarak Türkçe profesyonel bir özet çıkarır.

### 📸 Kalıcı (Persistent) Sanal Tarayıcı Engine
Performans kaybını önlemek için tek seferlik başlatılan **Playwright Chromium** motoru ile arka planda başsız (headless) olarak siteye girer. 
- Canlı ekran görüntüsü alır.
- Şifre giriş kutularını (`<input type="password">`) tespit eder.

### 👁️ Görüntü İşleme (OCR) Marka Tespiti
Oltalama siteleri genelde logoları HTML metni yerine "Görsel (PNG/JPG)" olarak gizler. **Tesseract OCR** entegrasyonu sayesinde ekran görüntüsündeki logolar okunur. Domain adresinde bulunmayan ama resimde yer alan kurum isimleri anında "Görsel Marka İhlali" olarak kırmızı bayrakla işaretlenir.

### 🇹🇷 Türkiye E-Ticaret Beyaz Listesi (Whitelist)
Yanlış alarmları (False-Positive) önlemek adına Türkiye'nin önde gelen pazar yeri ve sosyal medya uygulamaları (sahibinden, letgo, trendyol vb.) özel koruma ve beyaz liste altındadır. Orijinal sitelerde gereksiz işlemler (Whois, VT taraması) atlanarak maksimum performans sağlanır.

### ✉️ Otonom "Takedown" (İhbar) Sistemi
Zararlı tespit edilen bir sitenin barındırıcısı Whois kayıtlarından (abuse email) çekilir. Bot üzerindeki **🚨 OTOMATİK İHBAR ET** butonuna basıldığında:
1. **USOM (ihbar@usom.gov.tr):** AI tarafından yazılmış resmi Türkçe ihbar dilekçesi.
2. **Hosting Firması (Abuse):** AI tarafından yazılmış İngilizce DMCA / Phishing Takedown ihbarı, ekran görüntüsü kanıtıyla birlikte otomatik yollanır.

### 🛡️ Diğer Zırh Katmanları
- **SSRF Koruması:** Botun iç ağa (localhost/127.0.0.1) yönlendirilmesini engeller.
- **Typosquatting:** Levenshtein mesafesi ile "g00gle.com" gibi sahte domainleri tanır.
- **Threat Intel:** VirusTotal ve Google Safe Browsing API ile eşzamanlı sorgu yapar.
- **Domain & SSL Yaşı:** Timezone senkronizasyonlu Whois ve SSL sertifika yaşı analizi.

---

## 🚀 Kurulum Adımları

**1. Depoyu Klonlayın:**
```bash
git clone https://github.com/metinpy/MetinGuard.git
cd MetinGuard
```

**2. Gerekli Kütüphaneleri Yükleyin:**
```bash
pip install -r requirements.txt
playwright install chromium
```
*(Not: Windows'ta OCR özelliğinin çalışması için [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) yüklü olmalı ve kod içindeki `tesseract_cmd` yolu sisteminize uygun ayarlanmalıdır.)*

**3. Ortam Değişkenlerini Ayarlayın:**
Proje dizininde `.env` isimli bir dosya oluşturup API şifrelerinizi girin:
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

---

## 🛠️ Teknoloji Yığını (Stack)
- **Core:** Python 3.8+, Asyncio
- **Bot Altyapısı:** Aiogram 3.x
- **Browser Automation:** Playwright Async
- **Yapay Zeka:** Google Generative AI (Gemini Flash)
- **Computer Vision:** PyTesseract, Pillow
- **Ağ ve Güvenlik:** Aiohttp, Python-Whois, Tldextract, SSL, Mmh3

---

## ⚠️ Yasal Uyarı
Bu proje, siber güvenlik araştırmaları ve topluluk yararı amacıyla geliştirilmiştir. Geliştirici, kodun yasa dışı amaçlarla veya kötü niyetli kullanımından doğacak hiçbir yasal sorumluluğu kabul etmez.

<br>
<p align="center">
  <i>Geliştirici: <b>metin.py</b></i> 🇹🇷
</p>
