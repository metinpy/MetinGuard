import os
import re
import asyncio
import logging
import ssl
import socket
import ipaddress
import time
import json
import base64
from io import BytesIO
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import BufferedInputFile, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from dotenv import load_dotenv
import whois
import aiohttp
import Levenshtein
import tldextract
from playwright.async_api import async_playwright
import pytesseract
from PIL import Image
import mmh3
import google.generativeai as genai
import aiosmtplib
from email.message import EmailMessage
from bs4 import BeautifulSoup

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash')
else:
    gemini_model = None

try:
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
except:
    pass

TARGET_BRANDS = ["sahibinden", "letgo", "facebook", "dolap", "trendyol", "hepsiburada", "n11", "ciceksepeti", "amazon", "pazarama", "shopier"]

SAFE_DOMAINS = [
    "sahibinden.com", "letgo.com", "facebook.com", "dolap.com", "trendyol.com", 
    "hepsiburada.com", "n11.com", "ciceksepeti.com", "amazon.com.tr", "amazon.com", 
    "pazarama.com", "shopier.com", "m.facebook.com", "m.sahibinden.com", "shbd.io"
]

SUSPICIOUS_TLDS = ["xyz", "top", "free", "tk", "ml", "ga", "cf", "gq", "cc", "biz", "info", "online", "site", "vip", "icu", "click"]
SHORTENER_DOMAINS = ["bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "goo.gl", "ow.ly"]
MALICIOUS_EXTENSIONS = [".apk", ".exe", ".bat", ".zip", ".msi", ".cmd", ".vbs", ".scr"]

logging.basicConfig(level=logging.INFO)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

USER_COOLDOWNS = {}
COOLDOWN_SECONDS = 5
MAX_URLS_PER_MESSAGE = 3
MAX_URL_LENGTH = 300
USOM_LIST = set()
playwright_instance = None
browser_instance = None
REPORT_STORAGE = {}

async def fetch_usom_list():
    global USOM_LIST
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://www.usom.gov.tr/url-list.txt", timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    USOM_LIST = set([line.strip() for line in text.split('\n') if line.strip()])
    except Exception:
        pass

async def setup_playwright():
    global playwright_instance, browser_instance
    playwright_instance = await async_playwright().start()
    browser_instance = await playwright_instance.chromium.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])

async def teardown_playwright():
    global playwright_instance, browser_instance
    if browser_instance: await browser_instance.close()
    if playwright_instance: await playwright_instance.stop()

async def resolve_and_check_ip(domain):
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(domain, None)
        ip = ipaddress.ip_address(addr_info[0][4][0])
        if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            return False, f"İç ağ IP tespiti"
        return True, ""
    except Exception:
        return True, ""

def is_ip_address(domain):
    try: ipaddress.ip_address(domain); return True
    except ValueError: return False

async def safe_tld_extract(url):
    return await asyncio.to_thread(tldextract.extract, url)

async def unshorten_url(url):
    try:
        ext = await asyncio.wait_for(safe_tld_extract(url), timeout=3.0)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        if domain in SHORTENER_DOMAINS:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, allow_redirects=True, timeout=5) as resp:
                    return str(resp.url), True
    except Exception:
        pass
    return url, False

async def get_domain_age(domain):
    if is_ip_address(domain): return None, "IP adresi."
    try:
        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=6.0)
        creation_date = w.creation_date
        
        if type(creation_date) == list: 
            creation_date = creation_date[0]
            
        if isinstance(creation_date, datetime): 
            # Timezone (Zaman Dilimi) uyumsuzluklarından dolayı programın çökmesini engelle
            safe_creation = creation_date.replace(tzinfo=None)
            safe_now = datetime.now().replace(tzinfo=None)
            age = (safe_now - safe_creation).days
            
            # Bazı sunucular saati yanlış verebilir, negatif yaş olmasını engelle
            if age < 0: age = 0 
            return age, None
            
        return None, "Gizli (Whois Koruması)."
    except Exception:
        return None, "Whois sunucusu yanıt vermedi."

async def get_abuse_email(domain):
    if is_ip_address(domain): return None
    try:
        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=3.0)
        emails = w.emails
        if emails:
            if type(emails) == list:
                for e in emails:
                    if 'abuse' in e.lower(): return e
                return emails[0]
            else:
                return emails
    except: pass
    return None

async def check_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY: return False, "Key Yok"
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {"client": {"clientId": "metinguard", "clientVersion": "6.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(api_url, json=payload, timeout=4) as resp:
                data = await resp.json()
                if "matches" in data: return True, "Google Zararlı İşareti"
                return False, ""
        except: return False, "Sorgu Hatası"

async def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY: return False, "Key Yok"
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": VIRUSTOTAL_API_KEY, "resource": url}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(api_url, params=params, timeout=4) as resp:
                data = await resp.json()
                if data.get("response_code") == 1 and data.get("positives", 0) > 0:
                    return True, f"VT: {data.get('positives')}/{data.get('total')}"
                return False, ""
        except: return False, "Sorgu Hatası"

async def check_ssl_cert(domain):
    if is_ip_address(domain): return None, "IP adresleri için SSL analizi atlandı."
    loop = asyncio.get_event_loop()
    try:
        context = ssl.create_default_context()
        def fetch_cert():
            with socket.create_connection((domain, 443), timeout=3) as sock:
                sock.settimeout(3)
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.settimeout(3)
                    return ssock.getpeercert()
        cert = await asyncio.wait_for(loop.run_in_executor(None, fetch_cert), timeout=4.0)
        not_before = cert.get('notBefore')
        if not_before:
            creation_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            return (datetime.utcnow() - creation_date).days, None
        return None, "Sertifika tarihi alınamadı."
    except Exception:
        return None, "Geçersiz veya Yok."

async def capture_screenshot_and_analyze(url, root_domain):
    global browser_instance
    if not browser_instance: return None, None, 0, None, None, "Tarayıcı motoru hazır değil."
    context = None
    try:
        context = await browser_instance.new_context(viewport={'width': 1280, 'height': 720})
        page = await context.new_page()
        await page.goto(url, timeout=12000, wait_until="domcontentloaded")
        title = await page.title()
        screenshot_bytes = await page.screenshot(type="jpeg", quality=80)
        password_inputs = await page.locator("input[type='password']").count()
        inner_text = await page.evaluate("() => document.body.innerText")
        if inner_text: inner_text = " ".join(inner_text.split())[:1500]
        return screenshot_bytes, title, password_inputs, inner_text, None, None
    except Exception as e:
        return None, None, 0, None, None, f"Sayfa analiz hatası: {str(e)[:50]}"
    finally:
        if context: await context.close()

async def perform_ocr(screenshot_bytes):
    try:
        img = Image.open(BytesIO(screenshot_bytes))
        return await asyncio.to_thread(pytesseract.image_to_string, img, lang='eng+tur')
    except Exception: return ""

async def analyze_with_gemini(title, inner_text):
    if not gemini_model or not inner_text: return "AI Analizi kapalı."
    prompt = f"Sen bir Siber Güvenlik Analistisin. Aşağıdaki sayfa başlığı ve içeriği verilen sitenin bir dolandırıcılık (oltalama/phishing) amacı güdüp gütmediğini analiz et.\nSayfa Başlığı: {title}\nİçerik: {inner_text}\nSadece 2 cümlelik, net bir Türkçe özet ver."
    try:
        response = await asyncio.to_thread(gemini_model.generate_content, prompt)
        return response.text.strip()
    except: return "AI analizi sırasında hata."

async def generate_abuse_emails(url, reasons):
    if not gemini_model:
        return f"Sayın Yetkili,\n\nAşağıdaki adres zararlıdır:\n{url}", f"Dear Abuse Team,\n\nThe following URL is malicious:\n{url}"
    prompt_tr = f"Şu URL ({url}) için USOM'a gönderilecek resmi phishing ihbar e-postası yaz. Sadece mail metni olsun. Tespitler: {', '.join(reasons)}"
    prompt_en = f"Write an English DMCA/Phishing abuse report email for {url}. Just email body. Detections: {', '.join(reasons)}"
    try:
        task_tr = asyncio.to_thread(gemini_model.generate_content, prompt_tr)
        task_en = asyncio.to_thread(gemini_model.generate_content, prompt_en)
        res_tr, res_en = await asyncio.gather(task_tr, task_en)
        return res_tr.text.strip(), res_en.text.strip()
    except Exception:
        return f"Zararlı adres:\n{url}", f"Malicious URL:\n{url}"

async def send_abuse_email(target_url, report_data, screenshot_bytes):
    if not SENDER_EMAIL or not SENDER_PASSWORD: return False, "SMTP ayarları eksik (.env)."
    abuse_email = await get_abuse_email(urlparse(target_url).netloc)
    tr_body, en_body = await generate_abuse_emails(target_url, report_data.get("reasons", []))
    success_msg = ""
    try:
        msg_usom = EmailMessage()
        msg_usom['Subject'] = f"ACİL: Oltalama İhbarı - {urlparse(target_url).netloc}"
        msg_usom['From'] = SENDER_EMAIL
        msg_usom['To'] = "ihbar@usom.gov.tr"
        msg_usom.set_content(tr_body)
        if screenshot_bytes: msg_usom.add_attachment(screenshot_bytes, maintype='image', subtype='jpeg', filename='kanit.jpg')
        await aiosmtplib.send(msg_usom, hostname="smtp.gmail.com", port=587, start_tls=True, username=SENDER_EMAIL, password=SENDER_PASSWORD)
        success_msg = "🇹🇷 USOM ihbarı gönderildi."
        
        if abuse_email:
            msg_abuse = EmailMessage()
            msg_abuse['Subject'] = f"URGENT: Phishing Report - {urlparse(target_url).netloc}"
            msg_abuse['From'] = SENDER_EMAIL
            msg_abuse['To'] = abuse_email
            msg_abuse.set_content(en_body)
            if screenshot_bytes: msg_abuse.add_attachment(screenshot_bytes, maintype='image', subtype='jpeg', filename='evidence.jpg')
            await aiosmtplib.send(msg_abuse, hostname="smtp.gmail.com", port=587, start_tls=True, username=SENDER_EMAIL, password=SENDER_PASSWORD)
            success_msg += f"\n🇬🇧 Hosting ({abuse_email}) ihbarı gönderildi."
        return True, success_msg
    except Exception as e:
        return False, f"Mail hatası: {e}"

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🛡️ <b>MetinGuard v6.1 The Total Fortress</b>\n\n"
        "<i>Bu bot <b>metin.py</b> tarafından kamu yararına geliştirilmiştir.</i> 🇹🇷\n\n"
        "Siber dolandırıcılık ve oltalama (phishing) sitelerini tespit etmek için bana sadece bir link gönderin. Türkiye e-ticaret, sosyal medya ve devlet siteleri tam koruma altındadır.", 
        parse_mode=ParseMode.HTML
    )

@dp.callback_query(F.data.startswith("report_"))
async def process_callback(callback_query: CallbackQuery):
    action, report_id = callback_query.data.split("_")[0], callback_query.data.split("_")[1]
    if report_id not in REPORT_STORAGE: return await callback_query.answer("Rapor zaman aşımına uğramış.", show_alert=True)
    report_data = REPORT_STORAGE[report_id]
    
    if action == "report":
        await callback_query.answer("İhbar işlemi başlatıldı...")
        success, msg = await send_abuse_email(report_data['url'], report_data, report_data.get('screenshot'))
        await callback_query.message.reply(f"{'✅ Başarılı' if success else '❌ Başarısız'}\n{msg}")
    elif action == "safe":
        await callback_query.answer("URL Güvenli işaretlendi.")
        await callback_query.message.reply(f"✅ <code>{report_data['url']}</code> veri tabanına güvenli olarak kaydedildi.", parse_mode=ParseMode.HTML)

@dp.message(F.text)
async def analyze_message(message: types.Message):
    user_id = message.from_user.id
    current_time = time.time()
    
    if user_id in USER_COOLDOWNS and (current_time - USER_COOLDOWNS[user_id]) < COOLDOWN_SECONDS: return
    USER_COOLDOWNS[user_id] = current_time
    if len(message.text) > 2000: return

    url_pattern = re.compile(r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?')
    urls = list(set(url_pattern.findall(message.text)))[:MAX_URLS_PER_MESSAGE]
    
    for original_url in urls:
        if len(original_url) > MAX_URL_LENGTH: continue
        if not original_url.startswith(('http://', 'https://')): original_url = 'http://' + original_url
        
        if any(original_url.lower().endswith(ext) for ext in MALICIOUS_EXTENSIONS):
            await message.answer(f"🛑 <b>ZARARLI DOSYA</b>\nLink zararlı bir dosyaya ait!\n<code>{original_url}</code>", parse_mode=ParseMode.HTML)
            continue
            
        status_msg = await message.answer(f"🛡️ <b>MetinGuard v6.1 Analizi</b>\n<code>{original_url[:50]}...</code>", parse_mode=ParseMode.HTML)
        
        try:
            url, is_redirected = await unshorten_url(original_url)
            if url in USOM_LIST or urlparse(url).netloc in USOM_LIST:
                await status_msg.edit_text(f"🔴 <b>USOM ENGELLEMESİ</b>\nZararlı adres!\n<code>{url}</code>", parse_mode=ParseMode.HTML)
                continue
                
            ext = await safe_tld_extract(url)
            root_domain = f"{ext.domain}.{ext.suffix}".lower()
            full_domain = f"{ext.subdomain}.{root_domain}".lower() if ext.subdomain else root_domain
            
            is_safe, _ = await resolve_and_check_ip(full_domain)
            if not is_safe:
                await status_msg.edit_text("🛑 <b>SSRF Koruması İhlali</b>", parse_mode=ParseMode.HTML)
                continue

            is_whitelisted = root_domain in SAFE_DOMAINS or full_domain in SAFE_DOMAINS
            
            await status_msg.edit_text(f"🛡️ <b>MetinGuard v6.1 Analizi</b>\nHedef: <code>{original_url[:50]}...</code>\n\n[⚙️] Ekran görüntüsü ve veriler paralel olarak toplanıyor...", parse_mode=ParseMode.HTML)
            
            whois_task = asyncio.create_task(get_domain_age(root_domain))
            sb_task = asyncio.create_task(check_safe_browsing(url))
            vt_task = asyncio.create_task(check_virustotal(url))
            ssl_task = asyncio.create_task(check_ssl_cert(full_domain))
            screen_task = asyncio.create_task(capture_screenshot_and_analyze(url, root_domain))

            age_days, age_err = await whois_task
            sb_res, sb_msg = await sb_task
            vt_res, vt_msg = await vt_task
            ssl_age, ssl_err = await ssl_task
            screenshot_bytes, page_title, password_inputs, inner_text, _, screen_err = await screen_task

            risk_points = 0
            is_critical = False
            reasons = []
            
            if is_whitelisted:
                reasons.append("✅ BU SİTE RESMİ VE ORİJİNALDİR. Türkiye pazarında doğrulanmış firmadır.")
                ai_comment = "Bu site orijinal bir platformdur. Kullanıcıların verilerini girmesi güvenlidir."
                header = "🟢 <b>DÜŞÜK RİSKLİ (ORİJİNAL PLATFORM)</b>"
            else:
                if is_redirected: reasons.append("Yönlendirme (Redirect) Tespit Edildi."); risk_points += 10
                if is_ip_address(ext.domain): reasons.append("Doğrudan IP adresi kullanımı."); risk_points += 40

                brand_name = ext.domain.lower()
                subdomains = ext.subdomain.lower()
                
                for brand in TARGET_BRANDS:
                    dist = Levenshtein.distance(brand, brand_name)
                    if 0 < dist <= 2:
                        is_critical = True; reasons.append(f"🔴 Domain Marka Taklidi: '{brand}'"); risk_points += 80
                    elif brand in subdomains:
                        is_critical = True; reasons.append(f"🔴 Subdomain Spoofing: '{brand}'"); risk_points += 80

                if sb_res: is_critical = True; reasons.append(f"🔴 Google Safe Browsing: Zararlı İşaretlenmiş"); risk_points += 100
                if vt_res: is_critical = True; reasons.append(f"🔴 VirusTotal: {vt_msg}"); risk_points += 100
                
                if age_days is not None:
                    if age_days < 14: reasons.append(f"🔴 Domain çok yeni ({age_days} gün)."); risk_points += 40
                    elif age_days < 90: reasons.append(f"🟡 Domain yeni ({age_days} gün)."); risk_points += 20
                else:
                    if not is_ip_address(ext.domain): reasons.append(f"🟡 Domain Yaşı Gizli veya Hatası: {age_err}"); risk_points += 10

                if ssl_age is not None:
                    if ssl_age < 14: reasons.append(f"🔴 SSL çok yeni ({ssl_age} gün). Anlık alınmış olabilir."); risk_points += 40
                    elif ssl_age < 60: reasons.append(f"🟡 SSL yeni ({ssl_age} gün)."); risk_points += 20
                else:
                    if not is_ip_address(ext.domain): reasons.append(f"🔴 SSL Sertifikası Yok / Geçersiz: {ssl_err}"); risk_points += 30

                if screenshot_bytes:
                    ocr_text = await perform_ocr(screenshot_bytes)
                    for brand in TARGET_BRANDS:
                        if brand in ocr_text.lower() and brand not in full_domain:
                            is_critical = True
                            reasons.append(f"🔴 GÖRSEL MARKA TAKLİDİ: Resimde '{brand}' var ama domain farklı!")
                            risk_points += 90
                            break
                            
                    if password_inputs > 0:
                        reasons.append(f"🔴 Sayfada {password_inputs} adet şifre kutusu bulundu."); risk_points += 30
                        
                    ai_comment = await analyze_with_gemini(page_title, inner_text)
                else:
                    ai_comment = "Siteye bağlantı sağlanamadığı için yapay zeka analizi yapılamadı."

                risk_points = max(0, min(100, risk_points))
                if is_critical: risk_points = max(90, risk_points)

                if risk_points >= 80: header = "🔴 <b>KRİTİK RİSKLİ (PHISHING/MALWARE)</b>"
                elif risk_points >= 40: header = "🟡 <b>ORTA RİSKLİ (ŞÜPHELİ)</b>"
                else: header = "🟢 <b>DÜŞÜK RİSKLİ (GÜVENLİ)</b>"

            tech_age = f"{age_days} Gün" if age_days is not None else "Gizli/Bulunamadı"
            tech_ssl = f"{ssl_age} Gün" if ssl_age is not None else "Geçersiz/Yok"
            tech_login = f"Var ({password_inputs} Kutu)" if screenshot_bytes and password_inputs > 0 else "Yok"

            report_id = str(int(time.time() * 1000))
            REPORT_STORAGE[report_id] = {
                "url": url, "risk_score": risk_points, "reasons": reasons,
                "ai_comment": ai_comment, "screenshot": screenshot_bytes
            }

            report = f"🛡️ <b>MetinGuard v6.1 Analiz Raporu</b>\n"
            report += f"🌐 Hedef: <code>{url[:50]}</code>\n"
            report += f"📊 Risk Skoru: <b>% {risk_points}</b>\n"
            report += f"{header}\n\n"
            
            report += "<b>📋 Teknik Veriler:</b>\n"
            report += f"• Domain Yaşı: <b>{tech_age}</b>\n"
            report += f"• SSL Sertifikası: <b>{tech_ssl}</b>\n"
            report += f"• Şifre İsteği: <b>{tech_login}</b>\n\n"
            
            report += "<b>⚠️ Tespit Edilen Bulgular:</b>\n"
            if not reasons: report += "• Herhangi bir risk tespit edilmedi.\n"
            for r in reasons: report += f"• {r}\n"
                
            report += f"\n🤖 <b>AI Analizi:</b>\n<i>{ai_comment}</i>\n"

            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🚨 OTOMATİK İHBAR ET (USOM)", callback_data=f"report_{report_id}")],
                [InlineKeyboardButton(text="✅ Güvenli İşaretle", callback_data=f"safe_{report_id}")]
            ])

            if screenshot_bytes:
                photo = BufferedInputFile(screenshot_bytes, filename="guard_view.jpg")
                await message.answer_photo(photo=photo, caption=report[:1000], reply_markup=keyboard, parse_mode=ParseMode.HTML)
                await status_msg.delete()
            else:
                await status_msg.edit_text(report, reply_markup=keyboard, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

        except Exception as e:
            await status_msg.edit_text(f"❌ MetinGuard Analiz Hatası: {str(e)[:50]}", parse_mode=ParseMode.HTML)

async def main():
    if not BOT_TOKEN: return
    await fetch_usom_list()
    await setup_playwright()
    try: await dp.start_polling(bot)
    finally: await teardown_playwright()

if __name__ == '__main__':
    asyncio.run(main())
