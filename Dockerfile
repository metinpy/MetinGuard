FROM mcr.microsoft.com/playwright/python:v1.42.0-jammy

# Ortam değişkenleri
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Çalışma dizini
WORKDIR /app

# Tesseract OCR kurulumu
RUN apt-get update && apt-get install -y tesseract-ocr tesseract-ocr-eng tesseract-ocr-tur && rm -rf /var/lib/apt/lists/*

# Gereksinimleri kopyala ve yükle
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Proje dosyalarını kopyala
COPY . .

# Botu çalıştır
CMD ["python", "bot.py"]
