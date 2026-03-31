<div align="center">

```
 ██████╗████████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚══██╔══╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║        ██║   █████╗         ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██║        ██║   ██╔══╝         ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
╚██████╗   ██║   ██║            ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
 ╚═════╝   ╚═╝   ╚═╝            ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
```

# ⚡ CTF Toolkit

**Her CTF yarışmasında yanında olan kapsamlı araç seti**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Rich](https://img.shields.io/badge/UI-Rich_Terminal-purple?style=for-the-badge)](https://github.com/Textualize/rich)
[![Author](https://img.shields.io/badge/Author-Muhammet%20%C3%96zkaya-orange?style=for-the-badge&logo=github)](https://github.com/muhammetozkaya)

</div>

---

## 📖 İçindekiler

- [🎯 Proje Hakkında](#-proje-hakkında)
- [✨ Özellikler](#-özellikler)
- [🚀 Kurulum](#-kurulum)
- [📁 Proje Yapısı](#-proje-yapısı)
- [🔐 Kriptografi Modülü](#-kriptografi-modülü)
- [🖼️ Steganografi Modülü](#️-steganografi-modülü)
- [🔬 Adli Bilişim Modülü](#-adli-bilişim-modülü)
- [🌐 Web Güvenliği Modülü](#-web-güvenliği-modülü)
- [🏆 Gerçek CTF Senaryoları](#-gerçek-ctf-senaryoları)
- [🧪 Testler](#-testler)
- [👨‍💻 Katkıda Bulunma](#-katkıda-bulunma)

---

## 🎯 Proje Hakkında

**CTF Toolkit**, Capture The Flag yarışmalarında en sık karşılaşılan zorlukları çözmek için tasarlanmış, Python tabanlı kapsamlı bir araç setidir. İnteraktif terminal arayüzü ve bağımsız çalışabilen modülleriyle hem yeni başlayanlar hem de deneyimli CTF oyuncuları için idealdir.

> _"CTF çözmek için doğru araçlara sahip olmak, yarışmanın yarısını kazanmaktır."_

### 🎪 Desteklenen CTF Kategorileri

| Kategori | Araç | Açıklama |
|----------|------|----------|
| 🔐 Crypto | `crypto.py` | Şifreleme & kodlama işlemleri |
| 🖼️ Stego | `stego.py` | Görüntü & dosya steganografisi |
| 🔬 Forensics | `forensics.py` | Dijital adli bilişim |
| 🌐 Web | `web.py` | Web güvenliği araçları |

---

## ✨ Özellikler

<table>
<tr>
<td>

### 🔐 Kriptografi
- Base64 / Base32 / Base16 encode-decode
- Hex & Binary dönüşümleri
- ROT13 / Caesar Cipher + Brute Force
- Vigenere Cipher şifreleme/çözme
- XOR şifreleme
- Atbash Cipher
- Morse Kodu encode/decode
- Frekans analizi (İngilizce karşılaştırmalı)
- Tüm encoding'leri tek seferde gösterme

</td>
<td>

### 🖼️ Steganografi
- PNG/JPG LSB bit extraction
- LSB'ye mesaj gizleme
- Çok sayıda dosyadan string çıkarma
- File carving (magic bytes tespiti)
- PNG chunk analizi (tEXt, zTXt, iTXt)
- JPEG/PNG EOF sonrası veri tespiti
- Otomatik flag/URL/email arama
- Dosya metadata analizi

</td>
</tr>
<tr>
<td>

### 🔬 Adli Bilişim
- 30+ magic byte imzası ile dosya tespiti
- EXIF metadata okuma (GPS dahil)
- Renkli hex dump görüntüleme
- Zaman damgası analizi (ctime/mtime/atime)
- Çoklu hash hesaplama (MD5/SHA-1/SHA-256/SHA-512)
- Shannon entropi analizi
- Byte-level dosya karşılaştırma
- Dizin toplu analiz (uzantı uyumsuzluk tespiti)

</td>
<td>

### 🌐 Web Güvenliği
- URL encode / decode (4 farklı yöntem)
- HTML entity encode / decode
- JWT token decode + güvenlik analizi
- 17 farklı hash türü tanımlama
- Çoklu hash hesaplama
- URL bileşen analizi
- Cookie decoder
- SQLi & XSS payload listesi

</td>
</tr>
</table>

---

## 🚀 Kurulum

### Gereksinimler

- Python 3.8 veya üzeri
- pip paket yöneticisi

### Adım Adım Kurulum

```bash
# 1. Repoyu klonla
git clone https://github.com/muhammetozkaya/ctf-toolkit
cd ctf-toolkit

# 2. Bağımlılıkları yükle
pip install -r requirements.txt

# 3. Ana menüyü başlat
python src/toolkit.py
```

### Bağımlılıklar

```
rich>=13.0.0      # Renkli terminal arayüzü
Pillow>=10.0.0    # PNG/JPG görüntü işleme
requests>=2.28.0  # HTTP istekleri
```

---

## 📁 Proje Yapısı

```
ctf-toolkit/
├── 📂 src/
│   ├── 🐍 toolkit.py       # Ana interaktif menü
│   ├── 🔐 crypto.py        # Kriptografi araçları
│   ├── 🖼️  stego.py        # Steganografi araçları
│   ├── 🔬 forensics.py     # Adli bilişim araçları
│   └── 🌐 web.py           # Web güvenliği araçları
├── 📂 wordlists/
│   └── 📄 common.txt       # 50 yaygın CTF şifresi
├── 📂 samples/             # Test dosyaları
├── 📂 tests/
│   └── 🧪 test_toolkit.py  # Unit testler
├── 📂 docs/
│   └── 📖 usage.md         # Detaylı kullanım kılavuzu
├── 📄 README.md
├── 📄 requirements.txt
└── 📄 .gitignore
```

---

## 🔐 Kriptografi Modülü

### İnteraktif Mod

```bash
python src/crypto.py -i
# veya
python src/crypto.py --interactive
```

### CLI Kullanımı

```bash
# ── Encoding ──────────────────────────────────────────────
python src/crypto.py --encode base64 "Hello CTF"
# ➜ SGVsbG8gQ1RG

python src/crypto.py --decode base64 "SGVsbG8gQ1RG"
# ➜ Hello CTF

python src/crypto.py --encode hex "Hello"
# ➜ 48656c6c6f

python src/crypto.py --encode morse "SOS"
# ➜ ... --- ...

# ── Cipher ────────────────────────────────────────────────
python src/crypto.py --encrypt caesar "Hello World" --shift 13
# ➜ Uryyb Jbeyq

python src/crypto.py --decrypt caesar "Uryyb Jbeyq" --shift 13
# ➜ Hello World

python src/crypto.py --encrypt vigenere "HELLO" --key "SECRET"
# ➜ ZINCS

# ── Analiz ────────────────────────────────────────────────
python src/crypto.py --bruteforce "Khoor Zruog"
# ➜ Shift=3: Hello World ✓

python src/crypto.py --analyze "Kyv zj k yv ccf"
# ➜ En sık harf analizi tablosu

python src/crypto.py --all "CTF{test}"
# ➜ Tüm encoding sonuçları
```

### 💡 CTF Senaryosu: Klasik Şifreleme

```
🏴 Challenge: "Wkh iodjv lv: FWI{fdhvdu_lv_ixq}"
📋 Çözüm:
   python src/crypto.py --bruteforce "Wkh iodjv lv: FWI{fdhvdu_lv_ixq}"
   → Shift 3: "The flags is: CTF{caesar_is_fun}" ✓
```

---

## 🖼️ Steganografi Modülü

### İnteraktif Mod

```bash
python src/stego.py -i
```

### CLI Kullanımı

```bash
# ── LSB Extraction ────────────────────────────────────────
python src/stego.py --lsb image.png
python src/stego.py --lsb image.png --bits 2

# ── Strings ───────────────────────────────────────────────
python src/stego.py --strings binary_file.bin
python src/stego.py --strings binary_file.bin --min-length 8

# ── File Carving ──────────────────────────────────────────
python src/stego.py --carve suspicious.jpg

# ── PNG Chunk Analizi ─────────────────────────────────────
python src/stego.py --chunks image.png

# ── EOF Sonrası Veri ──────────────────────────────────────
python src/stego.py --eof image.jpg

# ── Mesaj Gizleme ─────────────────────────────────────────
python src/stego.py --hide original.png --message "gizli_flag" --output output.png
```

### 💡 CTF Senaryosu: Gizli Resim

```
🏴 Challenge: "image.png'de bir bayrak var"
📋 Çözüm:
   # 1. Adım: Strings dene
   python src/stego.py --strings image.png
   # → "CTF{hidden_in_plain_sight}" bulundu!

   # 2. Adım (alternatif): LSB extraction
   python src/stego.py --lsb image.png
   
   # 3. Adım (alternatif): File carving
   python src/stego.py --carve image.png
   # → Offset 0x1234'te ZIP dosyası tespit edildi!
```

---

## 🔬 Adli Bilişim Modülü

### İnteraktif Mod

```bash
python src/forensics.py -i
```

### CLI Kullanımı

```bash
# ── Dosya Tipi ────────────────────────────────────────────
python src/forensics.py --identify suspicious_file
# ➜ Gerçek Tip: ZIP Archive | Uzantı: .zip

# ── EXIF ──────────────────────────────────────────────────
python src/forensics.py --exif photo.jpg
# ➜ Make: Apple | Model: iPhone 14 | GPS: 41.0082, 28.9784

# ── Hex Dump ──────────────────────────────────────────────
python src/forensics.py --hexdump file.bin
python src/forensics.py --hexdump file.bin --offset 256 --length 128

# ── Timestamp ─────────────────────────────────────────────
python src/forensics.py --timestamps file.jpg
# ➜ Created: 2024-01-15 14:30:00 | Modified: ...

# ── Hash ──────────────────────────────────────────────────
python src/forensics.py --hashes file.exe
# ➜ MD5, SHA-1, SHA-256, SHA-512

# ── Entropi ───────────────────────────────────────────────
python src/forensics.py --entropy suspicious.bin
# ➜ 7.89/8.0 → Muhtemelen şifreli!

# ── Karşılaştırma ─────────────────────────────────────────
python src/forensics.py --compare original.jpg modified.jpg

# ── Dizin Analizi ─────────────────────────────────────────
python src/forensics.py --dir-analyze ./challenge_files/
```

### 💡 CTF Senaryosu: Sahte Dosya

```
🏴 Challenge: "document.pdf'yi inceleyin"
📋 Çözüm:
   # 1. Magic bytes kontrolü
   python src/forensics.py --identify document.pdf
   # → Gerçek Tip: ZIP Archive ⚠️ (Uzantı uyumsuzluğu!)
   
   # 2. Entropi analizi
   python src/forensics.py --entropy document.pdf
   # → 3.2/8.0 → Normal ZIP içeriği
   
   # 3. Hex dump ile inceleme
   python src/forensics.py --hexdump document.pdf
   # → 50 4B 03 04 (PK magic bytes = ZIP!)
   # → rename document.pdf document.zip && unzip document.zip
```

---

## 🌐 Web Güvenliği Modülü

### İnteraktif Mod

```bash
python src/web.py -i
```

### CLI Kullanımı

```bash
# ── URL Encoding ──────────────────────────────────────────
python src/web.py --url-encode "Hello World & foo=bar"
# ➜ Hello%20World%20%26%20foo%3Dbar

python src/web.py --url-decode "Hello%20World"
# ➜ Hello World

# ── HTML Entity ───────────────────────────────────────────
python src/web.py --html-encode "<script>alert(1)</script>"
# ➜ &lt;script&gt;alert(1)&lt;/script&gt;

python src/web.py --html-decode "&lt;h1&gt;Title&lt;/h1&gt;"
# ➜ <h1>Title</h1>

# ── JWT ───────────────────────────────────────────────────
python src/web.py --jwt-decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
# ➜ Header, Payload, Güvenlik analizi

# ── Hash ──────────────────────────────────────────────────
python src/web.py --hash-id "5f4dcc3b5aa765d61d8327deb882cf99"
# ➜ MD5 (128-bit)

python src/web.py --hash-text "password"
# ➜ MD5: 5f4dcc..., SHA-1: 5baa61..., SHA-256: 5e8848...

# ── Payloads ──────────────────────────────────────────────
python src/web.py --sqli     # SQL Injection payloads
python src/web.py --xss      # XSS payloads

# ── URL Analizi ───────────────────────────────────────────
python src/web.py --analyze-url "https://example.com:8080/admin?id=1&role=user"
```

### 💡 CTF Senaryosu: JWT Manipülasyonu

```
🏴 Challenge: "JWT token ile admin paneline erişin"
📋 Çözüm:
   # 1. Token'ı decode et
   python src/web.py --jwt-decode "<token>"
   # → alg: "HS256", role: "user"
   
   # 2. Güvenlik analizi
   # → ⚠️  Şifre: "secret" deneyebilirsiniz
   # → alg: "none" ile imzasız token deneyin
   
   # 3. Hash identifier ile algoritma doğrula
   python src/web.py --hash-id "<signature_part>"
```

---

## 🏆 Gerçek CTF Senaryoları

### 🔴 Senaryo 1: PicoCTF Stego Challenge

```bash
# Resmi indirdikten sonra
python src/stego.py --strings challenge.jpg
python src/stego.py --lsb challenge.jpg
python src/stego.py --carve challenge.jpg
python src/stego.py --eof challenge.jpg
```

### 🟠 Senaryo 2: CryptoHack Klasik Şifre

```bash
# Frekans analizi ile başla
python src/crypto.py --analyze "Zkhuh lv wkh iodjB"

# Brute force dene
python src/crypto.py --bruteforce "Zkhuh lv wkh iodjB"

# Eğer Vigenere ise anahtarı bilerek çöz
python src/crypto.py --decrypt vigenere "ŞIFRE" --key "ANAHTAR"
```

### 🟡 Senaryo 3: HackTheBox Forensics

```bash
# 1. Dosyayı analiz et
python src/forensics.py --identify suspicious

# 2. Entropy kontrolü
python src/forensics.py --entropy suspicious

# 3. Hex dump ile magic bytes bul
python src/forensics.py --hexdump suspicious --length 512

# 4. EXIF ve timestamp
python src/forensics.py --exif suspicious.jpg
python src/forensics.py --timestamps suspicious.jpg
```

### 🟢 Senaryo 4: Web CTF - JWT Bypass

```bash
# Token analizi
python src/web.py --jwt-decode "eyJ..."

# Hash identifier
python src/web.py --hash-id "<signature>"

# SQLi payload dene
python src/web.py --sqli
```

---

## 🧪 Testler

```bash
# Tüm testleri çalıştır
python tests/test_toolkit.py -v

# Sadece belirli test sınıfı
python -m pytest tests/ -v --tb=short

# Coverage raporu
pip install pytest-cov
python -m pytest tests/ --cov=src --cov-report=html
```

### Test Kapsamı

| Modül | Test Sayısı | Kapsam |
|-------|-------------|--------|
| crypto.py | 28 test | Base encoding, Caesar, XOR, Vigenere, Atbash, Morse, Freq. Analysis |
| web.py | 18 test | URL/HTML encoding, JWT decode, Hash ID & text |

---

## 👨‍💻 Yazar

<div align="center">

**Muhammet Özkaya**

[![GitHub](https://img.shields.io/badge/GitHub-muhammetozkaya-black?style=for-the-badge&logo=github)](https://github.com/muhammetozkaya)

*CTF Toolkit - Her CTF'çinin vazgeçilmez aracı*

</div>

---

## 📊 Hızlı Referans

| İşlem | Komut |
|-------|-------|
| Ana menü | `python src/toolkit.py` |
| Base64 decode | `python src/crypto.py --decode base64 "SGVsbG8="` |
| Caesar brute force | `python src/crypto.py --bruteforce "Khoor"` |
| LSB extraction | `python src/stego.py --lsb image.png` |
| File carving | `python src/stego.py --carve file.jpg` |
| Magic bytes | `python src/forensics.py --identify file` |
| Hex dump | `python src/forensics.py --hexdump file.bin` |
| JWT decode | `python src/web.py --jwt-decode "eyJ..."` |
| Hash identify | `python src/web.py --hash-id "5f4dcc..."` |
| XSS payloads | `python src/web.py --xss` |

---

<div align="center">

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**

[![GitHub stars](https://img.shields.io/github/stars/muhammetozkaya/ctf-toolkit?style=social)](https://github.com/muhammetozkaya/ctf-toolkit/stargazers)

</div>
