# CTF Toolkit - Kullanım Kılavuzu

## İçindekiler

1. [Hızlı Başlangıç](#hızlı-başlangıç)
2. [Kriptografi Modülü](#kriptografi-modülü)
3. [Steganografi Modülü](#steganografi-modülü)
4. [Adli Bilişim Modülü](#adli-bilişim-modülü)
5. [Web Güvenliği Modülü](#web-güvenliği-modülü)
6. [Gerçek CTF Senaryoları](#gerçek-ctf-senaryoları)

---

## Hızlı Başlangıç

### Kurulum

```bash
git clone https://github.com/muhammetozkaya/ctf-toolkit
cd ctf-toolkit
pip install -r requirements.txt
```

### Ana Menüyü Başlatma

```bash
python src/toolkit.py
```

### Modülleri Bağımsız Kullanma

```bash
python src/crypto.py --help
python src/stego.py --help
python src/forensics.py --help
python src/web.py --help
```

---

## Kriptografi Modülü

### Base Encoding/Decoding

```bash
# Base64 encode
python src/crypto.py --encode base64 "Hello CTF"
# Çıktı: SGVsbG8gQ1RG

# Base64 decode
python src/crypto.py --decode base64 "SGVsbG8gQ1RG"
# Çıktı: Hello CTF

# Base32 encode/decode
python src/crypto.py --encode base32 "ctf"
python src/crypto.py --decode base32 "MNQXO==="

# Hex encode/decode
python src/crypto.py --encode hex "Hello"
python src/crypto.py --decode hex "48656c6c6f"

# Binary encode/decode
python src/crypto.py --encode binary "A"
# Çıktı: 01000001
```

### Caesar Cipher

```bash
# Encode (shift=3)
python src/crypto.py --encrypt caesar "Hello World" --shift 3
# Çıktı: Khoor Zruog

# Decode
python src/crypto.py --decrypt caesar "Khoor Zruog" --shift 3
# Çıktı: Hello World

# Brute Force (tüm shift değerleri dene)
python src/crypto.py --bruteforce "Khoor"
```

### ROT13

```bash
python src/crypto.py --encode rot13 "Hello"
# Çıktı: Uryyb
```

### XOR Cipher

```bash
# Encrypt
python src/crypto.py --encrypt xor "Hello" --key "K"

# Decrypt (hex girdi)
python src/crypto.py --decrypt xor "030e061e08" --key "K"
```

### Vigenere Cipher

```bash
# Encrypt
python src/crypto.py --encrypt vigenere "HELLO" --key "KEY"
# Çıktı: RIJVS

# Decrypt
python src/crypto.py --decrypt vigenere "RIJVS" --key "KEY"
# Çıktı: HELLO
```

### Frekans Analizi

```bash
python src/crypto.py --analyze "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
```

### Tüm Encoding'leri Göster

```bash
python src/crypto.py --all "CTF{test}"
```

---

## Steganografi Modülü

### LSB Bit Extraction

```bash
# PNG'den mesaj çıkar
python src/stego.py --lsb image.png

# 2-bit LSB
python src/stego.py --lsb image.png --bits 2
```

### LSB'ye Mesaj Gizleme

```bash
python src/stego.py --hide original.png --message "Gizli mesaj" --output output.png
```

### Strings Çıkarma

```bash
python src/stego.py --strings binary_file.bin

# Minimum uzunluk belirt
python src/stego.py --strings binary_file.bin --min-length 8
```

### File Carving

```bash
# Dosya içindeki gizli dosyaları tespit et
python src/stego.py --carve suspicious.jpg
```

### PNG Chunk Analizi

```bash
python src/stego.py --chunks image.png
```

### EOF Sonrası Veri Tespiti

```bash
# JPEG/PNG EOF sonrası ekstra veri var mı?
python src/stego.py --eof image.jpg
```

---

## Adli Bilişim Modülü

### Dosya Tipi Tespiti

```bash
# Magic bytes ile gerçek dosya tipini öğren
python src/forensics.py --identify suspicious_file

# Dizindeki tüm dosyaları analiz et
python src/forensics.py --dir-analyze ./dizin
```

### EXIF Metadata

```bash
python src/forensics.py --exif photo.jpg
```

### Hex Dump

```bash
# İlk 256 byte
python src/forensics.py --hexdump file.bin

# Offset ve uzunluk belirt
python src/forensics.py --hexdump file.bin --offset 100 --length 512
```

### Zaman Damgası Analizi

```bash
python src/forensics.py --timestamps file.jpg
```

### Hash Hesaplama

```bash
python src/forensics.py --hashes file.exe
# MD5, SHA-1, SHA-256, SHA-512 aynı anda
```

### Entropi Analizi

```bash
python src/forensics.py --entropy suspicious.bin
# Yüksek entropi (>7) = şifreli veya sıkıştırılmış
```

### Dosya Karşılaştırma

```bash
python src/forensics.py --compare original.png modified.png
```

---

## Web Güvenliği Modülü

### URL Encoding

```bash
# Encode
python src/web.py --url-encode "Hello World & foo=bar"

# Decode
python src/web.py --url-decode "Hello%20World%20%26%20foo%3Dbar"
```

### HTML Entity Encoding

```bash
# Encode
python src/web.py --html-encode "<script>alert(1)</script>"
# Çıktı: &lt;script&gt;alert(1)&lt;/script&gt;

# Decode
python src/web.py --html-decode "&lt;script&gt;"
```

### JWT Token Decode

```bash
python src/web.py --jwt-decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
```

### Hash Tanımlama

```bash
python src/web.py --hash-id "5f4dcc3b5aa765d61d8327deb882cf99"
# Çıktı: MD5 (32 karakter)

python src/web.py --hash-id "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
# Çıktı: SHA-1 (40 karakter)
```

### Metin Hash'leme

```bash
python src/web.py --hash-text "password"
# MD5, SHA-1, SHA-256, SHA-512 hepsini gösterir
```

### URL Analizi

```bash
python src/web.py --analyze-url "https://example.com:8080/admin?id=1&user=admin#section"
```

### SQLi / XSS Payload Listesi

```bash
python src/web.py --sqli
python src/web.py --xss
```

---

## Gerçek CTF Senaryoları

### Senaryo 1: Şifreli Metin (Crypto)

```
Challenge: "Wkh iodjv lv: FWI{fdhvdu_flskhu_lv_ixq}"
Çözüm:
python src/crypto.py --bruteforce "Wkh iodjv lv: FWI{fdhvdu_flskhu_lv_ixq}"
→ Shift 3 ile: "The flags is: CTF{caesar_cipher_is_fun}"
```

### Senaryo 2: Gizli Resim (Stego)

```
Challenge: image.png dosyasında gizli bir bayrak var
Çözüm:
python src/stego.py --lsb image.png
(veya)
python src/stego.py --strings image.png
python src/stego.py --eof image.png
```

### Senaryo 3: Sahte Dosya (Forensics)

```
Challenge: "document.pdf" adlı dosyayı inceleyin
Çözüm:
python src/forensics.py --identify document.pdf
→ Gerçek tip: ZIP Archive!
python src/forensics.py --hexdump document.pdf
→ Magic bytes: 50 4B 03 04 (ZIP)
```

### Senaryo 4: JWT Manipülasyonu (Web)

```
Challenge: JWT token ile kimlik doğrulaması atlatın
Çözüm:
python src/web.py --jwt-decode "<token>"
→ Header: {"alg": "HS256"}, Payload: {"role": "user"}
→ alg değerini "none" yaparak role="admin" ile yeni token oluştur
```

---

## İnteraktif Mod

Tüm modüller interaktif menüyle de kullanılabilir:

```bash
python src/toolkit.py          # Ana menü
python src/crypto.py -i        # Sadece crypto
python src/stego.py -i         # Sadece stego
python src/forensics.py -i     # Sadece forensics
python src/web.py -i           # Sadece web
```

---

## Testleri Çalıştırma

```bash
python tests/test_toolkit.py -v
```

---

*Author: Muhammet Özkaya | GitHub: https://github.com/muhammetozkaya/ctf-toolkit*
