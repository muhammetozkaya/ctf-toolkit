#!/usr/bin/env python3
"""
CTF Toolkit - Cryptography Module
Author: Muhammet Özkaya
GitHub: https://github.com/muhammetozkaya/ctf-toolkit
"""

import base64
import argparse
import sys
import string
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BANNER = """
[bold cyan]
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ 
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ 
[/bold cyan]
[bold yellow]              CTF Toolkit - Crypto Module[/bold yellow]
[dim]              Author: Muhammet Özkaya[/dim]
"""

# ─── Base Encoding/Decoding ────────────────────────────────────────────────────

def base64_encode(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def base64_decode(data: str) -> str:
    try:
        return base64.b64decode(data).decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

def base32_encode(data: str) -> str:
    return base64.b32encode(data.encode()).decode()

def base32_decode(data: str) -> str:
    try:
        # Pad if needed
        pad = len(data) % 8
        if pad:
            data += '=' * (8 - pad)
        return base64.b32decode(data.upper()).decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

def base16_encode(data: str) -> str:
    return base64.b16encode(data.encode()).decode()

def base16_decode(data: str) -> str:
    try:
        return base64.b16decode(data.upper()).decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

def hex_encode(data: str) -> str:
    return data.encode().hex()

def hex_decode(data: str) -> str:
    try:
        return bytes.fromhex(data.replace(' ', '')).decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

def binary_encode(data: str) -> str:
    return ' '.join(format(ord(c), '08b') for c in data)

def binary_decode(data: str) -> str:
    try:
        bits = data.replace(' ', '')
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        return ''.join(chars)
    except Exception as e:
        return f"[ERROR] {e}"

# ─── Caesar / ROT Ciphers ──────────────────────────────────────────────────────

def caesar_cipher(text: str, shift: int, decode: bool = False) -> str:
    if decode:
        shift = -shift
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)

def rot13(text: str) -> str:
    return caesar_cipher(text, 13)

def caesar_bruteforce(text: str) -> list:
    results = []
    for shift in range(1, 26):
        decoded = caesar_cipher(text, shift, decode=True)
        results.append((shift, decoded))
    return results

# ─── XOR Cipher ───────────────────────────────────────────────────────────────

def xor_encrypt(text: str, key: str) -> str:
    result = []
    for i, char in enumerate(text):
        result.append(chr(ord(char) ^ ord(key[i % len(key)])))
    return ''.join(result)

def xor_hex(text: str, key: str) -> str:
    """XOR and return hex output"""
    result = xor_encrypt(text, key)
    return result.encode().hex()

def xor_with_key_hex(hex_text: str, key: str) -> str:
    """XOR from hex input"""
    try:
        text = bytes.fromhex(hex_text).decode(errors='replace')
        return xor_encrypt(text, key)
    except Exception as e:
        return f"[ERROR] {e}"

# ─── Vigenere Cipher ──────────────────────────────────────────────────────────

def vigenere_encrypt(text: str, key: str) -> str:
    result = []
    key = key.upper()
    key_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(text: str, key: str) -> str:
    result = []
    key = key.upper()
    key_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

# ─── Frequency Analysis ───────────────────────────────────────────────────────

def frequency_analysis(text: str) -> dict:
    text_upper = text.upper()
    letters = [c for c in text_upper if c.isalpha()]
    total = len(letters)
    if total == 0:
        return {}
    freq = Counter(letters)
    return {char: (count / total * 100) for char, count in sorted(freq.items(), key=lambda x: -x[1])}

ENGLISH_FREQ = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
    'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
    'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
    'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
    'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1, 'Z': 0.1
}

# ─── Atbash Cipher ────────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(char) - base)))
        else:
            result.append(char)
    return ''.join(result)

# ─── Morse Code ───────────────────────────────────────────────────────────────

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', ' ': '/'
}
MORSE_REVERSE = {v: k for k, v in MORSE_CODE.items()}

def morse_encode(text: str) -> str:
    return ' '.join(MORSE_CODE.get(c.upper(), '?') for c in text)

def morse_decode(code: str) -> str:
    return ''.join(MORSE_REVERSE.get(token, '?') for token in code.split(' '))

# ─── Display Helpers ──────────────────────────────────────────────────────────

def display_result(label: str, result: str):
    panel = Panel(
        Text(result, style="bold green"),
        title=f"[bold yellow]{label}[/bold yellow]",
        border_style="cyan",
        box=box.ROUNDED
    )
    console.print(panel)

def display_bruteforce(results: list, text: str):
    table = Table(title="Caesar Cipher Brute Force", box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("Shift", style="bold yellow", justify="center")
    table.add_column("Decrypted Text", style="green")
    for shift, decoded in results:
        table.add_row(str(shift), decoded[:80])
    console.print(table)

def display_frequency(freq: dict, text: str):
    table = Table(title="Frequency Analysis", box=box.SIMPLE_HEAD, border_style="cyan")
    table.add_column("Letter", style="bold yellow", justify="center")
    table.add_column("Count %", style="cyan", justify="right")
    table.add_column("English %", style="dim", justify="right")
    table.add_column("Bar", style="green")

    for char, pct in list(freq.items())[:10]:
        bar = "█" * int(pct / 2)
        eng = ENGLISH_FREQ.get(char, 0)
        table.add_row(char, f"{pct:.2f}%", f"{eng:.2f}%", bar)
    console.print(table)

def show_all_encodings(text: str):
    table = Table(title=f"All Encodings for: '{text}'", box=box.ROUNDED, border_style="cyan")
    table.add_column("Method", style="bold yellow")
    table.add_column("Result", style="green")
    table.add_row("Base64", base64_encode(text))
    table.add_row("Base32", base32_encode(text))
    table.add_row("Base16", base16_encode(text))
    table.add_row("Hex", hex_encode(text))
    table.add_row("Binary", binary_encode(text))
    table.add_row("ROT13", rot13(text))
    table.add_row("Atbash", atbash(text))
    table.add_row("Morse", morse_encode(text))
    console.print(table)

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    from rich.prompt import Prompt, IntPrompt

    while True:
        console.print(BANNER)
        console.print(Panel(
            "[1] Base64 Encode/Decode\n"
            "[2] Base32 Encode/Decode\n"
            "[3] Base16/Hex Encode/Decode\n"
            "[4] ROT13\n"
            "[5] Caesar Cipher\n"
            "[6] XOR Cipher\n"
            "[7] Vigenere Cipher\n"
            "[8] Frequency Analysis\n"
            "[9] Atbash Cipher\n"
            "[10] Morse Code\n"
            "[11] Show All Encodings\n"
            "[12] Caesar Brute Force\n"
            "[0] Ana Menüye Dön",
            title="[bold cyan]🔐 Kriptografi Araçları[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED
        ))

        choice = Prompt.ask("[bold yellow]Seçim[/bold yellow]", default="0")

        if choice == "0":
            break
        elif choice == "1":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            result = base64_encode(text) if op == "encode" else base64_decode(text)
            display_result(f"Base64 {op.capitalize()}", result)
        elif choice == "2":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            result = base32_encode(text) if op == "encode" else base32_decode(text)
            display_result(f"Base32 {op.capitalize()}", result)
        elif choice == "3":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            result = base16_encode(text) if op == "encode" else base16_decode(text)
            display_result(f"Base16 {op.capitalize()}", result)
        elif choice == "4":
            text = Prompt.ask("Metin")
            display_result("ROT13", rot13(text))
        elif choice == "5":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            shift = IntPrompt.ask("Shift değeri", default=13)
            result = caesar_cipher(text, shift, decode=(op == "decode"))
            display_result(f"Caesar Cipher (shift={shift})", result)
        elif choice == "6":
            text = Prompt.ask("Metin")
            key = Prompt.ask("Anahtar")
            result = xor_encrypt(text, key)
            display_result("XOR Çıktı (hex)", result.encode().hex())
        elif choice == "7":
            op = Prompt.ask("İşlem", choices=["encrypt", "decrypt"])
            text = Prompt.ask("Metin")
            key = Prompt.ask("Anahtar")
            result = vigenere_encrypt(text, key) if op == "encrypt" else vigenere_decrypt(text, key)
            display_result(f"Vigenere {op.capitalize()}", result)
        elif choice == "8":
            text = Prompt.ask("Analiz edilecek metin")
            freq = frequency_analysis(text)
            display_frequency(freq, text)
        elif choice == "9":
            text = Prompt.ask("Metin")
            display_result("Atbash", atbash(text))
        elif choice == "10":
            op = Prompt.ask("İşlem", choices=["encode", "decode"])
            text = Prompt.ask("Metin")
            result = morse_encode(text) if op == "encode" else morse_decode(text)
            display_result(f"Morse {op.capitalize()}", result)
        elif choice == "11":
            text = Prompt.ask("Metin")
            show_all_encodings(text)
        elif choice == "12":
            text = Prompt.ask("Şifreli metin")
            results = caesar_bruteforce(text)
            display_bruteforce(results, text)
        else:
            console.print("[red]Geçersiz seçim![/red]")

        Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
        console.clear()

# ─── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTF Toolkit - Crypto Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crypto.py --encode base64 "Hello World"
  python crypto.py --decode base64 "SGVsbG8gV29ybGQ="
  python crypto.py --encode rot13 "Hello"
  python crypto.py --decode caesar "Khoor" --shift 3
  python crypto.py --encode vigenere "Hello" --key "KEY"
  python crypto.py --analyze "Kyv zj k yv ccf"
  python crypto.py --bruteforce "Khoor Zruog"
        """
    )

    parser.add_argument('--encode', metavar='METHOD', help='Encoding method: base64, base32, base16, hex, binary, rot13, atbash, morse')
    parser.add_argument('--decode', metavar='METHOD', help='Decoding method: base64, base32, base16, hex, binary, rot13, atbash, morse')
    parser.add_argument('--encrypt', metavar='METHOD', help='Encrypt: caesar, vigenere, xor')
    parser.add_argument('--decrypt', metavar='METHOD', help='Decrypt: caesar, vigenere, xor')
    parser.add_argument('--analyze', metavar='TEXT', help='Frequency analysis on text')
    parser.add_argument('--bruteforce', metavar='TEXT', help='Caesar cipher brute force')
    parser.add_argument('--all', metavar='TEXT', help='Show all encodings')
    parser.add_argument('text', nargs='?', help='Input text')
    parser.add_argument('--shift', type=int, default=13, help='Caesar shift value')
    parser.add_argument('--key', type=str, default='KEY', help='Cipher key')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_menu()
        return

    console.print(BANNER)

    if args.analyze:
        freq = frequency_analysis(args.analyze)
        display_frequency(freq, args.analyze)
        return

    if args.bruteforce:
        results = caesar_bruteforce(args.bruteforce)
        display_bruteforce(results, args.bruteforce)
        return

    if args.all:
        show_all_encodings(args.all)
        return

    text = args.text or ""

    if args.encode:
        method = args.encode.lower()
        methods = {
            'base64': base64_encode, 'base32': base32_encode,
            'base16': base16_encode, 'hex': hex_encode,
            'binary': binary_encode, 'rot13': rot13,
            'atbash': atbash, 'morse': morse_encode,
        }
        if method in methods:
            display_result(f"{method.upper()} Encoded", methods[method](text))
        else:
            console.print(f"[red]Bilinmeyen method: {method}[/red]")

    elif args.decode:
        method = args.decode.lower()
        methods = {
            'base64': base64_decode, 'base32': base32_decode,
            'base16': base16_decode, 'hex': hex_decode,
            'binary': binary_decode, 'rot13': rot13,
            'atbash': atbash, 'morse': morse_decode,
        }
        if method in methods:
            display_result(f"{method.upper()} Decoded", methods[method](text))
        else:
            console.print(f"[red]Bilinmeyen method: {method}[/red]")

    elif args.encrypt:
        method = args.encrypt.lower()
        if method == 'caesar':
            display_result("Caesar Encrypted", caesar_cipher(text, args.shift))
        elif method == 'vigenere':
            display_result("Vigenere Encrypted", vigenere_encrypt(text, args.key))
        elif method == 'xor':
            display_result("XOR Encrypted (hex)", xor_hex(text, args.key))

    elif args.decrypt:
        method = args.decrypt.lower()
        if method == 'caesar':
            display_result("Caesar Decrypted", caesar_cipher(text, args.shift, decode=True))
        elif method == 'vigenere':
            display_result("Vigenere Decrypted", vigenere_decrypt(text, args.key))
        elif method == 'xor':
            display_result("XOR Decrypted", xor_with_key_hex(text, args.key))

if __name__ == '__main__':
    main()
