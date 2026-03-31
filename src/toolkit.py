#!/usr/bin/env python3
"""
CTF Toolkit - Main Interactive Menu
Author: Muhammet Özkaya
GitHub: https://github.com/muhammetozkaya/ctf-toolkit
"""

import sys
import os
import subprocess
import platform
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.layout import Layout
from rich.live import Live
from rich import box
from rich.prompt import Prompt

console = Console()

# ─── ASCII Banner ─────────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]
 ██████╗████████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚══██╔══╝██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║        ██║   █████╗         ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
██║        ██║   ██╔══╝         ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
╚██████╗   ██║   ██║            ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
 ╚═════╝   ╚═╝   ╚═╝            ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
[/bold cyan]"""

TAGLINE = "[bold yellow]⚡ Her CTF yarışmasında yanında olan araç seti ⚡[/bold yellow]"

AUTHOR_INFO = """[dim]
  Author  : Muhammet Özkaya
  GitHub  : https://github.com/muhammetozkaya/ctf-toolkit
  Version : 1.0.0
[/dim]"""

MODULE_DESCRIPTIONS = {
    "1": {
        "name": "🔐 Kriptografi Araçları",
        "module": "crypto",
        "color": "cyan",
        "features": [
            "Base64 / Base32 / Base16 Encode-Decode",
            "Hex / Binary Encode-Decode",
            "ROT13 / Caesar Cipher + Brute Force",
            "Vigenere Cipher",
            "XOR Şifreleme",
            "Atbash Cipher",
            "Morse Kodu",
            "Frekans Analizi",
        ]
    },
    "2": {
        "name": "🖼️  Steganografi Araçları",
        "module": "stego",
        "color": "magenta",
        "features": [
            "PNG/JPG LSB Bit Extraction",
            "LSB'ye Mesaj Gizleme",
            "Strings Çıkarma",
            "File Carving (Gizli Dosya Tespiti)",
            "PNG Chunk Analizi",
            "EOF Sonrası Veri Tespiti",
            "Flag / URL / Email Arama",
            "Dosya Metadata",
        ]
    },
    "3": {
        "name": "🔬 Adli Bilişim Araçları",
        "module": "forensics",
        "color": "red",
        "features": [
            "Magic Bytes Dosya Tipi Tespiti",
            "EXIF Metadata Okuma",
            "Hex Dump Görüntüleme",
            "Zaman Damgası Analizi",
            "MD5/SHA1/SHA256/SHA512 Hash",
            "Shannon Entropi Analizi",
            "Dosya Karşılaştırma",
            "Dizin Toplu Analiz",
        ]
    },
    "4": {
        "name": "🌐 Web Güvenliği Araçları",
        "module": "web",
        "color": "blue",
        "features": [
            "URL Encode / Decode",
            "HTML Entity Encode/Decode",
            "JWT Token Decode + Analiz",
            "Hash Tanımlama",
            "Çoklu Hash'leme",
            "URL Bileşen Analizi",
            "Cookie Decoder",
            "SQLi / XSS Payload Listesi",
        ]
    },
}

# ─── Helper Functions ─────────────────────────────────────────────────────────

def get_src_dir():
    return Path(__file__).parent

def run_module(module_name: str):
    src_dir = get_src_dir()
    module_path = src_dir / f"{module_name}.py"
    if not module_path.exists():
        console.print(f"[red]Modül bulunamadı: {module_path}[/red]")
        return

    try:
        subprocess.run([sys.executable, str(module_path), "--interactive"], check=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]Hata: {e}[/red]")

def display_banner():
    console.print(BANNER)
    console.print(Align.center(TAGLINE))
    console.print(Align.center(AUTHOR_INFO))
    console.print()

def display_main_menu():
    # Module cards
    panels = []
    for key, info in MODULE_DESCRIPTIONS.items():
        features_text = "\n".join(f"  [dim]▸[/dim] {f}" for f in info['features'])
        panel = Panel(
            features_text,
            title=f"[bold {info['color']}][{key}] {info['name']}[/bold {info['color']}]",
            border_style=info['color'],
            box=box.ROUNDED,
            padding=(0, 1),
        )
        panels.append(panel)

    # Display in 2x2 grid
    console.print(Columns([panels[0], panels[1]], equal=True, expand=True))
    console.print()
    console.print(Columns([panels[2], panels[3]], equal=True, expand=True))
    console.print()

    # Bottom options
    console.print(Panel(
        "[5] 📋 Wordlist Görüntüle    [6] ℹ️  Hakkında    [7] 🔧 Sistem Bilgisi    [0] Çıkış",
        border_style="dim",
        box=box.SIMPLE
    ))

def display_about():
    about_text = """
[bold cyan]CTF Toolkit[/bold cyan] - Capture The Flag Araç Seti

[bold yellow]Geliştirici:[/bold yellow] Muhammet Özkaya
[bold yellow]GitHub:[/bold yellow] https://github.com/muhammetozkaya/ctf-toolkit
[bold yellow]Versiyon:[/bold yellow] 1.0.0
[bold yellow]Python:[/bold yellow] 3.8+

[bold white]Desteklenen CTF Kategorileri:[/bold white]
  • Kriptografi (Crypto)
  • Steganografi (Stego) 
  • Adli Bilişim (Forensics)
  • Web Güvenliği (Web)

[bold white]Kullanılan Kütüphaneler:[/bold white]
  • rich        - Terminal arayüzü
  • Pillow      - Görüntü işleme
  • requests    - HTTP istekleri

[bold white]Lisans:[/bold white] MIT
"""
    console.print(Panel(
        about_text,
        title="[bold cyan]ℹ️  CTF Toolkit Hakkında[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    ))

def display_system_info():
    table = Table(title="🔧 Sistem Bilgisi", box=box.ROUNDED, border_style="yellow")
    table.add_column("Bileşen", style="bold yellow")
    table.add_column("Değer", style="green")

    table.add_row("İşletim Sistemi", f"{platform.system()} {platform.release()}")
    table.add_row("Python Versiyonu", sys.version.split()[0])
    table.add_row("Python Yolu", sys.executable)
    table.add_row("Platform", platform.platform())
    table.add_row("Mimari", platform.machine())

    # Check installed packages
    packages = ['rich', 'PIL', 'requests']
    for pkg in packages:
        try:
            __import__(pkg)
            table.add_row(f"Paket: {pkg}", "[green]✓ Kurulu[/green]")
        except ImportError:
            table.add_row(f"Paket: {pkg}", "[red]✗ Kurulu değil[/red]")

    console.print(table)

def display_wordlist():
    wordlist_path = get_src_dir().parent / "wordlists" / "common.txt"
    if not wordlist_path.exists():
        console.print("[red]Wordlist bulunamadı![/red]")
        return

    with open(wordlist_path, 'r', encoding='utf-8') as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    table = Table(
        title=f"📋 CTF Wordlist ({len(words)} kelime)",
        box=box.SIMPLE_HEAD,
        border_style="green"
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Kelime", style="bold green")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Kelime", style="bold green")

    pairs = []
    for i in range(0, len(words) - 1, 2):
        table.add_row(str(i+1), words[i], str(i+2), words[i+1])

    if len(words) % 2 == 1:
        table.add_row(str(len(words)), words[-1], "", "")

    console.print(table)

# ─── Quick Tools (Direct from main menu) ─────────────────────────────────────

def quick_decode_menu():
    """Quick decode tool accessible from main menu"""
    console.print(Panel(
        "Hızlı decode için bir metin girin. Tüm yöntemler otomatik denenir.",
        title="[bold cyan]⚡ Hızlı Decode[/bold cyan]",
        border_style="cyan"
    ))

    text = Prompt.ask("[bold yellow]Metin[/bold yellow]")
    if not text:
        return

    src_dir = get_src_dir()
    sys.path.insert(0, str(src_dir))

    try:
        import crypto
        results = Table(title="Hızlı Decode Sonuçları", box=box.ROUNDED, border_style="cyan")
        results.add_column("Yöntem", style="bold yellow")
        results.add_column("Sonuç", style="green")

        methods = [
            ("Base64", crypto.base64_decode),
            ("Base32", crypto.base32_decode),
            ("Base16", crypto.base16_decode),
            ("Hex", crypto.hex_decode),
            ("Binary", crypto.binary_decode),
            ("ROT13", crypto.rot13),
            ("Atbash", crypto.atbash),
        ]

        for name, func in methods:
            try:
                result = func(text)
                if result and not result.startswith('[ERROR]') and result != text:
                    results.add_row(name, result[:80])
            except:
                pass

        # Caesar brute force check
        try:
            bf = crypto.caesar_bruteforce(text)
            for shift, decoded in bf[:3]:
                results.add_row(f"Caesar (shift={shift})", decoded[:80])
        except:
            pass

        console.print(results)
    except ImportError as e:
        console.print(f"[red]crypto modülü yüklenemedi: {e}[/red]")

# ─── Main Loop ────────────────────────────────────────────────────────────────

def main():
    try:
        while True:
            console.clear()
            display_banner()
            display_main_menu()

            choice = Prompt.ask("[bold yellow]Modül seçin[/bold yellow]", default="0")

            if choice == "0":
                console.print("\n[bold cyan]İyi CTF'ler! 🚀[/bold cyan]\n")
                break
            elif choice in MODULE_DESCRIPTIONS:
                module_info = MODULE_DESCRIPTIONS[choice]
                console.clear()
                console.print(f"\n[bold {module_info['color']}]▶ {module_info['name']} başlatılıyor...[/bold {module_info['color']}]\n")
                run_module(module_info['module'])
            elif choice == "5":
                console.clear()
                display_wordlist()
                Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
            elif choice == "6":
                console.clear()
                display_about()
                Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
            elif choice == "7":
                console.clear()
                display_system_info()
                Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
            elif choice.lower() == "q":
                console.print("\n[bold cyan]İyi CTF'ler! 🚀[/bold cyan]\n")
                break
            else:
                console.print("[red]Geçersiz seçim![/red]")
                import time
                time.sleep(1)

    except KeyboardInterrupt:
        console.print("\n\n[bold cyan]Çıkılıyor... İyi CTF'ler! 🚀[/bold cyan]\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
