#!/usr/bin/env python3
"""
CTF Toolkit - Steganography Module
Author: Muhammet Özkaya
GitHub: https://github.com/muhammetozkaya/ctf-toolkit
"""

import argparse
import sys
import os
import struct
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

BANNER = """
[bold magenta]
 ██████╗████████╗███████╗ ██████╗  ██████╗ 
██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗
╚█████╗    ██║   █████╗  ██║  ███╗██║   ██║
 ╚═══██╗   ██║   ██╔══╝  ██║   ██║██║   ██║
██████╔╝   ██║   ███████╗╚██████╔╝╚██████╔╝
╚═════╝    ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ 
[/bold magenta]
[bold yellow]           CTF Toolkit - Stego Module[/bold yellow]
[dim]           Author: Muhammet Özkaya[/dim]
"""

# ─── File Signatures (Magic Bytes) ────────────────────────────────────────────

FILE_SIGNATURES = {
    b'\x89PNG\r\n\x1a\n': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'GIF87a': 'GIF Image (87a)',
    b'GIF89a': 'GIF Image (89a)',
    b'BM': 'BMP Image',
    b'PK\x03\x04': 'ZIP Archive',
    b'Rar!': 'RAR Archive',
    b'\x1f\x8b': 'GZIP Archive',
    b'%PDF': 'PDF Document',
    b'\x7fELF': 'ELF Executable',
    b'MZ': 'Windows PE/EXE',
    b'\xca\xfe\xba\xbe': 'Java Class',
    b'RIFF': 'WAV/AVI File',
    b'ftyp': 'MP4/MOV Video',
    b'ID3': 'MP3 Audio',
    b'\x00\x01\x00\x00': 'TTF Font',
    b'OggS': 'OGG Audio',
    b'\x42\x5a\x68': 'BZ2 Archive',
    b'\xfd7zXZ\x00': 'XZ Archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
    b'<!DOCTYPE html': 'HTML Document',
    b'<html': 'HTML Document',
    b'#!': 'Shell Script',
}

# ─── LSB Extraction ───────────────────────────────────────────────────────────

def lsb_extract_png(filepath: str, num_bits: int = 1) -> str:
    """Extract LSB from PNG image pixels"""
    try:
        from PIL import Image
        img = Image.open(filepath)
        img = img.convert('RGB')
        pixels = list(img.getdata())

        bits = []
        for pixel in pixels:
            for channel in pixel:
                for bit_pos in range(num_bits):
                    bits.append((channel >> bit_pos) & 1)

        # Convert bits to bytes
        chars = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) < 8:
                break
            byte_val = 0
            for j, bit in enumerate(byte_bits):
                byte_val |= bit << j
            if byte_val == 0:
                break
            chars.append(chr(byte_val))

        result = ''.join(chars)
        # Only return printable content
        printable = ''.join(c for c in result if c.isprintable() or c in '\n\r\t')
        return printable[:500] if printable else "[No readable LSB data found]"

    except ImportError:
        return "[ERROR] Pillow kütüphanesi gerekli: pip install Pillow"
    except Exception as e:
        return f"[ERROR] {e}"

def lsb_hide_message(image_path: str, message: str, output_path: str) -> bool:
    """Hide a message in image using LSB steganography"""
    try:
        from PIL import Image
        img = Image.open(image_path)
        img = img.convert('RGB')
        pixels = list(img.getdata())

        message_bits = []
        for char in message + '\x00':
            for bit_pos in range(8):
                message_bits.append((ord(char) >> bit_pos) & 1)

        if len(message_bits) > len(pixels) * 3:
            return False

        new_pixels = []
        bit_idx = 0
        for pixel in pixels:
            new_pixel = list(pixel)
            for ch_idx in range(3):
                if bit_idx < len(message_bits):
                    new_pixel[ch_idx] = (new_pixel[ch_idx] & ~1) | message_bits[bit_idx]
                    bit_idx += 1
            new_pixels.append(tuple(new_pixel))

        new_img = Image.new('RGB', img.size)
        new_img.putdata(new_pixels)
        new_img.save(output_path)
        return True

    except ImportError:
        console.print("[red]Pillow kütüphanesi gerekli: pip install Pillow[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Hata: {e}[/red]")
        return False

# ─── Strings Extraction ───────────────────────────────────────────────────────

def extract_strings(filepath: str, min_length: int = 4) -> list:
    """Extract printable strings from any file"""
    strings = []
    current = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        for byte in data:
            char = chr(byte)
            if char.isprintable() and char != '\n':
                current.append(char)
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    except Exception as e:
        return [f"[ERROR] {e}"]

def extract_urls(strings_list: list) -> list:
    """Extract URLs from strings"""
    urls = []
    for s in strings_list:
        if any(s.startswith(proto) for proto in ['http://', 'https://', 'ftp://', 'file://']):
            urls.append(s)
    return urls

def extract_emails(strings_list: list) -> list:
    """Extract emails from strings"""
    emails = []
    for s in strings_list:
        if '@' in s and '.' in s.split('@')[-1]:
            emails.append(s)
    return emails

def extract_flags(strings_list: list, prefix: str = 'CTF{') -> list:
    """Extract CTF flags from strings"""
    flags = []
    for s in strings_list:
        if prefix.lower() in s.lower() or 'flag{' in s.lower():
            flags.append(s)
    return flags

# ─── File Carving ─────────────────────────────────────────────────────────────

def file_carve(filepath: str) -> list:
    """Detect hidden files based on magic bytes"""
    found_files = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        for sig, filetype in FILE_SIGNATURES.items():
            pos = 0
            while True:
                idx = data.find(sig, pos)
                if idx == -1:
                    break
                if idx == 0 and pos == 0:
                    pos = idx + 1
                    continue
                found_files.append({
                    'offset': idx,
                    'offset_hex': hex(idx),
                    'type': filetype,
                    'signature': sig.hex(),
                    'preview': data[idx:idx+16].hex()
                })
                pos = idx + 1

        return found_files

    except Exception as e:
        return [{'error': str(e)}]

def detect_appended_data(filepath: str) -> dict:
    """Detect data appended after EOF markers"""
    results = {}

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # JPEG EOF
        jpeg_eof = data.find(b'\xff\xd9')
        if jpeg_eof != -1 and jpeg_eof < len(data) - 2:
            appended = data[jpeg_eof + 2:]
            if len(appended) > 0:
                results['jpeg_appended'] = {
                    'size': len(appended),
                    'preview_hex': appended[:32].hex(),
                    'preview_text': appended[:32].decode(errors='replace')
                }

        # PNG IEND
        png_iend = data.find(b'IEND\xaeB`\x82')
        if png_iend != -1:
            appended = data[png_iend + 8:]
            if len(appended) > 0:
                results['png_appended'] = {
                    'size': len(appended),
                    'preview_hex': appended[:32].hex(),
                    'preview_text': appended[:32].decode(errors='replace')
                }

        # ZIP at the end
        zip_sig = data.rfind(b'PK\x03\x04')
        if zip_sig > 0:
            results['embedded_zip'] = {
                'offset': zip_sig,
                'offset_hex': hex(zip_sig)
            }

        return results

    except Exception as e:
        return {'error': str(e)}

# ─── Metadata Extraction ──────────────────────────────────────────────────────

def extract_metadata(filepath: str) -> dict:
    """Extract basic metadata from file"""
    path = Path(filepath)
    if not path.exists():
        return {'error': 'File not found'}

    stat = path.stat()
    meta = {
        'filename': path.name,
        'size': stat.st_size,
        'size_human': f"{stat.st_size / 1024:.2f} KB",
        'extension': path.suffix,
        'created': stat.st_ctime,
        'modified': stat.st_mtime,
    }

    # Read magic bytes
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
        meta['magic_bytes'] = header.hex()
        meta['file_type'] = detect_file_type(header)
    except Exception as e:
        meta['magic_error'] = str(e)

    return meta

def detect_file_type(header: bytes) -> str:
    for sig, ftype in FILE_SIGNATURES.items():
        if header[:len(sig)] == sig:
            return ftype
    return 'Unknown'

# ─── PNG Chunk Analysis ───────────────────────────────────────────────────────

def analyze_png_chunks(filepath: str) -> list:
    """Analyze PNG chunks for hidden data"""
    chunks = []
    try:
        with open(filepath, 'rb') as f:
            signature = f.read(8)
            if signature != b'\x89PNG\r\n\x1a\n':
                return [{'error': 'Not a valid PNG file'}]

            while True:
                length_data = f.read(4)
                if len(length_data) < 4:
                    break
                length = struct.unpack('>I', length_data)[0]
                chunk_type = f.read(4).decode('ascii', errors='replace')
                data = f.read(length)
                crc = f.read(4)

                chunk_info = {
                    'type': chunk_type,
                    'length': length,
                    'crc': crc.hex(),
                }

                # Check for text chunks
                if chunk_type in ('tEXt', 'zTXt', 'iTXt'):
                    chunk_info['text_data'] = data.decode('utf-8', errors='replace')
                    chunk_info['suspicious'] = True

                chunks.append(chunk_info)

                if chunk_type == 'IEND':
                    break

    except Exception as e:
        return [{'error': str(e)}]

    return chunks

# ─── Display Helpers ──────────────────────────────────────────────────────────

def display_strings(strings: list, show_flags: bool = True):
    table = Table(title=f"Extracted Strings ({len(strings)} found)", box=box.SIMPLE_HEAD, border_style="magenta")
    table.add_column("#", style="dim", justify="right")
    table.add_column("String", style="green")
    table.add_column("Length", style="cyan", justify="right")

    flags = extract_flags(strings)
    urls = extract_urls(strings)

    if flags:
        console.print(Panel(
            '\n'.join(f"[bold green]🚩 {f}[/bold green]" for f in flags),
            title="[bold red]⚠️  OLASI FLAG BULUNDU![/bold red]",
            border_style="red"
        ))

    if urls:
        console.print(Panel(
            '\n'.join(f"[cyan]{u}[/cyan]" for u in urls[:10]),
            title="[bold yellow]🔗 URLs[/bold yellow]",
            border_style="yellow"
        ))

    for i, s in enumerate(strings[:50], 1):
        style = "bold green" if s in flags else "green"
        table.add_row(str(i), Text(s[:100], style=style), str(len(s)))

    console.print(table)
    if len(strings) > 50:
        console.print(f"[dim]... ve {len(strings) - 50} string daha[/dim]")

def display_carved_files(files: list):
    if not files:
        console.print("[yellow]Gizli dosya bulunamadı.[/yellow]")
        return

    table = Table(title=f"File Carving Results ({len(files)} found)", box=box.ROUNDED, border_style="magenta")
    table.add_column("Offset", style="yellow")
    table.add_column("Hex Offset", style="cyan")
    table.add_column("File Type", style="bold green")
    table.add_column("Magic Bytes", style="dim")

    for f in files:
        if 'error' in f:
            console.print(f"[red]{f['error']}[/red]")
            continue
        table.add_row(
            str(f.get('offset', '-')),
            f.get('offset_hex', '-'),
            f.get('type', '-'),
            f.get('preview', '-')
        )
    console.print(table)

def display_png_chunks(chunks: list):
    table = Table(title="PNG Chunk Analysis", box=box.ROUNDED, border_style="magenta")
    table.add_column("Type", style="bold yellow")
    table.add_column("Length", style="cyan", justify="right")
    table.add_column("CRC", style="dim")
    table.add_column("Data", style="green")

    for chunk in chunks:
        if 'error' in chunk:
            console.print(f"[red]{chunk['error']}[/red]")
            continue

        chunk_type = chunk.get('type', '-')
        style = "bold red" if chunk.get('suspicious') else "bold yellow"
        text_data = chunk.get('text_data', '')[:60] if chunk.get('text_data') else ""

        table.add_row(
            Text(chunk_type, style=style),
            str(chunk.get('length', 0)),
            chunk.get('crc', '-'),
            text_data
        )

    console.print(table)

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    from rich.prompt import Prompt, IntPrompt

    while True:
        console.print(BANNER)
        console.print(Panel(
            "[1] LSB Bit Extraction (PNG/JPG)\n"
            "[2] Strings Çıkarma\n"
            "[3] File Carving (Gizli Dosya Tespiti)\n"
            "[4] PNG Chunk Analizi\n"
            "[5] Dosya Metadata\n"
            "[6] EOF Sonrası Veri Tespiti\n"
            "[7] LSB'ye Mesaj Gizle\n"
            "[0] Ana Menüye Dön",
            title="[bold magenta]🖼️  Steganografi Araçları[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED
        ))

        choice = Prompt.ask("[bold yellow]Seçim[/bold yellow]", default="0")

        if choice == "0":
            break
        elif choice == "1":
            filepath = Prompt.ask("Resim dosyası yolu")
            bits = IntPrompt.ask("LSB bit sayısı", default=1)
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                with Progress(SpinnerColumn(), TextColumn("[cyan]Analiz ediliyor...")) as p:
                    task = p.add_task("", total=None)
                    result = lsb_extract_png(filepath, bits)
                console.print(Panel(result, title="[green]LSB Data[/green]", border_style="green"))
        elif choice == "2":
            filepath = Prompt.ask("Dosya yolu")
            min_len = IntPrompt.ask("Minimum string uzunluğu", default=4)
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                with Progress(SpinnerColumn(), TextColumn("[cyan]Strings çıkarılıyor...")) as p:
                    task = p.add_task("", total=None)
                    strings = extract_strings(filepath, min_len)
                display_strings(strings)
        elif choice == "3":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                with Progress(SpinnerColumn(), TextColumn("[cyan]File carving...")) as p:
                    task = p.add_task("", total=None)
                    files = file_carve(filepath)
                display_carved_files(files)
        elif choice == "4":
            filepath = Prompt.ask("PNG dosyası yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                chunks = analyze_png_chunks(filepath)
                display_png_chunks(chunks)
        elif choice == "5":
            filepath = Prompt.ask("Dosya yolu")
            meta = extract_metadata(filepath)
            table = Table(title="Dosya Metadata", box=box.ROUNDED, border_style="magenta")
            table.add_column("Alan", style="bold yellow")
            table.add_column("Değer", style="green")
            for k, v in meta.items():
                table.add_row(k, str(v))
            console.print(table)
        elif choice == "6":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                results = detect_appended_data(filepath)
                if results:
                    table = Table(title="EOF Sonrası Veri", box=box.ROUNDED, border_style="red")
                    table.add_column("Tür", style="bold red")
                    table.add_column("Bilgi", style="yellow")
                    for k, v in results.items():
                        table.add_row(k, str(v))
                    console.print(table)
                else:
                    console.print("[green]EOF sonrası ekstra veri bulunamadı.[/green]")
        elif choice == "7":
            img = Prompt.ask("Kaynak resim yolu")
            msg = Prompt.ask("Gizlenecek mesaj")
            out = Prompt.ask("Çıktı dosyası yolu", default="output_stego.png")
            if lsb_hide_message(img, msg, out):
                console.print(f"[green]✓ Mesaj başarıyla gizlendi: {out}[/green]")
            else:
                console.print("[red]Mesaj gizleme başarısız![/red]")
        else:
            console.print("[red]Geçersiz seçim![/red]")

        Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
        console.clear()

# ─── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTF Toolkit - Stego Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stego.py --lsb image.png
  python stego.py --strings binary_file
  python stego.py --carve suspicious.jpg
  python stego.py --chunks image.png
  python stego.py --eof image.jpg
        """
    )
    parser.add_argument('--lsb', metavar='FILE', help='LSB bit extraction')
    parser.add_argument('--strings', metavar='FILE', help='Extract strings from file')
    parser.add_argument('--carve', metavar='FILE', help='File carving - detect hidden files')
    parser.add_argument('--chunks', metavar='FILE', help='Analyze PNG chunks')
    parser.add_argument('--eof', metavar='FILE', help='Detect data after EOF')
    parser.add_argument('--meta', metavar='FILE', help='Extract file metadata')
    parser.add_argument('--hide', metavar='IMAGE', help='Hide message in image (use with --message and --output)')
    parser.add_argument('--message', metavar='MSG', help='Message to hide')
    parser.add_argument('--output', metavar='OUT', default='output_stego.png', help='Output file')
    parser.add_argument('--bits', type=int, default=1, help='Number of LSB bits (default: 1)')
    parser.add_argument('--min-length', type=int, default=4, help='Minimum string length')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_menu()
        return

    console.print(BANNER)

    if args.lsb:
        result = lsb_extract_png(args.lsb, args.bits)
        console.print(Panel(result, title="[green]LSB Extraction[/green]", border_style="green"))

    elif args.strings:
        strings = extract_strings(args.strings, args.min_length)
        display_strings(strings)

    elif args.carve:
        files = file_carve(args.carve)
        display_carved_files(files)

        appended = detect_appended_data(args.carve)
        if appended:
            console.print(Panel(str(appended), title="[red]EOF Sonrası Veri[/red]", border_style="red"))

    elif args.chunks:
        chunks = analyze_png_chunks(args.chunks)
        display_png_chunks(chunks)

    elif args.eof:
        results = detect_appended_data(args.eof)
        if results:
            for k, v in results.items():
                console.print(f"[red]{k}:[/red] {v}")
        else:
            console.print("[green]EOF sonrası ekstra veri bulunamadı.[/green]")

    elif args.meta:
        meta = extract_metadata(args.meta)
        table = Table(title="File Metadata", box=box.ROUNDED, border_style="magenta")
        table.add_column("Field", style="bold yellow")
        table.add_column("Value", style="green")
        for k, v in meta.items():
            table.add_row(k, str(v))
        console.print(table)

    elif args.hide:
        if not args.message:
            console.print("[red]--message parametresi gerekli![/red]")
            sys.exit(1)
        if lsb_hide_message(args.hide, args.message, args.output):
            console.print(f"[green]✓ Mesaj gizlendi: {args.output}[/green]")

if __name__ == '__main__':
    main()
