#!/usr/bin/env python3
"""
CTF Toolkit - Digital Forensics Module
Author: Muhammet Özkaya
GitHub: https://github.com/muhammetozkaya/ctf-toolkit
"""

import argparse
import sys
import os
import struct
import hashlib
import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

console = Console()

BANNER = """
[bold red]
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
[/bold red]
[bold yellow]              CTF Toolkit - Forensics Module[/bold yellow]
[dim]              Author: Muhammet Özkaya[/dim]
"""

# ─── Magic Bytes Database ─────────────────────────────────────────────────────

MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n':  {'type': 'PNG Image',          'ext': '.png',  'mime': 'image/png'},
    b'\xff\xd8\xff\xe0':   {'type': 'JPEG Image (JFIF)',   'ext': '.jpg',  'mime': 'image/jpeg'},
    b'\xff\xd8\xff\xe1':   {'type': 'JPEG Image (EXIF)',   'ext': '.jpg',  'mime': 'image/jpeg'},
    b'\xff\xd8\xff\xe2':   {'type': 'JPEG Image (ICC)',    'ext': '.jpg',  'mime': 'image/jpeg'},
    b'\xff\xd8\xff\xdb':   {'type': 'JPEG Image',          'ext': '.jpg',  'mime': 'image/jpeg'},
    b'GIF87a':             {'type': 'GIF 87a Image',       'ext': '.gif',  'mime': 'image/gif'},
    b'GIF89a':             {'type': 'GIF 89a Image',       'ext': '.gif',  'mime': 'image/gif'},
    b'BM':                 {'type': 'BMP Image',           'ext': '.bmp',  'mime': 'image/bmp'},
    b'RIFF':               {'type': 'WAV/AVI/WEBP File',   'ext': '.wav',  'mime': 'audio/wav'},
    b'\x00\x00\x01\x00':   {'type': 'ICO Icon',            'ext': '.ico',  'mime': 'image/x-icon'},
    b'PK\x03\x04':         {'type': 'ZIP Archive',         'ext': '.zip',  'mime': 'application/zip'},
    b'PK\x05\x06':         {'type': 'ZIP Archive (empty)', 'ext': '.zip',  'mime': 'application/zip'},
    b'Rar!\x1a\x07\x00':   {'type': 'RAR Archive (v4)',    'ext': '.rar',  'mime': 'application/x-rar'},
    b'Rar!\x1a\x07\x01':   {'type': 'RAR Archive (v5)',    'ext': '.rar',  'mime': 'application/x-rar'},
    b'\x1f\x8b':           {'type': 'GZIP Archive',        'ext': '.gz',   'mime': 'application/gzip'},
    b'\x42\x5a\x68':       {'type': 'BZ2 Archive',         'ext': '.bz2',  'mime': 'application/x-bzip2'},
    b'\xfd7zXZ\x00':       {'type': 'XZ Archive',          'ext': '.xz',   'mime': 'application/x-xz'},
    b'7z\xbc\xaf\x27\x1c': {'type': '7-Zip Archive',      'ext': '.7z',   'mime': 'application/x-7z-compressed'},
    b'%PDF':               {'type': 'PDF Document',        'ext': '.pdf',  'mime': 'application/pdf'},
    b'\x7fELF':            {'type': 'ELF Executable',      'ext': '',      'mime': 'application/x-elf'},
    b'MZ':                 {'type': 'Windows PE/EXE',      'ext': '.exe',  'mime': 'application/x-msdownload'},
    b'\xca\xfe\xba\xbe':   {'type': 'Java Class File',     'ext': '.class','mime': 'application/java-vm'},
    b'ID3':                {'type': 'MP3 Audio',           'ext': '.mp3',  'mime': 'audio/mpeg'},
    b'OggS':               {'type': 'OGG Audio/Video',     'ext': '.ogg',  'mime': 'audio/ogg'},
    b'fLaC':               {'type': 'FLAC Audio',          'ext': '.flac', 'mime': 'audio/flac'},
    b'\x00\x00\x00\x18ftyp': {'type': 'MP4 Video',        'ext': '.mp4',  'mime': 'video/mp4'},
    b'\x30\x26\xb2\x75':   {'type': 'WMV/ASF Video',      'ext': '.wmv',  'mime': 'video/x-ms-wmv'},
    b'<!DOCTYPE html':     {'type': 'HTML Document',       'ext': '.html', 'mime': 'text/html'},
    b'<html':              {'type': 'HTML Document',       'ext': '.html', 'mime': 'text/html'},
    b'<?xml':              {'type': 'XML Document',        'ext': '.xml',  'mime': 'text/xml'},
    b'#!':                 {'type': 'Shell Script',        'ext': '.sh',   'mime': 'text/x-shellscript'},
    b'\xd0\xcf\x11\xe0':   {'type': 'Microsoft Office (old)', 'ext': '.doc', 'mime': 'application/msword'},
    b'SQLite format 3':    {'type': 'SQLite Database',     'ext': '.db',   'mime': 'application/x-sqlite3'},
    b'\x4d\x5a':           {'type': 'DOS/PE Executable',  'ext': '.exe',  'mime': 'application/x-dosexec'},
}

# ─── File Type Detection ──────────────────────────────────────────────────────

def detect_file_type(filepath: str) -> dict:
    """Detect file type using magic bytes"""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(32)

        for sig, info in MAGIC_BYTES.items():
            if header[:len(sig)] == sig:
                return {**info, 'matched_signature': sig.hex()}

        # Try text detection
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                sample = f.read(256)
            return {'type': 'Text File (UTF-8)', 'ext': '.txt', 'mime': 'text/plain'}
        except UnicodeDecodeError:
            pass

        return {'type': 'Unknown/Binary', 'ext': '', 'mime': 'application/octet-stream'}

    except Exception as e:
        return {'error': str(e)}

def identify_directory(dirpath: str) -> list:
    """Identify all files in a directory"""
    results = []
    try:
        for root, dirs, files in os.walk(dirpath):
            for fname in files:
                fpath = os.path.join(root, fname)
                ftype = detect_file_type(fpath)
                stat = os.stat(fpath)
                results.append({
                    'file': fname,
                    'path': fpath,
                    'reported_ext': Path(fname).suffix,
                    'actual_type': ftype.get('type', 'Unknown'),
                    'expected_ext': ftype.get('ext', ''),
                    'size': stat.st_size,
                    'mismatch': Path(fname).suffix != ftype.get('ext', Path(fname).suffix)
                })
    except Exception as e:
        results.append({'error': str(e)})
    return results

# ─── EXIF Reader ──────────────────────────────────────────────────────────────

def read_exif(filepath: str) -> dict:
    """Read EXIF metadata from image"""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        import PIL.ExifTags

        img = Image.open(filepath)
        exif_data = {}

        raw_exif = img._getexif()
        if not raw_exif:
            return {'info': 'No EXIF data found'}

        for tag_id, value in raw_exif.items():
            tag = TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                try:
                    value = value.decode('utf-8', errors='replace')
                except:
                    value = value.hex()
            exif_data[tag] = str(value)[:200]

        # GPS Data
        gps_info = {}
        if 'GPSInfo' in exif_data:
            try:
                gps_raw = img._getexif().get(34853, {})
                for key, val in gps_raw.items():
                    tag = GPSTAGS.get(key, key)
                    gps_info[tag] = str(val)
                exif_data['GPS_Decoded'] = gps_info
            except:
                pass

        return exif_data

    except ImportError:
        return {'error': 'Pillow kütüphanesi gerekli: pip install Pillow'}
    except Exception as e:
        return {'error': str(e)}

# ─── Hex Dump ─────────────────────────────────────────────────────────────────

def hex_dump(filepath: str, offset: int = 0, length: int = 256) -> str:
    """Generate hex dump of file"""
    try:
        with open(filepath, 'rb') as f:
            f.seek(offset)
            data = f.read(length)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            addr = f"{offset + i:08x}"
            hex_part = ' '.join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(47)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{addr}  {hex_part}  |{ascii_part}|")

        return '\n'.join(lines)

    except Exception as e:
        return f"[ERROR] {e}"

def hex_dump_bytes(data: bytes, offset: int = 0) -> str:
    """Generate hex dump from bytes"""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        addr = f"{offset + i:08x}"
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{addr}  {hex_part}  |{ascii_part}|")
    return '\n'.join(lines)

# ─── Hash Calculation ─────────────────────────────────────────────────────────

def calculate_hashes(filepath: str) -> dict:
    """Calculate multiple hashes for a file"""
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512(),
    }

    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                for h in hashes.values():
                    h.update(chunk)

        return {name: h.hexdigest() for name, h in hashes.items()}

    except Exception as e:
        return {'error': str(e)}

# ─── Timestamp Analysis ───────────────────────────────────────────────────────

def analyze_timestamps(filepath: str) -> dict:
    """Analyze file timestamps"""
    try:
        stat = os.stat(filepath)

        def fmt(ts):
            dt = datetime.datetime.fromtimestamp(ts)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC') + f" (Unix: {int(ts)})"

        timestamps = {
            'Created (ctime)': fmt(stat.st_ctime),
            'Modified (mtime)': fmt(stat.st_mtime),
            'Accessed (atime)': fmt(stat.st_atime),
            'Size': f"{stat.st_size} bytes ({stat.st_size / 1024:.2f} KB)",
        }

        # Check for EXIF timestamps (images)
        try:
            from PIL import Image
            img = Image.open(filepath)
            exif = img._getexif()
            if exif:
                from PIL.ExifTags import TAGS
                for tag_id, val in exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if 'DateTime' in tag or 'Date' in tag:
                        timestamps[f'EXIF {tag}'] = str(val)
        except:
            pass

        return timestamps

    except Exception as e:
        return {'error': str(e)}

# ─── Entropy Analysis ─────────────────────────────────────────────────────────

def calculate_entropy(filepath: str) -> float:
    """Calculate Shannon entropy of file"""
    import math

    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        n = len(data)
        for count in freq.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    except Exception as e:
        return -1.0

def entropy_description(entropy: float) -> str:
    if entropy < 0: return "Hata"
    if entropy < 1: return "Çok düşük - muhtemelen tek bir karakter"
    if entropy < 3: return "Düşük - kısmen sıkıştırılmış veya tekrarlı veri"
    if entropy < 5: return "Orta - normal metin/kod"
    if entropy < 7: return "Yüksek - sıkıştırılmış veya şifreli"
    return "Çok yüksek (>7) - büyük olasılıkla şifreli/sıkıştırılmış"

# ─── File Comparison ──────────────────────────────────────────────────────────

def compare_files(file1: str, file2: str) -> dict:
    """Compare two files byte by byte"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()

        differences = []
        min_len = min(len(data1), len(data2))

        for i in range(min_len):
            if data1[i] != data2[i]:
                differences.append({
                    'offset': i,
                    'hex_offset': hex(i),
                    'file1_byte': f"{data1[i]:02x} ({chr(data1[i]) if 32 <= data1[i] < 127 else '.'})",
                    'file2_byte': f"{data2[i]:02x} ({chr(data2[i]) if 32 <= data2[i] < 127 else '.'})",
                })
                if len(differences) >= 50:
                    break

        return {
            'file1_size': len(data1),
            'file2_size': len(data2),
            'size_diff': abs(len(data1) - len(data2)),
            'identical': data1 == data2,
            'differences_found': len(differences),
            'differences': differences[:20],
        }

    except Exception as e:
        return {'error': str(e)}

# ─── Display Helpers ──────────────────────────────────────────────────────────

def display_file_type(result: dict, filepath: str):
    if 'error' in result:
        console.print(f"[red]{result['error']}[/red]")
        return

    panel = Panel(
        f"[bold green]Tip:[/bold green] {result.get('type', 'Unknown')}\n"
        f"[bold yellow]Uzantı:[/bold yellow] {result.get('ext', 'N/A')}\n"
        f"[bold cyan]MIME:[/bold cyan] {result.get('mime', 'N/A')}\n"
        f"[dim]Magic Bytes: {result.get('matched_signature', 'N/A')}[/dim]",
        title=f"[bold red]🔍 Dosya Tipi: {os.path.basename(filepath)}[/bold red]",
        border_style="red",
        box=box.ROUNDED
    )
    console.print(panel)

def display_exif(exif: dict):
    if 'error' in exif:
        console.print(f"[red]{exif['error']}[/red]")
        return

    table = Table(title="EXIF Metadata", box=box.ROUNDED, border_style="red")
    table.add_column("Tag", style="bold yellow", width=30)
    table.add_column("Value", style="green")

    for tag, val in exif.items():
        if isinstance(val, dict):
            for k, v in val.items():
                table.add_row(f"  {k}", str(v)[:100])
        else:
            table.add_row(tag, str(val)[:100])

    console.print(table)

def display_hashes(hashes: dict, filepath: str):
    table = Table(title=f"File Hashes: {os.path.basename(filepath)}", box=box.ROUNDED, border_style="red")
    table.add_column("Algorithm", style="bold yellow")
    table.add_column("Hash", style="green")

    for algo, h in hashes.items():
        table.add_row(algo.upper(), h)
    console.print(table)

def display_timestamps(timestamps: dict, filepath: str):
    table = Table(title=f"Timestamps: {os.path.basename(filepath)}", box=box.ROUNDED, border_style="red")
    table.add_column("Type", style="bold yellow")
    table.add_column("Value", style="green")

    for label, val in timestamps.items():
        table.add_row(label, str(val))
    console.print(table)

# ─── Interactive Menu ─────────────────────────────────────────────────────────

def interactive_menu():
    from rich.prompt import Prompt, IntPrompt

    while True:
        console.print(BANNER)
        console.print(Panel(
            "[1] Magic Bytes ile Dosya Tipi Tespiti\n"
            "[2] EXIF Metadata Okuma\n"
            "[3] Hex Dump Görüntüleme\n"
            "[4] Zaman Damgası Analizi\n"
            "[5] Hash Hesaplama (MD5/SHA1/SHA256/SHA512)\n"
            "[6] Entropi Analizi\n"
            "[7] Dosya Karşılaştırma\n"
            "[8] Dizin Analizi\n"
            "[0] Ana Menüye Dön",
            title="[bold red]🔬 Adli Bilişim Araçları[/bold red]",
            border_style="red",
            box=box.ROUNDED
        ))

        choice = Prompt.ask("[bold yellow]Seçim[/bold yellow]", default="0")

        if choice == "0":
            break
        elif choice == "1":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                result = detect_file_type(filepath)
                display_file_type(result, filepath)
        elif choice == "2":
            filepath = Prompt.ask("Resim dosyası yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                exif = read_exif(filepath)
                display_exif(exif)
        elif choice == "3":
            filepath = Prompt.ask("Dosya yolu")
            offset = IntPrompt.ask("Başlangıç offset", default=0)
            length = IntPrompt.ask("Byte sayısı", default=256)
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                dump = hex_dump(filepath, offset, length)
                console.print(Panel(
                    Text(dump, style="green"),
                    title=f"[bold red]Hex Dump: {os.path.basename(filepath)}[/bold red]",
                    border_style="red",
                    box=box.SIMPLE
                ))
        elif choice == "4":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                timestamps = analyze_timestamps(filepath)
                display_timestamps(timestamps, filepath)
        elif choice == "5":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                hashes = calculate_hashes(filepath)
                display_hashes(hashes, filepath)
        elif choice == "6":
            filepath = Prompt.ask("Dosya yolu")
            if not os.path.exists(filepath):
                console.print("[red]Dosya bulunamadı![/red]")
            else:
                entropy = calculate_entropy(filepath)
                desc = entropy_description(entropy)
                console.print(Panel(
                    f"[bold green]Entropi:[/bold green] {entropy:.4f} bits/byte\n"
                    f"[bold yellow]Yorum:[/bold yellow] {desc}\n"
                    f"[dim]Maks. Entropi: 8.0 (tamamen rastgele)[/dim]",
                    title="[bold red]📊 Entropi Analizi[/bold red]",
                    border_style="red"
                ))
        elif choice == "7":
            file1 = Prompt.ask("Birinci dosya")
            file2 = Prompt.ask("İkinci dosya")
            result = compare_files(file1, file2)
            if 'error' in result:
                console.print(f"[red]{result['error']}[/red]")
            else:
                status = "[green]Aynı[/green]" if result['identical'] else "[red]Farklı[/red]"
                console.print(f"Durum: {status}")
                console.print(f"Fark sayısı: {result['differences_found']}")
                if result['differences']:
                    table = Table(title="Farklı Byte'lar", box=box.SIMPLE_HEAD)
                    table.add_column("Offset", style="yellow")
                    table.add_column("Dosya 1", style="cyan")
                    table.add_column("Dosya 2", style="magenta")
                    for diff in result['differences']:
                        table.add_row(diff['hex_offset'], diff['file1_byte'], diff['file2_byte'])
                    console.print(table)
        elif choice == "8":
            dirpath = Prompt.ask("Dizin yolu")
            if not os.path.isdir(dirpath):
                console.print("[red]Dizin bulunamadı![/red]")
            else:
                files = identify_directory(dirpath)
                table = Table(title="Dizin Analizi", box=box.ROUNDED, border_style="red")
                table.add_column("Dosya", style="cyan")
                table.add_column("Bildirilen Uzantı", style="yellow")
                table.add_column("Gerçek Tip", style="green")
                table.add_column("Uyumsuz", style="red", justify="center")
                for f in files:
                    if 'error' in f:
                        continue
                    mismatch = "⚠️" if f['mismatch'] else "✓"
                    table.add_row(f['file'], f['reported_ext'], f['actual_type'], mismatch)
                console.print(table)
        else:
            console.print("[red]Geçersiz seçim![/red]")

        Prompt.ask("\n[dim]Devam etmek için Enter'a basın[/dim]")
        console.clear()

# ─── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTF Toolkit - Forensics Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python forensics.py --identify file.jpg
  python forensics.py --exif photo.jpg
  python forensics.py --hexdump binary.bin --offset 0 --length 512
  python forensics.py --timestamps file.jpg
  python forensics.py --hashes file.exe
  python forensics.py --entropy suspicious.bin
        """
    )
    parser.add_argument('--identify', metavar='FILE', help='Identify file type using magic bytes')
    parser.add_argument('--exif', metavar='FILE', help='Read EXIF metadata')
    parser.add_argument('--hexdump', metavar='FILE', help='Show hex dump')
    parser.add_argument('--timestamps', metavar='FILE', help='Analyze timestamps')
    parser.add_argument('--hashes', metavar='FILE', help='Calculate file hashes')
    parser.add_argument('--entropy', metavar='FILE', help='Calculate file entropy')
    parser.add_argument('--compare', nargs=2, metavar=('FILE1', 'FILE2'), help='Compare two files')
    parser.add_argument('--dir-analyze', metavar='DIR', help='Analyze all files in directory')
    parser.add_argument('--offset', type=int, default=0, help='Hex dump start offset')
    parser.add_argument('--length', type=int, default=256, help='Hex dump length in bytes')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive menu')

    args = parser.parse_args()

    if args.interactive or len(sys.argv) == 1:
        interactive_menu()
        return

    console.print(BANNER)

    if args.identify:
        result = detect_file_type(args.identify)
        display_file_type(result, args.identify)

    elif args.exif:
        exif = read_exif(args.exif)
        display_exif(exif)

    elif args.hexdump:
        dump = hex_dump(args.hexdump, args.offset, args.length)
        console.print(Panel(
            Text(dump, style="green"),
            title=f"[bold red]Hex Dump: {os.path.basename(args.hexdump)}[/bold red]",
            border_style="red",
            box=box.SIMPLE
        ))

    elif args.timestamps:
        timestamps = analyze_timestamps(args.timestamps)
        display_timestamps(timestamps, args.timestamps)

    elif args.hashes:
        hashes = calculate_hashes(args.hashes)
        display_hashes(hashes, args.hashes)

    elif args.entropy:
        entropy = calculate_entropy(args.entropy)
        desc = entropy_description(entropy)
        console.print(Panel(
            f"[bold green]Entropi:[/bold green] {entropy:.4f} bits/byte\n"
            f"[bold yellow]Yorum:[/bold yellow] {desc}",
            title="[bold red]📊 Entropi Analizi[/bold red]",
            border_style="red"
        ))

    elif args.compare:
        result = compare_files(args.compare[0], args.compare[1])
        if 'error' in result:
            console.print(f"[red]{result['error']}[/red]")
        else:
            status = "[green]Aynı[/green]" if result['identical'] else "[red]Farklı[/red]"
            console.print(f"Durum: {status} | Farklar: {result['differences_found']}")

    elif args.dir_analyze:
        files = identify_directory(args.dir_analyze)
        table = Table(title="Dizin Analizi", box=box.ROUNDED, border_style="red")
        table.add_column("Dosya", style="cyan")
        table.add_column("Gerçek Tip", style="green")
        table.add_column("Uyumsuz", justify="center")
        for f in files:
            if 'error' in f:
                continue
            table.add_row(f['file'], f['actual_type'], "⚠️" if f['mismatch'] else "✓")
        console.print(table)

if __name__ == '__main__':
    main()
