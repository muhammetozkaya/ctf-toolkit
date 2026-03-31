#!/usr/bin/env python3
"""
CTF Toolkit - Unit Tests
Author: Muhammet Özkaya
"""

import sys
import os
import unittest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import crypto
import web


class TestCrypto(unittest.TestCase):
    """Tests for the crypto module"""

    # ── Base Encoding ──────────────────────────────────────────────────────────

    def test_base64_encode(self):
        self.assertEqual(crypto.base64_encode("Hello"), "SGVsbG8=")
        self.assertEqual(crypto.base64_encode("CTF{flag}"), "Q1RGe2ZsYWd9")

    def test_base64_decode(self):
        self.assertEqual(crypto.base64_decode("SGVsbG8="), "Hello")
        self.assertEqual(crypto.base64_decode("Q1RGe2ZsYWd9"), "CTF{flag}")

    def test_base64_roundtrip(self):
        texts = ["Hello World", "CTF{test_flag}", "12345", "Special: @#$%"]
        for t in texts:
            self.assertEqual(crypto.base64_decode(crypto.base64_encode(t)), t)

    def test_base32_encode(self):
        result = crypto.base32_encode("Hello")
        self.assertEqual(result, "JBSWY3DP")

    def test_base32_roundtrip(self):
        text = "Hello CTF"
        self.assertEqual(crypto.base32_decode(crypto.base32_encode(text)), text)

    def test_base16_encode(self):
        self.assertEqual(crypto.base16_encode("Hi"), "4869")

    def test_base16_roundtrip(self):
        text = "test"
        self.assertEqual(crypto.base16_decode(crypto.base16_encode(text)), text)

    def test_hex_encode(self):
        self.assertEqual(crypto.hex_encode("A"), "41")
        self.assertEqual(crypto.hex_encode("Hi"), "4869")

    def test_hex_roundtrip(self):
        test_cases = ["Hello", "CTF{flag}", "0123"]
        for t in test_cases:
            self.assertEqual(crypto.hex_decode(crypto.hex_encode(t)), t)

    def test_binary_encode(self):
        result = crypto.binary_encode("A")
        self.assertEqual(result, "01000001")

    def test_binary_roundtrip(self):
        text = "Hi"
        self.assertEqual(crypto.binary_decode(crypto.binary_encode(text)), text)

    # ── Caesar Cipher ──────────────────────────────────────────────────────────

    def test_caesar_encode(self):
        self.assertEqual(crypto.caesar_cipher("Hello", 3), "Khoor")
        self.assertEqual(crypto.caesar_cipher("abc", 1), "bcd")
        self.assertEqual(crypto.caesar_cipher("xyz", 3), "abc")

    def test_caesar_decode(self):
        self.assertEqual(crypto.caesar_cipher("Khoor", 3, decode=True), "Hello")

    def test_caesar_roundtrip(self):
        for shift in range(1, 26):
            text = "Hello World"
            encrypted = crypto.caesar_cipher(text, shift)
            decrypted = crypto.caesar_cipher(encrypted, shift, decode=True)
            self.assertEqual(decrypted, text, f"Failed for shift={shift}")

    def test_caesar_preserves_non_alpha(self):
        result = crypto.caesar_cipher("Hello, World! 123", 3)
        self.assertIn(",", result)
        self.assertIn("!", result)
        self.assertIn("123", result)

    def test_rot13(self):
        self.assertEqual(crypto.rot13("Hello"), "Uryyb")
        self.assertEqual(crypto.rot13("Uryyb"), "Hello")
        self.assertEqual(crypto.rot13(crypto.rot13("CTF")), "CTF")

    def test_caesar_bruteforce_count(self):
        results = crypto.caesar_bruteforce("Hello")
        self.assertEqual(len(results), 25)

    # ── XOR Cipher ─────────────────────────────────────────────────────────────

    def test_xor_symmetry(self):
        text = "Hello"
        key = "K"
        encrypted = crypto.xor_encrypt(text, key)
        decrypted = crypto.xor_encrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_xor_multiple_char_key(self):
        text = "Hello World"
        key = "CTF"
        encrypted = crypto.xor_encrypt(text, key)
        decrypted = crypto.xor_encrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    # ── Vigenere Cipher ────────────────────────────────────────────────────────

    def test_vigenere_encrypt(self):
        result = crypto.vigenere_encrypt("HELLO", "KEY")
        self.assertEqual(result, "RIJVS")

    def test_vigenere_decrypt(self):
        result = crypto.vigenere_decrypt("RIJVS", "KEY")
        self.assertEqual(result, "HELLO")

    def test_vigenere_roundtrip(self):
        text = "Hello World"
        key = "SECRET"
        encrypted = crypto.vigenere_encrypt(text, key)
        decrypted = crypto.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    # ── Atbash ─────────────────────────────────────────────────────────────────

    def test_atbash(self):
        self.assertEqual(crypto.atbash("A"), "Z")
        self.assertEqual(crypto.atbash("Z"), "A")
        self.assertEqual(crypto.atbash("Hello"), "Svool")
        self.assertEqual(crypto.atbash(crypto.atbash("Hello")), "Hello")

    # ── Morse Code ─────────────────────────────────────────────────────────────

    def test_morse_encode(self):
        result = crypto.morse_encode("SOS")
        self.assertEqual(result, "... --- ...")

    def test_morse_roundtrip(self):
        text = "HELLO"
        encoded = crypto.morse_encode(text)
        decoded = crypto.morse_decode(encoded)
        self.assertEqual(decoded, text)

    # ── Frequency Analysis ─────────────────────────────────────────────────────

    def test_frequency_analysis_returns_dict(self):
        result = crypto.frequency_analysis("Hello World")
        self.assertIsInstance(result, dict)

    def test_frequency_analysis_sums_to_100(self):
        result = crypto.frequency_analysis("Hello World")
        total = sum(result.values())
        self.assertAlmostEqual(total, 100.0, places=5)

    def test_frequency_analysis_empty(self):
        result = crypto.frequency_analysis("")
        self.assertEqual(result, {})

    def test_frequency_analysis_most_common(self):
        result = crypto.frequency_analysis("AAABBC")
        most_common = max(result, key=result.get)
        self.assertEqual(most_common, "A")


class TestWeb(unittest.TestCase):
    """Tests for the web module"""

    # ── URL Encoding ───────────────────────────────────────────────────────────

    def test_url_encode(self):
        self.assertEqual(web.url_encode("Hello World"), "Hello%20World")

    def test_url_decode(self):
        self.assertEqual(web.url_decode("Hello%20World"), "Hello World")

    def test_url_encode_decode_roundtrip(self):
        texts = ["Hello World", "a=1&b=2", "path/../etc/passwd", "CTF{test}"]
        for t in texts:
            self.assertEqual(web.url_decode(web.url_encode_full(t)), t)

    def test_url_encode_special(self):
        result = web.url_encode_full("<script>alert(1)</script>")
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)

    # ── HTML Encoding ──────────────────────────────────────────────────────────

    def test_html_encode(self):
        self.assertEqual(web.html_encode("<script>"), "&lt;script&gt;")
        self.assertEqual(web.html_encode('"'), "&quot;")

    def test_html_decode(self):
        self.assertEqual(web.html_decode("&lt;script&gt;"), "<script>")
        self.assertEqual(web.html_decode("&amp;"), "&")

    def test_html_roundtrip(self):
        text = "<script>alert('XSS')</script>"
        self.assertEqual(web.html_decode(web.html_encode(text)), text)

    def test_html_encode_decimal(self):
        result = web.html_encode_decimal("A")
        self.assertEqual(result, "&#65;")

    def test_html_encode_hex(self):
        result = web.html_encode_hex("A")
        self.assertEqual(result, "&#x41;")

    # ── JWT Decoding ───────────────────────────────────────────────────────────

    def test_jwt_decode_valid(self):
        # Standard JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"John Doe","iat":1516239022}
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = web.jwt_decode(token)
        self.assertNotIn('error', result)
        self.assertIn('header', result)
        self.assertIn('payload', result)
        self.assertEqual(result['header']['alg'], 'HS256')
        self.assertEqual(result['payload']['name'], 'John Doe')

    def test_jwt_decode_invalid(self):
        result = web.jwt_decode("not.a.valid.jwt.token.at.all")
        # Should not crash, may return error
        self.assertIsInstance(result, dict)

    def test_jwt_decode_two_parts(self):
        result = web.jwt_decode("onlytwoparts.here")
        self.assertIn('error', result)

    # ── Hash Identification ────────────────────────────────────────────────────

    def test_identify_md5(self):
        result = web.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")  # MD5 of "password"
        names = [m['name'] for m in result]
        self.assertIn('MD5', names)

    def test_identify_sha1(self):
        result = web.identify_hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")  # SHA-1 of "password"
        names = [m['name'] for m in result]
        self.assertIn('SHA-1', names)

    def test_identify_sha256(self):
        result = web.identify_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
        names = [m['name'] for m in result]
        self.assertIn('SHA-256', names)

    def test_identify_unknown(self):
        result = web.identify_hash("notahash")
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)

    # ── Hash Text ──────────────────────────────────────────────────────────────

    def test_hash_text_md5(self):
        result = web.hash_text("password")
        self.assertEqual(result['MD5'], '5f4dcc3b5aa765d61d8327deb882cf99')

    def test_hash_text_sha1(self):
        result = web.hash_text("password")
        self.assertEqual(result['SHA-1'], '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8')

    def test_hash_text_sha256(self):
        result = web.hash_text("password")
        self.assertEqual(result['SHA-256'], '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8')

    # ── URL Analysis ───────────────────────────────────────────────────────────

    def test_analyze_url(self):
        result = web.analyze_url("https://example.com/path?id=1&user=admin")
        self.assertEqual(result['scheme'], 'https')
        self.assertEqual(result['host'], 'example.com')
        self.assertEqual(result['path'], '/path')
        self.assertIn('id', result['parameters'])

    def test_analyze_url_with_port(self):
        result = web.analyze_url("http://localhost:8080/admin")
        self.assertEqual(result['port'], 8080)


class TestCryptoEdgeCases(unittest.TestCase):
    """Edge case and boundary tests"""

    def test_base64_empty_string(self):
        result = crypto.base64_encode("")
        self.assertEqual(result, "")

    def test_caesar_wrap_around(self):
        # z + 1 = a
        result = crypto.caesar_cipher("z", 1)
        self.assertEqual(result, "a")
        # Z + 1 = A
        result = crypto.caesar_cipher("Z", 1)
        self.assertEqual(result, "A")

    def test_vigenere_preserves_non_alpha(self):
        result = crypto.vigenere_encrypt("Hello, World!", "KEY")
        self.assertIn(",", result)
        self.assertIn("!", result)

    def test_xor_empty_key_error(self):
        """XOR with empty key should raise or handle gracefully"""
        try:
            result = crypto.xor_encrypt("Hello", "")
            # If no exception, result should be some string
        except (ValueError, ZeroDivisionError, IndexError):
            pass  # Expected behavior

    def test_morse_numbers(self):
        result = crypto.morse_encode("1")
        self.assertEqual(result, ".----")

    def test_frequency_analysis_only_numbers(self):
        result = crypto.frequency_analysis("12345")
        self.assertEqual(result, {})  # No alpha chars


if __name__ == '__main__':
    # Rich test output
    import unittest
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
