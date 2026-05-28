"""
AI Security Pipeline - Encoding/Obfuscation Utilities
======================================================

Provides various encoding and obfuscation techniques for
evading content filters and safety mechanisms.
"""

import base64
import codecs
from typing import List, Dict


# Unicode homoglyph mappings (ASCII to similar Unicode characters)
HOMOGLYPHS: Dict[str, str] = {
    'a': 'а',  # Cyrillic 'a'
    'e': 'е',  # Cyrillic 'e' 
    'o': 'о',  # Cyrillic 'o'
    'p': 'р',  # Cyrillic 'r'
    'c': 'с',  # Cyrillic 's'
    'x': 'х',  # Cyrillic 'h'
    'y': 'у',  # Cyrillic 'u'
    'i': 'і',  # Cyrillic 'i'
    's': 'ѕ',  # Cyrillic 's'
}

# Leet speak mappings
LEET_SPEAK: Dict[str, str] = {
    'a': '4', 'A': '4',
    'e': '3', 'E': '3',
    'i': '1', 'I': '1',
    'o': '0', 'O': '0',
    's': '5', 'S': '5',
    't': '7', 'T': '7',
    'l': '1', 'L': '1',
    'b': '8', 'B': '8',
}

# Zero-width characters for whitespace injection
ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # Zero-width no-break space
]


def encode_rot13(text: str) -> str:
    """Apply ROT13 encoding."""
    return codecs.encode(text, 'rot_13')


def decode_rot13(text: str) -> str:
    """Decode ROT13 text."""
    return codecs.decode(text, 'rot_13')


def encode_base64(text: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(text.encode()).decode()


def decode_base64(text: str) -> str:
    """Decode Base64 text."""
    try:
        return base64.b64decode(text.encode()).decode()
    except Exception:
        return text


def encode_leet_speak(text: str) -> str:
    """Convert text to leet speak."""
    result = []
    for char in text:
        result.append(LEET_SPEAK.get(char, char))
    return ''.join(result)


def encode_homoglyphs(text: str, ratio: float = 0.3) -> str:
    """
    Replace some characters with Unicode homoglyphs.
    
    Args:
        text: Input text
        ratio: Fraction of characters to replace (0-1)
    """
    result = []
    import random
    for char in text:
        lower = char.lower()
        if lower in HOMOGLYPHS and random.random() < ratio:
            # Preserve case
            if char.isupper():
                result.append(HOMOGLYPHS[lower].upper())
            else:
                result.append(HOMOGLYPHS[lower])
        else:
            result.append(char)
    return ''.join(result)


def inject_zero_width(text: str, frequency: int = 3) -> str:
    """
    Inject zero-width characters between words.
    
    Args:
        text: Input text
        frequency: Insert after every N characters
    """
    import random
    if frequency < 1:
        frequency = 1
    result = []
    for i, char in enumerate(text):
        result.append(char)
        if (i + 1) % frequency == 0 and ZERO_WIDTH_CHARS:
            zw = random.choice(ZERO_WIDTH_CHARS)
            if zw:
                result.append(zw)
    return ''.join(result)


def fragment_text(text: str, parts: int = 3) -> List[str]:
    """
    Split text into fragments for multi-turn delivery.
    
    Args:
        text: Input text
        parts: Number of fragments
    """
    words = text.split()
    chunk_size = len(words) // parts
    fragments = []
    
    for i in range(parts):
        start = i * chunk_size
        if i == parts - 1:
            end = len(words)
        else:
            end = start + chunk_size
        fragments.append(' '.join(words[start:end]))
    
    return fragments


def encode_url(text: str) -> str:
    """URL encode text."""
    import urllib.parse
    return urllib.parse.quote(text)


def decode_url(text: str) -> str:
    """URL decode text."""
    import urllib.parse
    return urllib.parse.unquote(text)


def reverse_text(text: str) -> str:
    """Reverse text (simple obfuscation)."""
    return text[::-1]


def encode_hex(text: str) -> str:
    """Encode text to hexadecimal."""
    return text.encode().hex()


def decode_hex(text: str) -> str:
    """Decode hexadecimal text."""
    try:
        return bytes.fromhex(text).decode()
    except Exception:
        return text


def apply_encoding_chain(text: str, encodings: List[str]) -> str:
    """
    Apply multiple encodings in sequence.
    
    Args:
        text: Input text
        encodings: List of encoding names
        
    Supported: rot13, base64, leet, homoglyphs, zero_width, url, hex, reverse
    """
    encoding_funcs = {
        'rot13': encode_rot13,
        'base64': encode_base64,
        'leet': encode_leet_speak,
        'homoglyphs': encode_homoglyphs,
        'zero_width': inject_zero_width,
        'url': encode_url,
        'hex': encode_hex,
        'reverse': reverse_text,
    }
    
    result = text
    for encoding in encodings:
        if encoding in encoding_funcs:
            result = encoding_funcs[encoding](result)
    
    return result


class Encoder:
    """Convenience class for encoding operations."""
    
    @staticmethod
    def rot13(text: str) -> str:
        return encode_rot13(text)
    
    @staticmethod
    def base64(text: str) -> str:
        return encode_base64(text)
    
    @staticmethod
    def leet(text: str) -> str:
        return encode_leet_speak(text)
    
    @staticmethod
    def homoglyphs(text: str, ratio: float = 0.3) -> str:
        return encode_homoglyphs(text, ratio)
    
    @staticmethod
    def zero_width(text: str, frequency: int = 3) -> str:
        return inject_zero_width(text, frequency)
    
    @staticmethod
    def fragment(text: str, parts: int = 3) -> List[str]:
        return fragment_text(text, parts)
    
    @staticmethod
    def chain(text: str, encodings: List[str]) -> str:
        return apply_encoding_chain(text, encodings)
