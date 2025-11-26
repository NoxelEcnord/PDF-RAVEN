# pdfraven/config.py

# --- Configuration & Constants ---
VERSION = "3.2.0" # Updated version

# --- Character Sets ---
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_+=~`[]{}|\:;"'<>,.?/"
WHITESPACE = " "
HEX = "0123456789abcdef"

# Mapping for the new parser
CHARSET_MAP = {
    'w': LOWERCASE,
    'W': UPPERCASE,
    'd': DIGITS,
    's': SYMBOLS,
    'b': WHITESPACE,
    'h': HEX,
    'a': LOWERCASE + UPPERCASE + DIGITS + SYMBOLS + WHITESPACE,
}

