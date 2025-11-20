PDFRaven 🐦‍⬛

PDFRaven is a high-performance, multi-threaded PDF password recovery suite designed for security professionals and enthusiasts. It utilizes multiprocessing to bypass the Python GIL, leveraging all CPU cores for maximum speed.

It features a smart local database to cache found passwords, ensuring you never have to crack the same file twice.

🚀 Features

Multi-Process Architecture: Fully utilizes all CPU cores.

Smart Caching: Remembers cracked passwords in a local JSON database.

Auto-Decryption: Automatically saves a decrypted copy of the file upon success.

Attack Modes:

📖 Wordlist: Standard dictionary attack.

🔢 Numeric: Fixed-length PIN cracking (e.g., 4-digit, 6-digit).

🎯 Range: Specific integer range scanning.

📅 Date: Brute-forces dates (DDMMYYYY) within a year range.

🧩 Custom Query: Flexible pattern matching (e.g., USER{100-999}).

🔨 Brute Force: Full alphanumeric brute-force.

TUI Elements: Progress bars, colored output, and verbose logging.

📦 Installation

Clone the repository

git clone [https://github.com/NoxelEcnord/PDF-RAVEN.git](https://github.com/NoxelEcnord/PDF-RAVEN.git)
cd pdfraven


Install dependencies

pip install -r requirements.txt


Note: This tool relies on pikepdf (C++ QPDF bindings) for speed.

🛠️ Usage

Run the tool with -h or --manual to see the full help menu.

Basic Syntax

python3 pdfraven.py -f <file.pdf> <mode> [arguments]


Examples

1. Dictionary Attack
Use a wordlist (like rockyou.txt) to crack a file:

python3 pdfraven.py -f protected.pdf wordlist /usr/share/wordlists/rockyou.txt


2. Numeric PIN Attack (e.g., 6 digits)
Fastest way to crack PIN-locked bank statements or documents:

python3 pdfraven.py -f statement.pdf numeric 6
# Checks 000000 to 999999


3. Custom Pattern Attack
If you know the password format (e.g., "Employee ID is 'EMP' followed by 3 digits"):

python3 pdfraven.py -f doc.pdf custom-query "EMP{0-999}" --add-preceding-zeros
# Checks EMP000, EMP001 ... EMP999


4. Date Attack
Checks all days in DDMMYYYY format between two years:

python3 pdfraven.py -f birthcert.pdf date 1980 2000


⚙️ Options

Flag

Description

-f, --file

Path to the encrypted PDF file.

-t, --threads

Number of worker threads (Defaults to CPU count).

-v

Verbose mode (use -vv or -vvv for more detail).

--manual

Displays the detailed user manual.

⚠️ Disclaimer

This tool is developed for educational and ethical security testing purposes only. The author (Ecnord) is not responsible for any misuse or damage caused by this program. Ensure you have explicit permission before attempting to crack documents you do not own.

👤 Author

Ecnord

GitHub: @NoxelEcnord

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
