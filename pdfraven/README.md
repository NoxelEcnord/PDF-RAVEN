# PDFRaven

![PDFRaven Banner](https://raw.githubusercontent.com/NoxelEcnord/PDFRaven/main/banner.png) <!-- Placeholder for a potential banner image -->

## The Advanced PDF Password Recovery Tool

PDFRaven is a high-performance, multi-threaded tool designed to audit and recover passwords for encrypted PDF documents. Built with efficiency in mind, it leverages parallel processing and smart session management to quickly find passwords.

## Features

*   **Multi-threaded Performance:** Utilizes all available CPU cores for maximum cracking speed.
*   **Multiple Attack Modes:** Supports wordlist, numeric range, fixed-length numeric, date-based, custom query, brute-force (mask-based), and hybrid attacks.
*   **Session Resumption:** Automatically saves and resumes sessions, preventing loss of progress.
*   **Password Database:** Stores successfully cracked passwords in a local database for instant access if the same PDF is encountered again.
*   **Decrypted File Saving:** Automatically saves a decrypted version of the PDF once the password is found.
*   **User-Friendly Interface:** Clear console output with rich progress bars and logging.

## Installation

PDFRaven requires Python 3.8 or higher.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/NoxelEcnord/PDFRaven.git
    cd PDFRaven
    ```

2.  **Install dependencies:**
    ```bash
    pip install -e .
    ```
    This will install `pikepdf` and `rich`, and make the `pdfraven` command available in your PATH.

## Usage

PDFRaven is a command-line tool. You can always get help by running `pdfraven --help`.

**Basic Syntax:**
```bash
pdfraven -f <encrypted_pdf_file> [attack_mode] [attack_mode_arguments]
```

### Core Arguments:

*   `-f, --file <path>`: Path to the encrypted PDF file. (Required)
*   `-t, --threads <num>`: Number of worker threads (defaults to CPU count).
*   `--resume`: Resume the last session for this file.
*   `--no-decrypt`: Do not save a decrypted version of the PDF.
*   `--batch-size <num>`: Number of passwords per worker batch (default: 1000).
*   `--timeout <seconds>`: Maximum time in seconds to run the attack.
*   `--output-dir <path>`: Directory to save decrypted files (default: `.`).
*   `--session-dir <path>`: Directory to store session files (default: `.pdfraven_sessions`).
*   `--db-file <path>`: Path to the password database file (default: `found_passwords.json`).

### Attack Modes:

#### 1. Wordlist Attack
Uses a dictionary file to try common passwords.
```bash
pdfraven -f my_document.pdf wordlist rockyou.txt
```

#### 2. Numeric Range Attack
Checks a specific integer range (e.g., PINs).
```bash
pdfraven -f my_document.pdf range 0 9999
```

#### 3. Fixed-Length Numeric Attack
Checks all numbers of a fixed length (auto-pads zeros).
```bash
pdfraven -f my_document.pdf numeric 6  # Checks 000000-999999
```

#### 4. Date-Based Attack (DDMMYYYY)
Checks all dates in `DDMMYYYY` format for a year range.
```bash
pdfraven -f my_document.pdf date 1990 2023

# New options for date format and separator
pdfraven -f my_document.pdf date 1990 2023 --format YYYYMMDD --separator -
```

#### 5. Custom Query Attack
Smart pattern generation using a prefix, number range, and suffix.
*   Format: `PREFIX{MIN-MAX}SUFFIX`
*   Use `--add-preceding-zeros` to pad numbers with leading zeros.
```bash
pdfraven -f my_document.pdf custom-query "EMPLOYEE{100-500}-DATA" --add-preceding-zeros
```

#### 6. Brute-Force Attack (Mask-based)
Advanced brute-force with a defined charset and length mask.
*   `w`: lowercase letters (`a-z`)
*   `W`: uppercase letters (`A-Z`)
*   `d`: digits (`0-9`)
*   `s`: symbols (`!@#$%^&*()-_+=~`[]{}|\:;"'<>,.?/`)
*   `b`: whitespace (` `)
*   `h`: hexadecimal (`0-9a-f`)
*   `a`: all common characters (`wWdsb`)
*   Length can be specified as `{length}` or `{min_length,max_length}`.
```bash
pdfraven -f my_document.pdf brute "w{4}d{2}"  # e.g., 'abcd12'
pdfraven -f my_document.pdf brute "W{1}w{3,5}d{1}" # e.g., 'Aabc1', 'Aabcd1', 'Aabcde1'
```

#### 7. Hybrid Attack
Combines two masks or a wordlist with a mask.
```bash
pdfraven -f my_document.pdf hybrid mywordlist.txt "d{4}" # Tries word from list + 4 digits
pdfraven -f my_document.pdf hybrid "admin" "d{2,4}" # Tries admin00, admin000, admin0000
```

#### 8. Custom Brute-Force
Brute-force with a user-defined character set and length range.
```bash
pdfraven -f my_document.pdf custom-brute --charset "abc!@#" --min-length 1 --max-length 5
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Credits

*   **Author:** Ecnord (GitHub: [NoxelEcnord](https://github.com/NoxelEcnord))
*   **Dependencies:** `pikepdf`, `rich`