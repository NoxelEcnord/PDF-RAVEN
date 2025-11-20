#!/usr/bin/env python3
"""
PDFRaven - Advanced PDF Password Recovery Suite
Author: Ecnord (GitHub: NoxelEcnord)
Description: A multi-process, database-backed PDF cracker with TUI elements.
             Supports dictionary, brute-force, dates, ranges, and custom patterns.
"""

import argparse
import concurrent.futures
import itertools
import string
import sys
import time
import os
import re
import multiprocessing
import calendar
import json
import shutil
from pathlib import Path
from datetime import datetime

# --- Configuration & Constants ---
DB_FILE = "found_passwords.json"
VERSION = "2.0.0"

# --- ANSI Colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

try:
    import pikepdf
    from tqdm import tqdm
except ImportError:
    print(f"{Colors.FAIL}[CRITICAL] Missing dependencies.{Colors.ENDC}")
    print(f"Please run: {Colors.BOLD}pip install -r requirements.txt{Colors.ENDC}")
    sys.exit(1)

# --- Helpers ---

def print_banner():
    banner = f"""{Colors.CYAN}
    ██████╗ ██████╗ ███████╗██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
    ██████╔╝██║  ██║█████╗  ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
    ██╔═══╝ ██║  ██║██╔══╝  ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
    ██║     ██████╔╝██║     ██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
    ╚═╝     ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
    {Colors.ENDC}{Colors.BLUE}        >> The Advanced PDF Recovery Tool <<
            Author: Ecnord (GitHub: NoxelEcnord)
            Version: {VERSION}{Colors.ENDC}
    """
    print(banner)

def log(message, level, required_level, verbose_mode):
    """Handles verbosity logging"""
    if verbose_mode >= required_level:
        prefix = ""
        if level == "INFO": prefix = f"{Colors.BLUE}[*]{Colors.ENDC} "
        elif level == "SUCCESS": prefix = f"{Colors.GREEN}[+]{Colors.ENDC} "
        elif level == "WARN": prefix = f"{Colors.WARNING}[!]{Colors.ENDC} "
        elif level == "ERROR": prefix = f"{Colors.FAIL}[-]{Colors.ENDC} "
        elif level == "DEBUG": prefix = f"{Colors.HEADER}[D]{Colors.ENDC} "
        
        # If using tqdm, we must use write to avoid breaking the bar
        tqdm.write(f"{prefix}{message}")

def print_manual():
    print_banner()
    manual = f"""
{Colors.BOLD}USER MANUAL{Colors.ENDC}
--------------------------------------------------------------------------------
{Colors.HEADER}DESCRIPTION{Colors.ENDC}
PDFRaven is a high-performance, multi-threaded tool designed to audit and recover
passwords for PDF documents. It uses smart caching to remember found passwords.

{Colors.HEADER}MODES{Colors.ENDC}
1. {Colors.BOLD}wordlist{Colors.ENDC}      : Standard dictionary attack using a text file.
   Usage: pdfraven -f doc.pdf wordlist rockyou.txt

2. {Colors.BOLD}range{Colors.ENDC}         : Checks a specific integer range (e.g., PINs).
   Usage: pdfraven -f doc.pdf range 0 9999

3. {Colors.BOLD}numeric{Colors.ENDC}       : Checks all numbers of a fixed length (auto-pads zeros).
   Usage: pdfraven -f doc.pdf numeric 6 (checks 000000-999999)

4. {Colors.BOLD}date{Colors.ENDC}          : Checks all dates in DDMMYYYY format for a year range.
   Usage: pdfraven -f doc.pdf date 1990 2023

5. {Colors.BOLD}custom-query{Colors.ENDC}  : Smart pattern generation.
   Format: PREFIX{{MIN-MAX}}SUFFIX
   Usage: pdfraven -f doc.pdf custom-query "EMPLOYEE{{100-500}}-DATA"
   Flag: --add-preceding-zeros (Pads numbers to match max digit length)

6. {Colors.BOLD}default-query{Colors.ENDC} : Full alphanumeric brute-force (Slowest, most thorough).
   Usage: pdfraven -f doc.pdf default-query --min-length 4 --max-length 8

{Colors.HEADER}VERBOSITY LEVELS{Colors.ENDC}
 -v    : Show basic process info.
 -vv   : Show batch processing details.
 -vvv  : Debug mode (worker traces, extensive info).

{Colors.HEADER}DATABASE{Colors.ENDC}
Passwords found are stored in '{DB_FILE}'. PDFRaven checks this file 
before starting any attack. If the PDF hasn't changed, it unlocks instantly.
    """
    print(manual)
    sys.exit(0)

# --- Database Functions ---

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_to_db(pdf_path, password):
    db = load_db()
    abs_path = str(Path(pdf_path).resolve())
    db[abs_path] = password
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=4)
    except Exception as e:
        pass

def check_db_for_password(pdf_path, verbose):
    db = load_db()
    abs_path = str(Path(pdf_path).resolve())
    
    if abs_path in db:
        saved_pass = db[abs_path]
        log(f"Found entry in database for this file. Testing password: {saved_pass}", "INFO", 1, verbose)
        try:
            with pikepdf.open(pdf_path, password=saved_pass) as pdf:
                log("Database password matched! Skipping attack.", "SUCCESS", 0, verbose)
                return saved_pass
        except pikepdf.PasswordError:
            log("Database password incorrect (file changed?). Removing entry.", "WARN", 1, verbose)
            del db[abs_path]
            with open(DB_FILE, 'w') as f:
                json.dump(db, f, indent=4)
    return None

# --- Core Cracking Logic ---

def attempt_crack_batch(args):
    pdf_path, passwords = args
    # Suppress QPDF warnings implicitly by not configuring logger
    for password in passwords:
        try:
            with pikepdf.open(pdf_path, password=password, allow_overwriting_input=True) as pdf:
                return password
        except pikepdf.PasswordError:
            continue
        except Exception:
            continue
    return None

# --- Dispatcher Template ---

def run_attack(attack_name, generator, total_est, pdf_path, workers, batch_size, verbose):
    log(f"Initializing {attack_name} with {workers} workers...", "INFO", 1, verbose)
    
    pool = concurrent.futures.ProcessPoolExecutor(max_workers=workers)
    futures = []
    
    start_time = time.time()
    
    # Progress Bar
    pbar = tqdm(total=total_est, unit="pw", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
    
    found_password = None
    
    try:
        batch = []
        for pwd in generator:
            batch.append(pwd)
            if len(batch) >= batch_size:
                futures.append(pool.submit(attempt_crack_batch, (pdf_path, batch)))
                batch = []
                
                # Memory management
                if len(futures) > workers * 10:
                    done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        res = future.result()
                        pbar.update(batch_size) 
                        if res:
                            found_password = res
                            pool.shutdown(wait=False, cancel_futures=True)
                            break
                        futures.remove(future)
            
            if found_password: break
            
        # Submit final batch
        if batch and not found_password:
            futures.append(pool.submit(attempt_crack_batch, (pdf_path, batch)))
            
        # Drain remaining
        if not found_password:
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                pbar.update(batch_size) # Approximation for visualization
                if res:
                    found_password = res
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                    
    except KeyboardInterrupt:
        pbar.close()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
        
    pbar.close()
    return found_password

# --- Attack Generators ---

def gen_wordlist(path):
    with open(path, 'r', encoding='latin-1', errors='ignore') as f:
        for line in f:
            yield line.strip()

def gen_range(start, end):
    for i in range(start, end + 1):
        yield str(i)

def gen_numeric(length):
    limit = 10 ** length
    for i in range(limit):
        yield f"{i:0{length}d}"

def gen_date(start, end):
    for year in range(start, end + 1):
        for month in range(1, 13):
            _, num_days = calendar.monthrange(year, month)
            for day in range(1, num_days + 1):
                yield f"{day:02d}{month:02d}{year}"

def gen_custom(query, add_zeros):
    match = re.search(r'(.*)\{(\d+)-(\d+)\}(.*)', query)
    if not match: return
    prefix, start, end, suffix = match.group(1), int(match.group(2)), int(match.group(3)), match.group(4)
    width = len(match.group(3)) if add_zeros else 0
    for i in range(start, end + 1):
        num = f"{i:0{width}d}" if add_zeros else str(i)
        yield f"{prefix}{num}{suffix}"

def gen_brute(min_l, max_l, charset):
    for length in range(min_l, max_l + 1):
        for p in itertools.product(charset, repeat=length):
            yield "".join(p)

# --- Main ---

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--manual", action="store_true", help="Show user manual")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv, -vvv)")
    
    # Initial parse to check for --manual
    args, unknown = parser.parse_known_args()
    
    if args.manual:
        print_manual()

    # Full Parser
    parser = argparse.ArgumentParser(description="PDFRaven: Advanced PDF Cracker")
    parser.add_argument("-f", "--file", required=True, help="Encrypted PDF file")
    parser.add_argument("-t", "--threads", type=int, default=multiprocessing.cpu_count(), help="Worker threads")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--manual", action="store_true", help="Show user manual")

    subparsers = parser.add_subparsers(dest="command", help="Attack mode", required=True)

    # Subcommands
    subparsers.add_parser("wordlist").add_argument("wordlist_path")
    r_p = subparsers.add_parser("range")
    r_p.add_argument("min", type=int)
    r_p.add_argument("max", type=int)
    
    n_p = subparsers.add_parser("numeric")
    n_p.add_argument("length", type=int)

    d_p = subparsers.add_parser("date")
    d_p.add_argument("start_year", type=int)
    d_p.add_argument("end_year", type=int)

    c_p = subparsers.add_parser("custom-query")
    c_p.add_argument("query")
    c_p.add_argument("--add-preceding-zeros", action="store_true")

    b_p = subparsers.add_parser("default-query")
    b_p.add_argument("--min-length", type=int, default=4)
    b_p.add_argument("--max-length", type=int, default=8)

    args = parser.parse_args()
    
    print_banner()
    
    if not os.path.isfile(args.file):
        log(f"File not found: {args.file}", "ERROR", 0, args.verbose)
        sys.exit(1)

    # 1. Check encryption
    try:
        with pikepdf.open(args.file) as pdf:
            log("File is NOT password protected.", "WARN", 0, args.verbose)
            sys.exit(0)
    except pikepdf.PasswordError:
        pass
    except Exception as e:
        log(f"Corrupt PDF or Permission Error: {e}", "ERROR", 0, args.verbose)
        sys.exit(1)

    # 2. Check DB
    log("Checking local database for known password...", "INFO", 1, args.verbose)
    db_pass = check_db_for_password(args.file, args.verbose)
    
    password = None
    
    if db_pass:
        password = db_pass
    else:
        # 3. Start Attack
        log(f"Target: {args.file}", "INFO", 0, args.verbose)
        log(f"Mode: {args.command.upper()}", "INFO", 0, args.verbose)
        
        # Config based on mode
        gen = None
        est_total = 0 # Used for progress bar if calculable
        
        if args.command == "wordlist":
            # Count lines for progress bar
            log("Counting lines in wordlist...", "INFO", 1, args.verbose)
            try:
                est_total = sum(1 for _ in open(args.wordlist_path, 'rb'))
            except: est_total = None
            gen = gen_wordlist(args.wordlist_path)
            
        elif args.command == "range":
            est_total = (args.max - args.min) + 1
            gen = gen_range(args.min, args.max)
            
        elif args.command == "numeric":
            est_total = 10 ** args.length
            gen = gen_numeric(args.length)
            
        elif args.command == "date":
            est_total = (args.end_year - args.start_year + 1) * 365 # Rough estimate
            gen = gen_date(args.start_year, args.end_year)
            
        elif args.command == "custom-query":
             match = re.search(r'\{(\d+)-(\d+)\}', args.query)
             if match: est_total = int(match.group(2)) - int(match.group(1)) + 1
             gen = gen_custom(args.query, args.add_preceding_zeros)
             
        elif args.command == "default-query":
            # Calculation is complex, leave None for indefinite bar or rough calc
            charset = string.ascii_letters + string.digits
            gen = gen_brute(args.min_length, args.max_length, charset)
        
        try:
            password = run_attack(args.command, gen, est_total, args.file, args.threads, 1000, args.verbose)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Aborted by user.{Colors.ENDC}")
            sys.exit(0)

    # 4. Result Handling
    print("\n" + f"{Colors.BLUE}={Colors.ENDC}"*50)
    if password:
        print(f"{Colors.GREEN} [SUCCESS] PASSWORD FOUND: {Colors.BOLD}{password}{Colors.ENDC}")
        print(f"{Colors.BLUE}={Colors.ENDC}"*50)
        
        # Save to DB
        save_to_db(args.file, password)
        log("Password saved to database.", "SUCCESS", 0, args.verbose)
        
        # Auto Decrypt
        out_file = f"decrypted_{Path(args.file).name}"
        try:
            with pikepdf.open(args.file, password=password) as pdf:
                pdf.save(out_file)
            print(f"{Colors.GREEN} [+] Decrypted file saved: {out_file}{Colors.ENDC}")
        except Exception as e:
            log(f"Could not save decrypted file: {e}", "ERROR", 0, args.verbose)
    else:
        print(f"{Colors.FAIL} [FAILURE] Password NOT found.{Colors.ENDC}")
        print(f"{Colors.BLUE}={Colors.ENDC}"*50)

if __name__ == "__main__":
    main()
