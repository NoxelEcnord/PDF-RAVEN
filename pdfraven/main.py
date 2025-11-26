# pdfraven/main.py

import argparse
import multiprocessing
import sys
import pikepdf
from pathlib import Path

from . import ui
from . import cracker
from . import database
from . import generators

def setup_arg_parser():
    parser = argparse.ArgumentParser(
        description="PDFRaven: Advanced, multi-threaded PDF password recovery tool.",
        add_help=False # We handle help manually to use rich formatting
    )
    
    # Core arguments
    core_args = parser.add_argument_group("Core Arguments")
    core_args.add_argument("-f", "--file", required=True, help="Path to the encrypted PDF file.")
    core_args.add_argument("-t", "--threads", type=int, default=multiprocessing.cpu_count(), help="Number of worker threads (defaults to CPU count).")
    core_args.add_argument("--resume", action="store_true", help="Resume the last session for this file.")
    core_args.add_argument("--no-decrypt", action="store_true", help="Do not save a decrypted version of the PDF.")

    # Performance
    perf_args = parser.add_argument_group("Performance Arguments")
    perf_args.add_argument("-b", "--batch-size", type=int, default=1000, help="Number of passwords per worker batch.")
    perf_args.add_argument("--timeout", type=int, default=None, help="Maximum time in seconds to run the attack.")

    # File Paths
    path_args = parser.add_argument_group("File Path Arguments")
    path_args.add_argument("--output-dir", default=".", help="Directory to save decrypted files.")
    path_args.add_argument("--session-dir", default=".pdfraven_sessions", help="Directory to store session files.")
    path_args.add_argument("--db-file", default="found_passwords.json", help="Path to the password database file.")

    # General options
    gen_opts = parser.add_argument_group("General Options")
    gen_opts.add_argument("-h", "--help", action="store_true", help="Show this help message and exit.")
    
    # Subparsers for attack modes
    subparsers = parser.add_subparsers(dest="command", help="Attack mode", required=True)

    # Wordlist
    p_wordlist = subparsers.add_parser("wordlist", help="Dictionary attack")
    p_wordlist.add_argument("path", help="Path to the wordlist file.")

    # Range
    p_range = subparsers.add_parser("range", help="Numeric range attack")
    p_range.add_argument("min", type=int, help="Minimum number in the range.")
    p_range.add_argument("max", type=int, help="Maximum number in the range.")

    # Numeric
    p_numeric = subparsers.add_parser("numeric", help="Fixed-length numeric attack")
    p_numeric.add_argument("length", type=int, help="Length of the numbers to check.")

    # Date
    p_date = subparsers.add_parser("date", help="Date-based attack (DDMMYYYY)")
    p_date.add_argument("start_year", type=int, help="The starting year.")
    p_date.add_argument("end_year", type=int, help="The ending year.")
    p_date.add_argument("--format", default="DDMMYYYY", choices=["DDMMYYYY", "YYYYMMDD", "MMDDYYYY", "DDMMYY", "YYMMDD", "MMDDYY"], help="Date format (default: DDMMYYYY).")
    p_date.add_argument("--separator", default="", choices=["/", ".", "-", "_", ""], help="Separator character between date components (default: none).")

    # Custom Query (Legacy)
    p_custom = subparsers.add_parser("custom-query", help="Simple pattern attack (e.g., NAME{1-100})")
    p_custom.add_argument("query", help="The query string, e.g., 'ID-{1000-2000}'")
    p_custom.add_argument("--add-preceding-zeros", action="store_true", help="Pad numbers with leading zeros.")

    # Brute-force
    p_brute = subparsers.add_parser("brute", help="Advanced brute-force with custom charsets")
    p_brute.add_argument("mask", help="The password mask (e.g., 'w{4}d{2}'). See manual for syntax.")
    
    # Hybrid
    p_hybrid = subparsers.add_parser("hybrid", help="Combine two attack masks")
    p_hybrid.add_argument("masks", nargs='+', help="Two masks to combine (e.g., 'wordlist.txt' 'd{4}')")

    # Custom Brute-force
    p_custom_brute = subparsers.add_parser("custom-brute", help="Brute-force with a user-defined charset")
    p_custom_brute.add_argument("--charset", required=True, help="String of characters to use in the attack.")
    p_custom_brute.add_argument("--min-length", type=int, default=1, help="Minimum password length.")
    p_custom_brute.add_argument("--max-length", type=int, required=True, help="Maximum password length.")

    return parser

def main():
    parser = setup_arg_parser()
    args = parser.parse_args()

    if args.help:
        ui.print_manual()
        sys.exit(0)

    # --- Setup and Config ---
    # Pass configurable paths to the database module
    database.DB_FILE = args.db_file
    database.SESSION_DIR = args.session_dir

    ui.print_banner()

    # --- File Validation ---
    if not os.path.isfile(args.file):
        ui.log(f"File not found: [bold red]{args.file}[/bold red]", "danger")
        ui.log("Please check the file path and try again.", "info")
        sys.exit(1)

    try:
        with pikepdf.open(args.file) as pdf:
            ui.log("File is NOT password protected.", "warning")
            sys.exit(0)
    except pikepdf.PasswordError:
        ui.log("File is encrypted. Proceeding with attack...", "info")
    except Exception as e:
        ui.log(f"Could not open PDF. It may be corrupt or an unsupported format.", "danger")
        ui.log(f"Error details: {e}", "info")
        sys.exit(1)

    # --- DB Check ---
    db_pass = database.check_db_for_password(args.file)
    if db_pass:
        output_path = Path(args.output_dir)
        output_path.mkdir(exist_ok=True)
        decrypted_path = output_path / f"decrypted_{Path(args.file).name}"
        try:
            with pikepdf.open(args.file, password=db_pass) as pdf:
                pdf.save(decrypted_path)
        except Exception:
            decrypted_path = None
        ui.print_result(db_pass, args.file, decrypted_path)
        sys.exit(0)

    # --- Session Handling ---
    resume_password = None
    if args.resume:
        resume_password = database.load_session(args.file)
        if not resume_password:
            ui.log("No session found to resume, starting a new attack.", "warning")

    # --- Generator and Estimator Setup ---
    generator = None
    est_total = None

    try:
        if args.command == "wordlist":
            if not os.path.isfile(args.path):
                raise FileNotFoundError(f"Wordlist file not found: {args.path}")
            ui.log("Counting lines in wordlist for progress bar...", "info")
            est_total = sum(1 for _ in open(args.path, 'rb'))
            generator = generators.gen_wordlist(args.path, start_after=resume_password)

        elif args.command == "range":
            if args.min >= args.max:
                raise ValueError("The 'min' value for range must be less than the 'max' value.")
            est_total = (args.max - args.min) + 1
            generator = generators.gen_range(args.min, args.max, start_after=resume_password)

        elif args.command == "numeric":
            if args.length <= 0:
                raise ValueError("The 'length' for numeric mode must be a positive integer.")
            est_total = 10 ** args.length
            generator = generators.gen_numeric(args.length, start_after=resume_password)

        elif args.command == "date":
            if args.start_year > args.end_year:
                raise ValueError("The start year must not be after the end year.")
            est_total = (args.end_year - args.start_year + 1) * 366 # Approximation is fine
            generator = generators.gen_date(args.start_year, args.end_year, args.format, args.separator, start_after=resume_password)
            
        elif args.command == "custom-query":
             match = re.search(r'\{(\d+)-(\d+)\}', args.query)
             if match: est_total = int(match.group(2)) - int(match.group(1)) + 1
             else: raise ValueError("Invalid custom-query format. Expected something like 'PREFIX{min-max}SUFFIX'.")
             generator = generators.gen_custom_query(args.query, args.add_preceding_zeros, start_after=resume_password)

        elif args.command == "brute":
            est_total = generators.estimate_total_from_mask(args.mask)
            generator = generators.gen_from_mask(args.mask, start_after=resume_password)
            if est_total:
                ui.log(f"Calculated [bold cyan]{est_total:,}[/bold cyan] possible passwords.", "info")
            else:
                ui.log("Mask is too complex to estimate total. Progress bar will be indeterminate.", "warning")

        elif args.command == "hybrid":
            if len(args.masks) != 2:
                raise ValueError("Hybrid mode requires exactly two masks (e.g., a wordlist and a mask).")
            est_total = generators.estimate_total_hybrid(args.masks)
            generator = generators.gen_hybrid(args.masks, start_after=resume_password)
            if est_total:
                ui.log(f"Calculated [bold cyan]{est_total:,}[/bold cyan] possible passwords.", "info")
            else:
                ui.log("Could not estimate total for hybrid mode. Progress bar will be indeterminate.", "warning")

        elif args.command == "custom-brute":
            if args.min_length > args.max_length:
                raise ValueError("Min length cannot be greater than max length.")
            est_total = generators.estimate_total_custom_brute(args.charset, args.min_length, args.max_length)
            generator = generators.gen_custom_brute(args.charset, args.min_length, args.max_length, start_after=resume_password)
            if est_total:
                ui.log(f"Calculated [bold cyan]{est_total:,}[/bold cyan] possible passwords.", "info")

    except (ValueError, FileNotFoundError) as e:
        ui.log(f"Setup Error: {e}", "danger")
        ui.log("Please check your command and try again. Use -h for help.", "info")
        sys.exit(1)
    except Exception as e:
        ui.log(f"An unexpected error occurred during setup: {e}", "danger")
        sys.exit(1)

    if not generator:
        ui.log("Could not initialize a password generator for the selected mode.", "danger")
        sys.exit(1)
        
    # --- Execute The Attack ---
    found_password = None
    try:
        ui.log(f"Target: [bold]{args.file}[/bold]", "info")
        ui.log(f"Mode: [bold]{args.command.upper()}[/bold]", "info")
        found_password = cracker.run_attack(
            args.command, generator, est_total, args.file, args.threads, 
            args.batch_size, resume_password, args.timeout
        )
    except (KeyboardInterrupt, SystemExit):
        sys.exit(130)
    except Exception as e:
        ui.log(f"A critical error occurred during the attack: {e}", "danger")
        sys.exit(1)
    
    # --- Result Handling ---
    decrypted_path = None
    if found_password:
        database.save_to_db(args.file, found_password)
        if not args.no_decrypt:
            output_path = Path(args.output_dir)
            output_path.mkdir(exist_ok=True)
            decrypted_path = output_path / f"decrypted_{Path(args.file).name}"
            try:
                with pikepdf.open(args.file, password=found_password) as pdf:
                    pdf.save(decrypted_path)
            except Exception as e:
                ui.log(f"Could not save decrypted file: {e}", "danger")
                decrypted_path = None

    ui.print_result(found_password, args.file, decrypted_path)

if __name__ == "__main__":
    main()
