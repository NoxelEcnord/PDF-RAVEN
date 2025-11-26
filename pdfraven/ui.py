# pdfraven/ui.py
import sys
from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from .config import VERSION

# --- Rich Console Setup ---
custom_theme = Theme({
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "danger": "bold red",
    "header": "bold magenta",
    "banner": "bold blue",
})
console = Console(theme=custom_theme)

def print_banner():
    banner_text = f"""
    ██████╗ ██████╗ ███████╗██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
    ██████╔╝██║  ██║█████╗  ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
    ██╔═══╝ ██║  ██║██╔══╝  ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
    ██║     ██████╔╝██║     ██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
    ╚═╝     ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
    """
    sub_text = "       >> The Advanced PDF Recovery Tool <<\n" \
               f"            Author: Ecnord (GitHub: NoxelEcnord)\n" \
               f"            Version: {VERSION}"
    
    console.rule(style="banner") # New
    console.print(Text(banner_text, style="cyan"), justify="center")
    console.print(Text(sub_text, style="bold blue"), justify="center") # Changed style to bold blue
    console.print() # Add an extra line for spacing
    console.rule(style="banner") # New
    console.print() # Add an extra line for spacing

def log(message, level="info"):
    """Logs a message to the console with a given level."""
    console.print(message, style=level)

def print_manual():
    print_banner()
    manual = f"""
[bold]USER MANUAL[/bold]
--------------------------------------------------------------------------------
[header]DESCRIPTION[/header]
PDFRaven is a high-performance, multi-threaded tool designed to audit and recover
passwords for PDF documents. It uses smart caching to remember found passwords and
can resume interrupted sessions.

[header]MODES[/header]
1. [bold]wordlist[/bold]      : Standard dictionary attack using a text file.
   Usage: pdfraven -f doc.pdf wordlist rockyou.txt

2. [bold]range[/bold]         : Checks a specific integer range (e.g., PINs).
   Usage: pdfraven -f doc.pdf range 0 9999

3. [bold]numeric[/bold]       : Checks all numbers of a fixed length (auto-pads zeros).
   Usage: pdfraven -f doc.pdf numeric 6 (checks 000000-999999)

4. [bold]date[/bold]          : Checks all dates for a year range with customizable format and separator.
   Usage: pdfraven -f doc.pdf date 1990 2023 [--format DDMMYYYY] [--separator /]
   Formats: DDMMYYYY, YYYYMMDD, MMDDYYYY, DDMMYY, YYMMDD, MMDDYY
   Separators: /, ., -, _, (none)
   Example: pdfraven -f doc.pdf date 1990 1991 --format YYYYMMDD --separator -

5. [bold]custom-query[/bold]  : Smart pattern generation.
   Format: PREFIX{{MIN-MAX}}SUFFIX
   Usage: pdfraven -f doc.pdf custom-query "EMPLOYEE{{100-500}}-DATA"
   Flag: --add-preceding-zeros (Pads numbers to match max digit length)

6. [bold]brute[/bold]         : Full brute-force with a defined charset.
   Usage: pdfraven -f doc.pdf brute "w{4}d{2}"
   (w=lower, W=upper, d=digits, s=symbols, b=space)

7. [bold]hybrid[/bold]         : Combine multiple attack masks.
   Usage: pdfraven -f doc.pdf hybrid "myword" "d{4}"
   (This will try myword0000, myword0001, ...)

[header]VERBOSITY LEVELS[/header]
 -v    : Show basic process info.
 -vv   : Show batch processing details.
 -vvv  : Debug mode (worker traces, extensive info).

[header]DATABASE[/header]
Passwords found are stored in '[bold]found_passwords.json[/bold]'. PDFRaven checks this file 
before starting any attack. If the PDF hasn't changed, it unlocks instantly.
    "
    console.print(manual)
    sys.exit(0)

def get_progress_bar():
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        SpinnerColumn(),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        "<",
        TimeRemainingColumn(),
        console=console,
    )

def print_result(password, pdf_path, decrypted_path):
    console.rule(style="blue")
    if password:
        success_panel = Panel(
            f"[bold green]✔ SUCCESS! PASSWORD FOUND[/bold green]\n\n[bold white]{password}[/bold white]", # Added emoji
            title="[bold green]✔ Result[/bold green]", # Added emoji
            border_style="green",
            expand=False
        )
        console.print(success_panel)
        log("Password saved to database.", "success")
        if decrypted_path:
            log(f"Decrypted file saved: [bold]{decrypted_path}[/bold]", "success")
        else:
            log("Could not save decrypted file.", "danger")
    else:
        fail_panel = Panel(
            "[bold red]✖ FAILURE! PASSWORD NOT FOUND[/bold red]", # Added emoji
            title="[bold red]✖ Result[/bold red]", # Added emoji
            border_style="red",
            expand=False
        )
        console.print(fail_panel)
    console.rule(style="blue")
