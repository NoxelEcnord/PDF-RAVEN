# pdfraven/database.py
import json
import os
from pathlib import Path
import pikepdf
from .ui import log

# These are module-level variables that will be set by main.py
DB_FILE = "found_passwords.json"
SESSION_DIR = ".pdfraven_sessions"

# --- Database Functions ---

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            log(f"Warning: Could not parse '{DB_FILE}'. Starting fresh.", "warning")
            return {}
    return {}

def save_to_db(pdf_path, password):
    db = load_db()
    abs_path = str(Path(pdf_path).resolve())
    db[abs_path] = password
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=4)
    except Exception:
        log(f"Error saving password to database '{DB_FILE}'.", "danger")

def check_db_for_password(pdf_path):
    db = load_db()
    abs_path = str(Path(pdf_path).resolve())
    
    if abs_path in db:
        saved_pass = db[abs_path]
        log(f"Found entry in database for this file. Testing password: [bold]{saved_pass}[/bold]", "info")
        try:
            with pikepdf.open(pdf_path, password=saved_pass):
                log("Database password matched! Skipping attack.", "success")
                return saved_pass
        except pikepdf.PasswordError:
            log("Database password incorrect (file changed?). Removing entry.", "warning")
            del db[abs_path]
            with open(DB_FILE, 'w') as f:
                json.dump(db, f, indent=4)
    return None

# --- Session Management ---

def get_session_file(pdf_path):
    """Gets the path for a session file based on the PDF's name."""
    session_path = Path(SESSION_DIR)
    session_path.mkdir(exist_ok=True)
    pdf_name = Path(pdf_path).stem
    return session_path / f"{pdf_name}.session"

def save_session(pdf_path, last_password):
    session_file = get_session_file(pdf_path)
    session_data = {'last_password': last_password}
    try:
        with open(session_file, 'w') as f:
            json.dump(session_data, f)
    except Exception:
        log(f"Warning: Could not save session to '{session_file}'.", "warning")

def load_session(pdf_path):
    session_file = get_session_file(pdf_path)
    if os.path.exists(session_file):
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
                log(f"Resuming session, starting after: [bold]{session_data['last_password']}[/bold]", "info")
                return session_data.get('last_password')
        except (json.JSONDecodeError, KeyError):
            log(f"Warning: Invalid session file '{session_file}'. Starting new session.", "warning")
            return None
    return None

def clear_session(pdf_path):
    session_file = get_session_file(pdf_path)
    if os.path.exists(session_file):
        try:
            os.remove(session_file)
        except OSError as e:
            log(f"Warning: Could not remove session file '{session_file}': {e}", "warning")
