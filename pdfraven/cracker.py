# pdfraven/cracker.py
import concurrent.futures
import pikepdf
import time
from .ui import log, get_progress_bar
from .database import save_session, clear_session

# --- Core Cracking Worker ---

def attempt_crack_batch(pdf_path, passwords):
    """
    Worker function that attempts to open a PDF with a batch of passwords.
    This function is executed in a separate process.
    """
    # Suppress QPDF warnings by not configuring a logger here
    for password in passwords:
        try:
            # allow_overwriting_input=True is critical for performance
            with pikepdf.open(pdf_path, password=password, allow_overwriting_input=True):
                return password  # Password found
        except pikepdf.PasswordError:
            continue  # Wrong password
        except Exception:
            # Could be a malformed PDF or other issue
            continue
    return None

# --- Attack Dispatcher ---

def run_attack(attack_name, generator, total_est, pdf_path, workers, batch_size, resume_pass, timeout=None):
    log(f"Initializing [bold]{attack_name}[/bold] attack with [bold]{workers}[/bold] workers...", "info")
    if timeout:
        log(f"Attack will run for a maximum of [bold]{timeout}[/bold] seconds.", "info")

    pool = concurrent.futures.ProcessPoolExecutor(max_workers=workers)
    futures = []
    
    progress = get_progress_bar()
    task_id = progress.add_task("[cyan]Cracking...", total=total_est)
    
    found_password = None
    last_checked_password = resume_pass
    
    start_time = time.time()
    progress.start()
    try:
        batch = []
        for pwd in generator:
            batch.append(pwd)
            last_checked_password = pwd
            
            if len(batch) >= batch_size:
                futures.append(pool.submit(attempt_crack_batch, pdf_path, batch))
                batch = []
                
                # Throttle submission to avoid memory issues
                if len(futures) >= workers * 5:
                    # Wait for the first future to complete
                    done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        res = future.result()
                        progress.update(task_id, advance=batch_size)
                        if res:
                            found_password = res
                            break
                        futures.remove(future)
            
            if found_password:
                break
            
            if timeout and (time.time() - start_time) > timeout:
                log("\n[warning]Attack timed out.[/warning]", "warning")
                break
        
        # Submit final batch
        if batch and not found_password:
            futures.append(pool.submit(attempt_crack_batch, pdf_path, batch))
            
        # Process remaining futures
        if not found_password:
            # Calculate remaining time if a timeout is set
            remaining_time = timeout - (time.time() - start_time) if timeout else None
            
            for future in concurrent.futures.as_completed(futures, timeout=remaining_time):
                res = future.result()
                progress.update(task_id, advance=batch_size)
                if res:
                    found_password = res
                    break
    
    except concurrent.futures.TimeoutError:
        log("\n[warning]Attack timed out.[/warning]", "warning")
    except (KeyboardInterrupt, SystemExit):
        log("\n[warning]Attack aborted by user. Saving session...[/warning]")
    finally:
        progress.stop()
        pool.shutdown(wait=False, cancel_futures=True)

    # Session saving logic
    if found_password:
        clear_session(pdf_path)
    elif last_checked_password:
        save_session(pdf_path, last_checked_password)
        
    return found_password
