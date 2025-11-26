# pdfraven/generators.py
import itertools
import calendar
import re
import os
from .config import CHARSET_MAP

# --- Estimation Functions ---
def estimate_total_from_mask(mask):
    """Estimates the total number of passwords a mask will generate."""
    try:
        parsed_mask = parse_mask(mask)
        if not parsed_mask:
            return None
        total = 1
        for charset, len_range in parsed_mask:
            len_sum = 0
            for length in len_range:
                len_sum += len(charset) ** length
            total *= len_sum
        return total
    except Exception:
        return None

def estimate_total_hybrid(masks):
    if len(masks) != 2:
        return None
    try:
        _, total1 = get_generator_for_mask(masks[0])
        _, total2 = get_generator_for_mask(masks[1])
        if total1 is None or total2 is None:
            return None
        return total1 * total2
    except (ValueError, FileNotFoundError):
        return None

def estimate_total_custom_brute(charset, min_len, max_len):
    """Estimates the total passwords for a custom brute-force attack."""
    if min_len > max_len:
        return 0
    total = 0
    for length in range(min_len, max_len + 1):
        total += len(charset) ** length
    return total

# --- Password Generators ---

def gen_wordlist(path, start_after=None):
    found_start = not bool(start_after)
    with open(path, 'r', encoding='latin-1', errors='ignore') as f:
        for line in f:
            stripped_line = line.strip()
            if not found_start and stripped_line == start_after:
                found_start = True
                continue
            if found_start:
                yield stripped_line

def gen_range(start, end, start_after=None):
    current = int(start_after) + 1 if start_after else start
    for i in range(current, end + 1):
        yield str(i)

def gen_numeric(length, start_after=None):
    limit = 10 ** length
    start_num = int(start_after) + 1 if start_after else 0
    for i in range(start_num, limit):
        yield f"{i:0{length}d}"

def gen_date(start_year, end_year, date_format, separator, start_after=None):
    """
    Generates dates in specified format (DDMMYYYY, YYYYMMDD, MMDDYYYY, DDMMYY, YYMMDD, MMDDYY)
    with an optional separator.
    """
    resume_date_found = False
    if not start_after:
        resume_date_found = True # No start_after, so start immediately

    for year in range(start_year, end_year + 1):
        for month in range(1, 13):
            _, num_days = calendar.monthrange(year, month)
            for day in range(1, num_days + 1):
                # Construct date components
                d = f"{day:02d}"
                m = f"{month:02d}"
                y_full = str(year)
                y_short = str(year)[2:]

                # Build the date string based on format
                formatted_date_parts = []
                if date_format == "DDMMYYYY":
                    formatted_date_parts = [d, m, y_full]
                elif date_format == "YYYYMMDD":
                    formatted_date_parts = [y_full, m, d]
                elif date_format == "MMDDYYYY":
                    formatted_date_parts = [m, d, y_full]
                elif date_format == "DDMMYY":
                    formatted_date_parts = [d, m, y_short]
                elif date_format == "YYMMDD":
                    formatted_date_parts = [y_short, m, d]
                elif date_format == "MMDDYY":
                    formatted_date_parts = [m, d, y_short]
                else:
                    # Should not happen due to argparse choices, but for safety
                    raise ValueError(f"Invalid date format: {date_format}")

                current_date_str = separator.join(formatted_date_parts)

                if not resume_date_found:
                    if current_date_str == start_after:
                        resume_date_found = True
                    continue
                
                yield current_date_str

def gen_custom_query(query, add_zeros, start_after=None):
    match = re.search(r'(.*)\{(\d+)-(\d+)\}(.*)', query)
    if not match: return
    prefix, start, end, suffix = match.group(1), int(match.group(2)), int(match.group(3)), match.group(4)
    width = len(match.group(3)) if add_zeros else 0
    
    start_num = 0
    if start_after:
        try:
            start_num = int(re.search(r'\d+', start_after).group()) + 1
        except (ValueError, AttributeError):
            start_num = start
            
    for i in range(max(start, start_num), end + 1):
        num = f"{i:0{width}d}" if add_zeros else str(i)
        yield f"{prefix}{num}{suffix}"

def parse_mask(mask):
    """
    Parses a mask like "w{3}d{1,2}" into a list of character sets and lengths.
    """
    if not mask:
        raise ValueError("Mask cannot be empty.")

    parsed = []
    i = 0
    while i < len(mask):
        char_type = mask[i]
        if char_type not in CHARSET_MAP:
            raise ValueError(f"Invalid character type '{char_type}' in mask.")
        
        i += 1
        min_len, max_len = 1, 1

        if i < len(mask) and mask[i] == '{':
            i += 1
            len_match = ""
            while i < len(mask) and mask[i] != '}':
                len_match += mask[i]
                i += 1
            if i == len(mask):
                raise ValueError("Unterminated '{' in mask.")
            i += 1

            if ',' in len_match:
                min_str, max_str = len_match.split(',')
                min_len = int(min_str) if min_str else 1
                max_len = int(max_str) if max_str else min_len
            elif len_match:
                min_len = max_len = int(len_match)
        
        parsed.append((CHARSET_MAP[char_type], range(min_len, max_len + 1)))

    if not parsed:
        raise ValueError(f"Could not parse mask: '{mask}'")
        
    return parsed

def gen_from_mask(mask, start_after=None):
    """
    Generates passwords from a mask, e.g., "w{1,3}d"
    """
    parsed_mask = parse_mask(mask)

    charsets = [item[0] for item in parsed_mask]
    len_ranges = [item[1] for item in parsed_mask]

    segment_product_iterators = []
    for charset, len_range in zip(charsets, len_ranges):
        len_iterators = []
        for length in len_range:
            len_iterators.append(itertools.product(charset, repeat=length))
        segment_product_iterators.append(itertools.chain(*len_iterators))

    if not segment_product_iterators:
        return

    resuming = bool(start_after)
    for combination_tuple in itertools.product(*segment_product_iterators):
        parts = ["".join(part) for part in combination_tuple]
        password = "".join(parts)

        if resuming:
            if password == start_after:
                resuming = False
            continue
            
        yield password

def get_generator_for_mask(mask_string, start_after=None):
    """
    Determines the correct generator to use for a given mask string.
    """
    if os.path.isfile(mask_string):
        try:
            count = sum(1 for _ in open(mask_string, 'rb'))
            return (gen_wordlist(mask_string, start_after=start_after), count)
        except Exception as e:
            raise ValueError(f"Could not read wordlist: {mask_string}") from e
            
    elif re.match(r'^\d+-\d+$', mask_string):
        start, end = map(int, mask_string.split('-'))
        if start >= end:
            raise ValueError(f"Invalid range '{mask_string}'. Min must be less than max.")
        return (gen_range(start, end, start_after=start_after), (end - start + 1))
    else:
        try:
            total = estimate_total_from_mask(mask_string)
            return (gen_from_mask(mask_string, start_after=start_after), total)
        except ValueError as e:
            raise ValueError(f"Invalid mask format '{mask_string}'. Use 'w', 'W', 'd', 's', 'b', 'h', 'a' with optional lengths like {{min,max}}.") from e

def gen_hybrid(masks, start_after=None):
    """
    Generates passwords by combining multiple masks.
    """
    if len(masks) != 2:
        raise ValueError("Hybrid mode currently supports exactly two masks.")

    last_parts = [None, None]
    if start_after:
        try:
            gen1_preview, _ = get_generator_for_mask(masks[0])
            for part1 in gen1_preview:
                if start_after.startswith(part1):
                    last_parts[0] = part1
                    last_parts[1] = start_after[len(part1):]
                    break
            if last_parts[0] is None:
                start_after = None
        except Exception:
            start_after = None

    gen1, _ = get_generator_for_mask(masks[0], start_after=last_parts[0])
    
    for part1 in gen1:
        current_start_after_part2 = last_parts[1] if part1 == last_parts[0] else None
        gen2, _ = get_generator_for_mask(masks[1], start_after=current_start_after_part2)
        for part2 in gen2:
            yield f"{part1}{part2}"
        last_parts[0] = None

def gen_custom_brute(charset, min_l, max_l, start_after=None):
    """
    Generates passwords from a custom charset and length range.
    """
    start_len = len(start_after) if start_after else min_l
    
    for length in range(start_len, max_l + 1):
        g = itertools.product(charset, repeat=length)

        if start_after and len(start_after) == length:
            start_tuple = tuple(start_after)
            g = itertools.dropwhile(lambda x: x != start_tuple, g)
            next(g, None) 
            start_after = None

        for p in g:
            yield "".join(p)
