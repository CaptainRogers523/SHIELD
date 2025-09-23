#!/usr/bin/env python3

import argparse
import os
import sys
import json
import hashlib
import requests
import math

# --- FILE SIGNATURES DATABASE ---
# Updated with more common file types
FILE_SIGNATURES = {
  # Common Image & Media
  "jpg": ["FFD8FF"],
  "jpeg": ["FFD8FF"],
  "png": ["89504E470D0A1A0A"],
  "gif": ["47494638"],
  "bmp": ["424D"],
  "mp3": ["494433"],
  "wav": ["52494646"],
  "mp4": ["0000001866747970"],

  # Documents
  "pdf": ["25504446"],
  "doc": ["D0CF11E0A1B11AE1"], # OLE2 for old Office docs
  "ppt": ["D0CF11E0A1B11AE1"],
  "docx": ["504B030414000600"], # Modern Office Docs
  "xlsx": ["504B030414000600"],
  "pptx": ["504B030414000600"],

  # Archives
  "zip": ["504B0304"],
  "rar": ["526172211A0700"],
  "7z": ["377ABCAF271C"],
  "gz": ["1F8B"],
  "bz2": ["425A68"],

  # Executables & Scripts
  "exe": ["4D5A"],
  "dll": ["4D5A"],
  "bat": ["406563686f206f6666"], # Common header for batch files
  "sh": ["23212F62696E"], # Common header for bash scripts
}

# --- VIRUSTOTAL API KEY ---
VIRUSTOTAL_API_KEY = 'deae405ef7b48319348a4438c04e8692ea6c966512f3d00bf82da1ba6b9d2f05'

# --- CORE ANALYZER FUNCTIONS ---
def read_magic_bytes(filepath, num_bytes=10):
    try:
        with open(filepath, 'rb') as f:
            return f.read(num_bytes)
    except Exception:
        return None

def get_file_extension(filepath):
    return os.path.splitext(filepath)[1].lstrip('.').lower()

def analyze_file(filepath):
    declared_ext = get_file_extension(filepath)
    file_header = read_magic_bytes(filepath)
    if file_header is None:
        return {'filepath': filepath, 'error': 'Failed to read file header.'}

    detected_ext = 'unknown'
    header_hex = file_header.hex().upper()

    for ext, sig_list in FILE_SIGNATURES.items():
        for sig in sig_list:
            if header_hex.startswith(sig):
                detected_ext = ext
                break
        if detected_ext != 'unknown':
            break

    is_suspicious = (detected_ext != 'unknown' and detected_ext != declared_ext)
    
    return {
        'filepath': filepath,
        'declared_type': declared_ext,
        'detected_type': detected_ext,
        'is_suspicious': is_suspicious
    }

# --- HASHER FUNCTION ---
def calculate_hash(filepath, hash_algorithm='sha256'):
    if not os.path.exists(filepath):
        return "File not found."

    try:
        hasher = hashlib.new(hash_algorithm)
    except ValueError:
        return f"Invalid hash algorithm: {hash_algorithm}"

    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error reading file for hashing: {e}"
    
# --- VIRUSTOTAL CHECKER FUNCTION ---
def check_hash_virustotal(hash_to_check):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'deae405ef7b48319348a4438c04e8692ea6c966512f3d00bf82da1ba6b9d2f05':
        return "API key missing or invalid."

    url = f"https://www.virustotal.com/api/v3/files/{hash_to_check}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data']['attributes']:
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    return f"Found by {malicious} vendors as malicious."
                else:
                    return "Not found as malicious by any vendor."
            return "Hash not found in VirusTotal database."
        elif response.status_code == 404:
            return "Hash not found in VirusTotal database."
        elif response.status_code == 401:
            return "Invalid API key."
        else:
            return f"Error: {response.status_code} - {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Network error: {e}"

# --- HEURISTIC ANALYSIS FUNCTION ---
def is_suspicious_name_and_size(filepath, declared_ext):
    filename = os.path.basename(filepath)
    suspicious_keywords = ['malware', 'virus', 'crack', 'keygen']
    executable_exts = ['exe', 'bat', 'cmd', 'ps1', 'sh', 'vbs', 'com']
    
    parts = filename.split('.')
    if len(parts) > 2 and parts[-1].lower() in executable_exts and parts[-2].lower() in ['jpg', 'png', 'pdf']:
        return "Double extension (e.g., .jpg.exe)"

    if any(keyword in filename.lower() for keyword in suspicious_keywords):
        return "Filename contains suspicious keyword."
    
    if declared_ext in ['txt', 'log'] and os.path.getsize(filepath) > 50 * 1024 * 1024:
        return "Suspiciously large file size."

    return None

# --- ENTROPY CALCULATION FUNCTION ---
def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            if not data:
                return 0.0
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            file_size = len(data)
            probabilities = [count / file_size for count in byte_counts]
            
            entropy = -sum([p * math.log2(p) for p in probabilities if p > 0])
            return entropy
    except Exception as e:
        return f"Error calculating entropy: {e}"

# --- NEW: REPORT WRITER ---
def report_writer(text, file_obj=None):
    print(text)
    if file_obj:
        file_obj.write(text + '\n')

# --- REPORTING AND SCANNING FUNCTIONS ---
def analyze_and_report_file(filepath, args, log_file=None):
    writer = lambda text: report_writer(text, log_file)
    
    file_hash_sha256 = calculate_hash(filepath, 'sha256')
    
    analysis_results = analyze_file(filepath)
    if 'error' in analysis_results:
        writer("-" * 30)
        writer(f"Error scanning file '{filepath}': {analysis_results['error']}")
        writer("-" * 30)
        return

    heuristic_reason = is_suspicious_name_and_size(filepath, analysis_results['declared_type'])
    file_hash_sha256 = calculate_hash(filepath, 'sha256')
    file_hash_md5 = calculate_hash(filepath, 'md5')

    writer("-" * 30)
    writer(f"File Path: {analysis_results['filepath']}")
    writer(f"Declared Type: {analysis_results['declared_type']}")
    writer(f"Detected Type: {analysis_results['detected_type']}")
    
    if analysis_results['is_suspicious']:
        writer("🚩 STATUS: Type Mismatch! Extension does not match its real type.")
    if heuristic_reason:
        writer(f"🚩 STATUS: Heuristic Suspicion - {heuristic_reason}")
    if not analysis_results['is_suspicious'] and not heuristic_reason:
        writer("✅ STATUS: OK.")

    if args.entropy:
        entropy_score = calculate_entropy(filepath)
        writer(f"\nEntropy Score: {entropy_score:.4f}")
        if isinstance(entropy_score, (float, int)) and entropy_score > 7.0:
            writer("❗ NOTE: High entropy suggests packed or encrypted data.")

    writer("\nFile Hashes:")
    writer(f"  SHA256: {file_hash_sha256}")
    writer(f"  MD5: {file_hash_md5}")
    
    writer("\n--- VIRUSTOTAL CHECK ---")
    vt_result = check_hash_virustotal(file_hash_sha256)
    writer(vt_result)
    writer("-" * 30)

def scan_directory(path, recursive, args, log_file=None):
    writer = lambda text: report_writer(text, log_file)
    writer(f"\n--- Starting Directory Scan for '{path}' ---")
    
    for root, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            analyze_and_report_file(filepath, args, log_file)
        
        if not recursive:
            break
    writer("\nScan complete.")

# --- NEW: WELCOME SCREEN FUNCTION ---
def show_welcome_screen():
    print("""
-------------------------------------------------------
 ********    **      **    **    ********    **          *******  
 **//////    /**     /**   /**   /**/////    /**         /**////** 
/**          /**     /**   /**   /**         /**         /**    /**
/*********   /**********   /**   /*******    /**         /**    /**
////////**   /**//////**   /**   /**////     /**         /**    /**
       /** **/**     /** **/** **/**       **/**       **/**    ** 
 ******** /**/**     /**/**/**/**/********/**/********/**/*******  
////////  // //      // // // // //////// // //////// // ///////   
                                                  
                                                    @Captain Rogers         
         Secure Hash Identifier & Log Defender
-------------------------------------------------------

A powerful tool to scan files and directories for suspicious activity.

Usage: shield <path> [-r] [-e] [-o] <file>

  <path>      Path to the file or directory to scan.

  -r, --recursive    Scan subdirectories as well.
  -e, --entropy      Perform file entropy analysis.
  -o, --output       Save the scan report to a file.

Example: shield -r -e /home/kali/Desktop
""")

# --- MAIN CLI LOGIC ---
def main():
    if len(sys.argv) == 1:
        show_welcome_screen()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description="File Type Identifier & Malware Hint Scanner",
        epilog="Example: shield my_file.jpg or -r /path/to/folder"
    )
    
    parser.add_argument('path', type=str, help="Path to the file or directory to scan.")
    parser.add_argument('-r', '--recursive', action='store_true', help="Scan subdirectories recursively.")
    parser.add_argument('-e', '--entropy', action='store_true', help="Perform file entropy analysis.")
    parser.add_argument('-o', '--output', type=str, help="Path to a file to save the scan report.")

    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path not found at '{args.path}'")
        sys.exit(1)

    log_file = None
    if args.output:
        try:
            log_file = open(args.output, 'w', encoding='utf-8')
        except Exception as e:
            print(f"Error: Could not open output file '{args.output}': {e}")
            sys.exit(1)

    try:
        if os.path.isfile(args.path):
            print("\n--- Starting File Scan ---")
            analyze_and_report_file(args.path, args, log_file)
            print("\nScan complete.")
        elif os.path.isdir(args.path):
            scan_directory(args.path, args.recursive, args, log_file)
    finally:
        if log_file:
            log_file.close()

if __name__ == '__main__':
    main()