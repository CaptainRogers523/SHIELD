# S.H.I.E.L.D.
<img width="940" height="746" alt="Screenshot (551)" src="https://github.com/user-attachments/assets/fbf2bd49-38b5-474a-9166-8edee47ee805" />

                                                    
S.H.I.E.L.D. is a powerful command-line utility for scanning files and directories for potential malware and suspicious activity. It uses multiple analysis techniques to provide a comprehensive report, helping you identify disguised threats on your system.

## Key Features

- **Magic Byte-based File Type Detection:** Accurately identifies a file's true type by reading its header, independent of the file's extension. This is a core defense against disguised malware.
- **Heuristic Analysis:** Scans for suspicious file names (e.g., `invoice.pdf.exe`) and unusually large file sizes to flag potential threats.
- **Entropy Analysis:** Measures the randomness of a file's data. High entropy scores can be a strong indicator of packed or encrypted content, a common malware tactic.
- **Secure Hashing:** Calculates SHA256 and MD5 hashes, providing a unique digital fingerprint for every file.
- **VirusTotal Integration:** Automatically checks a file's hash against the VirusTotal database to see if it's a known malicious file.
- **Recursive Directory Scanning:** Scans an entire directory and all its subdirectories for threats.
- **Report Logging:** Saves the entire scan report to a file for later analysis and auditing.

## Installation

To get S.H.I.E.L.D. up and running on a Kali Linux machine, follow these simple steps.

1.  **Install Python Dependencies:**
    ```bash
    sudo pip3 install requests
    ```
2.  **Add your VirusTotal API Key:**
    Open the `shield` script in a text editor and replace `'YOUR_API_KEY_HERE'` with your personal API key from the VirusTotal website.
3.  **Make the Script Executable:**
    ```bash
    chmod +x shield
    ```
4.  **Move the Script to PATH:**
    This command makes the `shield` tool accessible from any directory in your terminal.
    ```bash
    sudo mv shield /usr/local/bin/
    ```

## Usage

Run S.H.I.E.L.D. by simply typing `shield` followed by the path to the file or directory you want to scan. You can use the following flags to customize your scan.

### Examples

-   **Scan a single file:**
    `shield /home/kali/Desktop/my_document.pdf`

-   **Scan a directory recursively:**
    `shield -r /var/www/html`

-   **Scan a file with entropy analysis:**
    `shield -e /home/kali/Downloads/setup.exe`

-   **Scan a directory and save the report:**
    `shield -r /home/kali/documents -o scan_log.txt`

## Example Output

--- Starting File Scan ---
File Path: /home/kali/Downloads/eicar.txt
Declared Type: txt
Detected Type: unknown
🚩 STATUS: Heuristic Suspicion - Filename contains suspicious keyword.

Entropy Score: 7.0094
❗ NOTE: High entropy suggests packed or encrypted data.

File Hashes:
SHA256: 3395856ce81f2b7382dee72602f798b642f141408226065608d519b2f280f9e1
MD5: 44d88612fea8a8f36de82e1278abb02f

--- VIRUSTOTAL CHECK --- Found by 60 vendors as malicious.
Scan complete.


---

## Credits


This tool was created by **Captain Rogers** (Vinayak Prajapati) as a project to demonstrate file analysis and security concepts.
