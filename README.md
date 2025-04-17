# Malware Hash Scanner 🔍

A Python script to scan directories for malicious files using local hash lists and the VirusTotal API. Ideal for cybersecurity investigations and threat hunting.

---

## 📋 Features
- **Recursive Directory Scanning**: Checks all subdirectories.
- **Dual Detection Modes**:
  - **Local Hash List**: Compare against known malware hashes.
  - **VirusTotal API**: Real-time lookup for threat intelligence.
- **SHA-256 Hashing**: Secure file hashing with error handling.
- **Lightweight**: No heavy dependencies.

---

## ⚙️ Prerequisites (Without Docker)
1. **Python 3.6+**  
   Verify with:  
   ```bash
   python --version

  Install Dependencies (Run as Admin):
    bash
  

    pip install requests python-dotenv

  If failed, install separately:
    bash
    Copy

    pip install requests
    pip install dotenv

  Environment Setup:

        Create a .env file in the project root:
        ini
   

        VT_API_KEY=your_virustotal_api_key_here

  Ensure your environment allows imported scripts (e.g., disable execution restrictions in PowerShell/CMD).

🚀 Usage
Basic Scan (Local Hash List Only)

  ```
{
 python scanner.py /path/to/scan --hash-list known_hashes.txt
}
```

Full Scan (Local + VirusTotal)

``` { python scanner.py /path/to/scan --hash-list known_hashes.txt --vt-check} ```

| Argument      | Description 
| :---        |    :----:   
| directory      | Path To Scan (required)      
| --hash-list    | Path to local hash list (Must enter one for local)
| --vt-check     | Enables VirusTotal API


🐋 Docker Support (Coming Soon!)

Note: Docker integration is under development.
