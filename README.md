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

   
