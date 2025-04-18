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
- **Docker Support**: Uses docker to run on various CLI's if desired without manually importing.
- **Flexibility**: Can be modified to user's needs.

---

## ⚙️ Prerequisites (Without Docker)
1. **Python 3.6+**  
   Verify with:  
   ```
   python --version
  Install Dependencies (Run as Admin):

    pip install requests python-dotenv

  If failed, install separately:
    
    

    pip install requests
    pip install dotenv

  Environment Setup:

  Create a .env file in the project root:
        
   

    VT_API_KEY=your_virustotal_api_key_here

  Ensure your environment allows imported scripts (e.g., disable execution restrictions in PowerShell/CMD).

  ---

## 🚀 Usage
Basic Scan (Local Hash List Only)

```
 python scanner.py /path/to/scan --hash-list known_hashes.txt
```

Full Scan (Local + VirusTotal)

```
python scanner.py /path/to/scan --hash-list known_hashes.txt --vt-check}
```

| Argument      | Description 
| :---        |    :----:   
| directory      | Path To Scan (required)      
| --hash-list    | Path to local hash list (Must enter one for local)
| --vt-check     | Enables VirusTotal API


---

## 🐋 Docker Support!

The script comes prepackaged with a dockerfile ready to build.

simply perform the following 

```
docker build -t yourBuildName .
```

To add the directory to be scanned on your machine:

```
docker run -v your/directory/here:/scandir 
```

To establish your API key for Virus Total:

```
-e VT_API_KEY=YOUR_KEY_HERE
```

and to add a local hash list to the scan:

```
.\Your/hash/file:/app/hashes.txt
```

and the final command will look something like this for all options.

```
docker run -v .\Directory\to\scan:/scandir -e VT_API_KEY=YOUR_API_KEY -v .\your/hash/file.txt:/app/hashes.txt  yourBuildName  --hash-list hashes.txt --vt-check
```

Make sure to use the path type based on the local OS. I.E "\" for windows and "/" for linux. 

I am but a student and unable to aid in much technical support.


---

## 📂 File Structure


├── scanner.py             # Main script  
├── known_hashes.txt       # Example local hash list  
├── /Default               # Holds the test file to check local scan works.  
├── .env                   # API key storage  
└── README.md              # This file  

---

## ⚠️ Notes

  * VirusTotal Rate Limits: Free API allows 4 requests/minute. Add time.sleep(15) in the code if needed.

  * Hash List Format: One hash per line (SHA-256, lowercase).

  * Permissions: Run with admin rights to access restricted files. 


## 📜 License

MIT License - Use responsibly for authorized testing only.
