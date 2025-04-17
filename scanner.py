import os # for directory traversal and api key handling 
import hashlib # for file hashing
import argparse # handling user input 
import requests # api requests
import time # rate limiting 
from dotenv import load_dotenv # safe api key handling 

# This script allows a user to scan for known malware or other unwanted files by their known hash 
# and is customasable based on adding hashes they require into the provided text file. 
# Written by Ian Barrie for CMP320 
# May be extended to honors project? who knows.

# Load API key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# TODO encrypt api key (the user should have their own api key so this may not be neccesary, dev's API key should not be posted.)
# TODO prompt user to enter their own key. Either create a .env file with it, or modify one. 
def main():
    args = parse_arguments() # takes in the user arguments. this is to allow users to know what input is required and query options. 
    known_hashes = load_known_hashes(args.hash_list) if args.hash_list else set() 
    scan_directory(args.directory, known_hashes, args.vt_check)

def parse_arguments(): # does what it says
    parser = argparse.ArgumentParser(description="Malware Hash Scanner")
    parser.add_argument("directory", help="Directory to scan") ## shows the arguments
    parser.add_argument("--hash-list", help="Path to local hash list file") # allows the user to choose their own hash list.
    parser.add_argument("--vt-check", action="store_true", help="Enable VirusTotal checks") # using virus total
    return parser.parse_args() # currently passes usage checks and correctly takes a directory variable. 

def load_known_hashes(hash_list_path):
    with open(hash_list_path, "r") as f:
        return set(line.strip().lower() for line in f) # loads the hashes from the file line by line, as a stripped lowercase string. also handles duplicates.

def scan_directory(directory, known_hashes, vt_check): # bulk of the code is here.
    print("Scanning directory.")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = compute_hash(file_path)
            if not file_hash: continue
            
            # Check local hash list
            if file_hash in known_hashes:
                print(f"[LOCAL HIT] {file_path} - {file_hash}\n")
            
            # TODO add logging when a file is successfully matched. perhaps a logging function to be used here and with virus total

            # Check VirusTotal if the user requests to.
            if vt_check:
                print("Checking Virus total.")
                vt_result = check_virustotal(file_hash)
                if vt_result["malicious"]:
                    print(f"[VT HIT] {file_path} - {file_hash}")
                    print(f"Detections: {vt_result['positives']}/{vt_result['total']}")
                    print(f"Malware Names: {', '.join(vt_result['names'])}\n")

def compute_hash(file_path, buffer_size=65536): # scans the file in 65536 byte chunks. 
    # TODO impliment threading for faster handling (falls under should haves.)
    try:
        sha256 = hashlib.sha256() # cause sha256 avoids hash collisions practically entirely. may switch to md5 if virustotal doesnt like sha256 as usual.
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha256.update(chunk)
        return sha256.hexdigest().lower()
    except Exception as e:
        print(f"Error reading {file_path}: {e}\n") # fixed formatting
        return None

def check_virustotal(file_hash):
    """Query VirusTotal v3 API with proper error handling"""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        # Handle specific status codes
        if response.status_code == 404:
            return {
                "error": "Hash not found in VirusTotal",
                "status_code": 404,
                "malicious": False
            }
        elif response.status_code == 429:
            print("[!] VirusTotal rate limit exceeded")
            time.sleep(60)  # Wait 1 minute before retrying
            return check_virustotal(file_hash)  # Recursive retry
            
        response.raise_for_status()
        
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        
        return {
            "malicious": stats["malicious"] > 0,
            "positives": stats["malicious"],
            "total": sum(stats.values()),
            "names": data["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_names", []),
            "status_code": 200
        }
        
    except requests.exceptions.RequestException as e:
        print(f"[!] VirusTotal API Error: {str(e)}")
        return {
            "error": str(e),
            "status_code": 500,
            "malicious": False
        }

if __name__ == "__main__":
    main()