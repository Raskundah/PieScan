import os
import hashlib
import argparse
import requests
import time
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
# TODO encrypt api key (the user should have their own api key so this may not be neccesary, dev's API key should not be posted.)

def main():
    args = parse_arguments() ##takes in the user arguments. 
    known_hashes = load_known_hashes(args.hash_list) if args.hash_list else set()
    scan_directory(args.directory, known_hashes, args.vt_check)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Malware Hash Scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--hash-list", help="Path to local hash list file") ## using local file list.
    parser.add_argument("--vt-check", action="store_true", help="Enable VirusTotal checks") ## using virus total
    return parser.parse_args() ## currently passes usage checks and correctly takes a directory variable. 

def load_known_hashes(hash_list_path):
    with open(hash_list_path, "r") as f:
        return set(line.strip().lower() for line in f) ##  loads the hashes from the file line by line, as a stripped lowercase string.

def scan_directory(directory, known_hashes, vt_check): ## bulk of the code is here.
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = compute_hash(file_path)
            if not file_hash: continue
            
            # Check local hash list
            if file_hash in known_hashes:
                print(f"[LOCAL HIT] {file_path} - {file_hash}")
            
            # TODO add logging when a file is successfully matched. perhaps a logging function to be used here and with virus total

            # Check VirusTotal if the user requests to.
            if vt_check:
                vt_result = check_virustotal(file_hash)
                if vt_result["malicious"]:
                    print(f"[VT HIT] {file_path} - {file_hash}")
                    print(f"Detections: {vt_result['positives']}/{vt_result['total']}")
                    print(f"Malware Names: {', '.join(vt_result['names'])}\n")

def compute_hash(file_path, buffer_size=65536): ## scans the file in 65536 byte chunks. 
    # TODO impliment threading for faster handling (falls under should haves.)
    try:
        sha256 = hashlib.sha256() ## cause sha256 avoids hash collisions practically entirely. may switch to md5 if virustotal doesnt like sha256 as usual.
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                sha256.update(chunk)
        return sha256.hexdigest().lower()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}" ## the file hash to be checked on virus total.
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        time.sleep(15) ## Handles api rate limiting, as we can take 4 calls a minute on a free api key.
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json() ## allows returning of the result in json format. 
        
        return {
            "malicious": data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0,
            "positives": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "total": sum(data["data"]["attributes"]["last_analysis_stats"].values()),
            "names": list(data["data"]["attributes"]["popular_threat_classification"]["suggested_threat_names"]),
        }
    except Exception as e:
        print(f"VirusTotal Error: {e}") ## lets hope we dont have to deal with this.
        return {"malicious": False, "positives": 0, "total": 0, "names": []}

if __name__ == "__main__":
    main()