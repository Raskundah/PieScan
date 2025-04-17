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

def scan_directory(directory, known_hashes, vt_check):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = compute_hash(file_path)
            if not file_hash:
                continue

            # Local hash check
            if file_hash in known_hashes:
                print(f"\n[LOCAL HIT] {file_path}")
                print(f"Hash: {file_hash}")

            # VirusTotal check
            if vt_check:
                vt_result = check_virustotal(file_hash) # if yuou want to view different data, edit the virus total function and this section to display various json data.
                
                if vt_result["status"] == "found":
                    print(f"\n[VT RESULTS] {file_path}")
                    print(f"Hash: {file_hash}")
                    print(f"\nDetection Ratio: {vt_result['detections']}")
                    
                    # Display threat categories
                    if vt_result["categories"]:
                        print("\nThreat Categories:")
                        for category in vt_result["categories"]:
                            print(f"- {category['value']} (confidence: {category['count']})")
                    
                    # Display threat labels
                    if vt_result["labels"]:
                        print(f"Malware Names: {(vt_result['labels'])}\n")
                    
                    
                    print(f"\nFile Type: {vt_result['file_type']}")
                    print(f"Reputation Score: {vt_result['reputation']}")
                    
                elif vt_result["status"] == "not_found":
                    print(f"\n[VT MISS] {file_path} - Hash not in database")
                elif vt_result["status"] == "error":
                    print(f"\n[VT ERROR] {file_path} - {vt_result.get('error', 'Unknown error')}")

                    

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
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            return {"status": "not_found", "code": 404}
        
        response.raise_for_status()
        data = response.json()
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        
        # Handle both string and dictionary formats for threat labels
        
        
        return { # this section is where you want to modify the data returned from the function for displaying via the scan directory function.
            "status": "found",
            "code": 200,
            "malicious": stats.get("malicious", 0) > 0,
            "detections": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "categories": data["data"]["attributes"].get("popular_threat_classification", {}).get("popular_threat_category", []),
            "labels": data["data"]["attributes"].get("popular_threat_classification", {}).get("suggested_threat_label", []),
            "file_type": attributes.get("type_description", "Unknown"),
            "reputation": attributes.get("reputation", "N/A")
        }
        
    except Exception as e:
        return {
            "status": "error",
            "code": 500,
            "error": str(e)
        }

if __name__ == "__main__":
    main()