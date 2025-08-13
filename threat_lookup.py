import requests
import csv
import os
from urllib.parse import urlparse
from prettytable import PrettyTable

# ----------------------------
# Abuse.ch API Auth Keys
# ----------------------------
THREATFOX_AUTH_KEY = "THREATFOX_AUTH_KEY"
URLHAUS_AUTH_KEY = "URLHAUS_AUTH_KEY"
MALWAREBAZAAR_AUTH_KEY = "MALWAREBAZAAR_AUTH_KEY"

# ----------------------------
# Validation Functions
# ----------------------------
def is_valid_ip(ip_address):
    try:
        parts = ip_address.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False

def is_valid_domain(domain):
    try:
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        return all(part.isalnum() or part == "-" for part in parts)
    except ValueError:
        return False

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_malware_hash(malware_hash):
    return len(malware_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in malware_hash)

def get_ioc_type(ioc):
    if is_valid_ip(ioc):
        return "ip_address"
    elif is_valid_domain(ioc):
        return "domain"
    elif is_valid_url(ioc):
        return "url"
    elif is_valid_malware_hash(ioc):
        return "malware_hash"
    else:
        return "unknown"

# ----------------------------
# Search Functions
# ----------------------------
def search_threatfox(ioc):
    results = []
    payload = {"query": "search_ioc", "search_term": ioc}
    headers = {"Auth-Key": THREATFOX_AUTH_KEY}
    try:
        response = requests.post("https://threatfox-api.abuse.ch/api/v1/", headers=headers, json=payload, timeout=10)
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"Error accessing ThreatFox API: {e}")
        return results

    if data.get("query_status") in ["ok", "success"] or data.get("status") == "success":
        table = PrettyTable()
        table.field_names = ["Indicator", "Type", "First Seen", "Last Seen", "Tags"]
        for indicator in data.get("data", []):
            table.add_row([
                indicator.get("ioc", ""),
                indicator.get("type", ""),
                indicator.get("first_seen", ""),
                indicator.get("last_seen", ""),
                ", ".join(indicator.get("tags", []))
            ])
            results.append({
                "Indicator": indicator.get("ioc", ""),
                "Type": indicator.get("type", ""),
                "First Seen": indicator.get("first_seen", ""),
                "Last Seen": indicator.get("last_seen", ""),
                "Tags": ", ".join(indicator.get("tags", []))
            })
        print(table)
    else:
        print(f"No data found for IOC: {ioc}")
    return results

def search_urlhaus(url):
    results = []
    payload = {"url": url}
    headers = {"Auth-Key": URLHAUS_AUTH_KEY}
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", headers=headers, data=payload, timeout=10)
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"Error accessing URLhaus API: {e}")
        return results

    if data.get("success"):
        url_data = data.get("url", {})
        table = PrettyTable()
        table.field_names = ["URL", "URL Status", "First Seen", "Last Seen", "Tags"]
        table.add_row([
            url_data.get("url", ""),
            url_data.get("url_status", ""),
            url_data.get("firstseen", ""),
            url_data.get("lastseen", ""),
            ", ".join(url_data.get("tags", []))
        ])
        results.append({
            "Indicator": url_data.get("url", ""),
            "Type": "URL",
            "First Seen": url_data.get("firstseen", ""),
            "Last Seen": url_data.get("lastseen", ""),
            "Tags": ", ".join(url_data.get("tags", []))
        })
        print(table)
    else:
        print(f"No data found for URL: {url}")
    return results

def search_malwarebazaar(malware_hash):
    results = []
    payload = {"query": "get_info", "hash": malware_hash}
    headers = {"Auth-Key": MALWAREBAZAAR_AUTH_KEY}
    try:
        response = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=payload, timeout=10)
        data = response.json()
    except (requests.RequestException, ValueError) as e:
        print(f"Error accessing MalwareBazaar API: {e}")
        return results

    if data.get("query_status") in ["ok", "found"]:
        table = PrettyTable()
        table.field_names = ["Indicator", "Type", "First Seen", "Last Seen", "Tags"]
        for sample in data.get("data", []):
            table.add_row([
                sample.get("sha256", ""),
                "Malware Hash",
                sample.get("first_seen", ""),
                sample.get("last_seen", ""),
                ", ".join(sample.get("tags", []))
            ])
            results.append({
                "Indicator": sample.get("sha256", ""),
                "Type": "Malware Hash",
                "First Seen": sample.get("first_seen", ""),
                "Last Seen": sample.get("last_seen", ""),
                "Tags": ", ".join(sample.get("tags", []))
            })
        print(table)
    else:
        print(f"No data found for hash: {malware_hash}")
    return results

# ----------------------------
# CSV Save Function
# ----------------------------
def save_results_to_csv(results):
    if not results:
        print("No results to save.")
        return
    filename = "threat_intelligence_results.csv"
    if os.path.exists(filename):
        os.remove(filename)
    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"Results saved to {filename}")

# ----------------------------
# Main Menu
# ----------------------------
def main():
    all_results = []

    while True:
        print("\nThreat Intelligence Lookup Tool")
        print("1. Search by IP Address")
        print("2. Search by Domain")
        print("3. Search by URL")
        print("4. Search by Malware Hash")
        print("5. Quit")

        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            ip = input("Enter the IP address: ")
            results = search_threatfox(ip)
        elif choice == "2":
            domain = input("Enter the domain: ")
            results = search_threatfox(domain)
        elif choice == "3":
            url = input("Enter the URL: ")
            results = search_urlhaus(url)
        elif choice == "4":
            hash_val = input("Enter the malware hash: ")
            results = search_malwarebazaar(hash_val)
        elif choice == "5":
            break
        else:
            print("Invalid choice.")
            continue

        all_results.extend(results)
        save_csv = input("Save all results to CSV? (y/n): ")
        if save_csv.lower() == "y":
            save_results_to_csv(all_results)

if __name__ == "__main__":
    main()
