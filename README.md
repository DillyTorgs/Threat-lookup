Threat Intelligence Lookup Tool


A Python-based threat intelligence tool that queries Abuse.ch APIs: ThreatFox, URLhaus, and MalwareBazaar. Quickly check IPs, domains, URLs, and malware hashes, and export results to CSV.

Features
✅ Search ThreatFox for IPs or domains

✅ Search URLhaus for malicious URLs

✅ Search MalwareBazaar for malware hashes

✅ Interactive menu-driven interface

✅ PrettyTable output for readability

✅ Export results to CSV

Demo Screenshot

Installation
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/threat-intel-lookup.git
cd threat-intel-lookup
Install dependencies:

bash
Copy code
pip install requests prettytable
Usage
Add your API keys in threat_lookup.py:

python
Copy code
THREATFOX_AUTH_KEY = "YOUR_THREATFOX_KEY"
URLHAUS_AUTH_KEY = "YOUR_URLHAUS_KEY"
MALWAREBAZAAR_AUTH_KEY = "YOUR_MALWAREBAZAAR_KEY"
Run the script:

bash
Copy code
python threat_lookup.py
Choose an option from the menu:

IP address

Domain

URL

Malware hash

Optionally save results to CSV.

API Key Security
Important: Do not commit your API keys to GitHub. Leave placeholders in the repository, and have each user add their own keys locally.

License
This project is licensed under the MIT License.
