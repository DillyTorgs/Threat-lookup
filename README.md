Open threat_lookup.py and replace the placeholders with your own API keys:

python
Copy code
THREATFOX_AUTH_KEY = "YOUR_THREATFOX_KEY"
URLHAUS_AUTH_KEY = "YOUR_URLHAUS_KEY"
MALWAREBAZAAR_AUTH_KEY = "YOUR_MALWAREBAZAAR_KEY"
Run the script:

bash
Copy code
python threat_lookup.py
Follow the interactive menu to search by:

IP address

Domain

URL

Malware hash

Optionally save results to a CSV file.

Validation
The tool validates:

IPv4 addresses

Domains

URLs

SHA256 malware hashes

Security Note
Do not commit your personal API keys. Leave placeholders in the repository and have each user add their own keys locally.

License
This project is licensed under the MIT License.

If you want, I can also make a short version with badges and screenshots so it looks extra professional on GitHub. Do you want me to do that?
