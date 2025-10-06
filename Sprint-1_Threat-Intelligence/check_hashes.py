import requests
import time
API_KEY = "YOUR_VIRUSTOTAL_API_KEY" # Replace with your actual API key
hashes = [
"Aa?36e1a3e40e4e5a62b5b12bcd227?b", # Replace with the actual hashes
"f?d2d2d2d2d2d2d2d2d2d2d2d2d2d2?2",
"5d?1402abc4b2a76b9719d911017c5?2",
"6a?b8c9d0e1f2g3h4i5j6k7l8m9n0o?p"
]
for index, file_hash in enumerate(hashes):
url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
headers = {"x-apikey": API_KEY}
response = requests.get(url, headers=headers)
data = response.json()
if "data" in data and "attributes" in data["data"]:
stats = data["data"]["attributes"]["last_analysis_stats"]
vendors = data["data"]["attributes"].get("last_analysis_results", {})
if stats["malicious"] > 0:
detected_by = []
for vendor, result in vendors.items():
if result["category"] == "malicious":
detected_by.append(f"{vendor}: {result['result']}")
print(f" {file_hash} is flagged as malicious by:")
for detection in detected_by:
print(f" - {detection}")
else:
print(f"✅ {file_hash} appears clean.")
if (index + 1) % 4 == 0:
print(" Waiting for 60 seconds to stay within API rate limit...")
time.sleep(60)