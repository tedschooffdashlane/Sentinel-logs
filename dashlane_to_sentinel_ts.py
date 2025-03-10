import json
import requests
import hashlib
import hmac
import base64
import datetime

# Azure Sentinel Log Analytics Workspace Details
WORKSPACE_ID = "a9d4457e-9024-4865-a329-26f74c2fcc87"
SHARED_KEY = "j2TJsXoPWEPiU1ytmsRWzqeXhmqMNSn+C1zHvciAADJkV6o77G1F5Ak09lxm3fupcCXuK1Xp3vuOlBSZ18i3Lg=="
LOG_TYPE = "DashlaneMembers"  # Custom log name

# Dashlane API Endpoint
DASHLANE_API_URL = "https://api.dashlane.com/public/teams/Logs"
DASHLANE_API_KEY = "DLP_ac645e35-97db-491b-b8c3-064cc2159833_9DF2Z6QX3PY80K429NQJX4E9X3MFKQS3_cLj7hoptx7gk6JBhpGgrsgrgR3jQk8nYvECnfYWAj87ECGOhf4UhWOAeb3qfiiJt"

def get_dashlane_members():
    """Fetches member data from Dashlane API and prints response for debugging."""
    DASHLANE_API_URL = "https://api.dashlane.com/public/teams/Logs"  #Ensure correct API endpoint
    headers = {
        "Authorization": f"Bearer {DASHLANE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(DASHLANE_API_URL, headers=headers, json={})  #Ensures POST request
        response_text = response.text  # Get raw response text

        print(f"Raw API Response:\n{response_text}")  #Debugging line to inspect response

        if response.status_code == 200:
            try:
                response_data = response.json()  #Convert response to JSON
                members = response_data.get("data", {}).get("members", [])


                #Debugging: Check the type of `members`
                print(f"🛠 Type of 'members': {type(members)}")
                if members and isinstance(members[0], str):  # If list contains strings instead of dicts
                    print("⚠ Warning: API returned a list of strings instead of user objects.")
                    return []

                print(f"Successfully retrieved {len(members)} members from Dashlane.")
                return members

            except json.JSONDecodeError:
                print("Failed to decode JSON. Response might not be in expected format.")
                return []

        elif response.status_code == 401:
            print("Authentication Error: Invalid or expired Bearer Token.")
        elif response.status_code == 403:
            print("Access Denied: Ensure your Dashlane API key has the right permissions.")
        elif response.status_code == 404:
            print("API Endpoint Not Found: Check if the URL is correct.")
        else:
            print(f"Unexpected Error {response.status_code}: {response_text}")

    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")

    return []


def build_signature(date, content_length, content_type, resource):
    """Creates HMAC signature for Azure Log Analytics authentication."""
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(SHARED_KEY)
    hashed_string = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    encoded_hash = base64.b64encode(hashed_string).decode()
    return f"SharedKey {WORKSPACE_ID}:{encoded_hash}"

def send_logs_to_sentinel(logs):
    """Sends formatted logs to Microsoft Sentinel via Azure Monitor API."""
    body = json.dumps(logs)
    date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    resource = "/api/logs"
    content_type = "application/json"
    content_length = len(body)
    signature = build_signature(date, str(content_length), content_type, resource)

    headers = {
        "Authorization": signature,
        "Content-Type": content_type,
        "Log-Type": LOG_TYPE,
        "x-ms-date": date,
        "time-generated-field": "time_generated"
    }

    url = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    response = requests.post(url, headers=headers, data=body)

    if response.status_code == 200:
        print("Logs successfully sent to Sentinel.")
    else:
        print(f"Error sending logs: {response.text}")

if __name__ == "__main__":
    logs = get_dashlane_members()
    if logs:
        send_logs_to_sentinel(logs)