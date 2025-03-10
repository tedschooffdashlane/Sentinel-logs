# 🚀 Dashlane to Microsoft Sentinel Log Integration

This script fetches **Dashlane team member data** (or device information) via the **Dashlane Public API** and sends it to **Microsoft Sentinel** for security monitoring.

1. Replace workspace ID and shared key with Sentinel information from specified workspace
2. Replace Dashlane API key from public API info in TAC
3. Call the desired API endpoint by inserting Dashlane_API_URL. Endpoints specified here: (https://dashlane.gitlab.dashlane.com/teams/code/server/misc/api-documentation-v2/category/public-api/)

4. Run script using command python3 *package name*.py

5. Navigate to specified Sentinel workspace and view logs 

(example command: "search * 
| sort by TimeGenerated desc")

---

## Features

Fetches **Dashlane team members** or **device information**  
Sends logs to **Azure Log Analytics (Microsoft Sentinel)**  
Uses **HMAC authentication** for secure API calls  
Supports **automated execution** via **Cron, Azure Functions, or AWS Lambda**  

---

## Setup & Installation

### **Prerequisites**
- **Python 3.8+** installed
- **Dashlane API Key** with appropriate permissions
- **Azure Sentinel (Log Analytics Workspace)**
- Install required Python packages:
  ```bash
  pip install requests
