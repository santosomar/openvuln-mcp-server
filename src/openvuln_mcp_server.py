# This is a Model Context Protocol (MCP) server for Cisco Security Advisories
# It provides tools to retrieve and list security advisories from the Cisco OpenVuln API.
# The Cisco OpenVuln API is a RESTful API that provides access to security advisories from the Cisco PSIRT (Product Security Incident Response Team).

# Author: Omar Santos @santosomar

import os
import requests
import json
import time
from datetime import datetime, timedelta
import sys # Added for sys.exit
from dotenv import load_dotenv # Added for .env file loading
from mcp.server.fastmcp import FastMCP

load_dotenv() # Load environment variables from .env file

# --- Configuration Constants ---
# Cisco OpenVuln API base URL
CISCO_API_BASE_URL = "https://apix.cisco.com/security/advisories/v2"
# Cisco OAuth 2.0 token endpoint
CISCO_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"

# Rate limit constants for Cisco OpenVuln API (per the documentation)
RATE_LIMIT_PER_SECOND = 5
RATE_LIMIT_PER_MINUTE = 30
RATE_LIMIT_PER_DAY = 5000

# Simple rate limiting interval to stay below 5 calls/second
# (1/5 calls/sec = 0.2 seconds per call)
SLEEP_INTERVAL_PER_CALL = 1.0 / RATE_LIMIT_PER_SECOND

# --- CiscoOpenVulnClient Class ---
class CiscoOpenVulnClient:
    """
    A client for interacting with the Cisco PSIRT OpenVuln API, handling
    authentication, rate limiting, and request/response management.
    """
    def __init__(self, client_id: str, client_secret: str):
        """
        Initializes the CiscoOpenVulnClient.

        Args:
            client_id (str): Your Cisco API Client ID.
            client_secret (str): Your Cisco API Client Secret.
        """
        if not client_id or not client_secret:
            raise ValueError("Client ID and Client Secret must be provided.")

        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expiry = None
        self.last_api_call_time = datetime.min # To track per-second rate limit
        self.calls_this_minute = 0
        self.minute_start_time = datetime.now()
        self.calls_this_day = 0
        self.day_start_time = datetime.now().date()

        print("CiscoOpenVulnClient initialized.")

    def _get_access_token(self):
        """
        Retrieves a new OAuth 2.0 access token from Cisco.
        Handles token expiry and refresh.
        """
        # Check if current token is still valid
        if self.access_token and self.token_expiry and datetime.now() < self.token_expiry:
            # print("Using existing access token.")
            return

        print("Attempting to acquire a new access token...")
        try:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            response = requests.post(CISCO_TOKEN_URL, headers=headers, data=data)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

            token_data = response.json()
            self.access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in", 3600) # Default to 1 hour if not provided
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 300) # Refresh 5 mins before expiry

            if self.access_token:
                print("Access token acquired successfully.")
            else:
                raise ValueError("Access token not found in response.")

        except requests.exceptions.RequestException as e:
            print(f"Error acquiring access token: {e}")
            raise ConnectionError(f"Failed to get access token: {e}") from e
        except json.JSONDecodeError as e:
            print(f"Error decoding token response: {e}")
            raise ValueError(f"Invalid token response: {e}") from e

    def _apply_rate_limiting(self):
        """
        Applies client-side rate limiting based on Cisco's API quotas.
        """
        # Per-second rate limit
        time_since_last_call = (datetime.now() - self.last_api_call_time).total_seconds()
        if time_since_last_call < SLEEP_INTERVAL_PER_CALL:
            sleep_duration = SLEEP_INTERVAL_PER_CALL - time_since_last_call
            # print(f"Sleeping for {sleep_duration:.2f} seconds to respect per-second rate limit.")
            time.sleep(sleep_duration)
        self.last_api_call_time = datetime.now()

        # Per-minute rate limit
        if (datetime.now() - self.minute_start_time).total_seconds() >= 60:
            self.calls_this_minute = 0
            self.minute_start_time = datetime.now()
        self.calls_this_minute += 1
        if self.calls_this_minute > RATE_LIMIT_PER_MINUTE:
            # This is a crude way; a token bucket would be better.
            # For simplicity, if we hit the minute limit, sleep until the next minute.
            sleep_until_next_minute = 60 - (datetime.now() - self.minute_start_time).total_seconds() + 1
            print(f"Approaching minute rate limit. Sleeping for {sleep_until_next_minute:.2f} seconds.")
            time.sleep(sleep_until_next_minute)
            self.calls_this_minute = 1 # Reset for the new minute
            self.minute_start_time = datetime.now()

        # Per-day rate limit
        if datetime.now().date() != self.day_start_time:
            self.calls_this_day = 0
            self.day_start_time = datetime.now().date()
        self.calls_this_day += 1
        if self.calls_this_day > RATE_LIMIT_PER_DAY:
            print("Daily rate limit exceeded. Please wait until tomorrow.")
            raise Exception("Daily API rate limit exceeded.") # Or implement a longer wait/notification

    def _make_api_call(self, endpoint: str, params: dict = None):
        """
        Makes a GET request to the Cisco OpenVuln API.
        Includes authentication, rate limiting, and error handling.

        Args:
            endpoint (str): The API endpoint (e.g., "/advisory/cisco-sa-20230101-example").
            params (dict, optional): Dictionary of query parameters. Defaults to None.

        Returns:
            dict: JSON response from the API.

        Raises:
            requests.exceptions.RequestException: For network or HTTP errors.
            Exception: For API-specific errors or rate limit issues.
        """
        self._get_access_token() # Ensure token is fresh (method handles its own expiry check)
        self._apply_rate_limiting() # Apply client-side rate limits

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        url = f"{CISCO_API_BASE_URL}{endpoint}"
        print(f"Making API call to: {url} with params: {params}")

        try:
            response = requests.get(url, headers=headers, params=params)
            # Check for 429 Too Many Requests and respect Retry-After
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                print(f"Rate limit hit (429). Retrying after {retry_after} seconds.")
                time.sleep(retry_after)
                # After sleeping, try the request again (recursive call, but with a limit in a real app)
                return self._make_api_call(endpoint, params)
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            # Check for Cisco-specific error codes in the response body
            if "errorCode" in data and data["errorCode"] != "0":
                error_message = data.get("errorMessage", "Unknown Cisco API error")
                print(f"Cisco API Error: {data['errorCode']} - {error_message}")
                raise Exception(f"Cisco API Error: {error_message} (Code: {data['errorCode']})")
            
            return data

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err} - {http_err.response.text}")
            raise
        except requests.exceptions.ConnectionError as conn_err:
            print(f"Connection error occurred: {conn_err}")
            raise
        except requests.exceptions.Timeout as timeout_err:
            print(f"Timeout error occurred: {timeout_err}")
            raise
        except requests.exceptions.RequestException as req_err:
            print(f"An unexpected error occurred: {req_err}")
            raise
        except json.JSONDecodeError as json_err:
            print(f"Error decoding JSON response: {json_err} - Response text: {response.text}")
            raise

    # --- OpenVuln API Endpoints as Client Methods ---

    def get_all_advisories(self):
        """Retrieves a comprehensive list of all advisories."""
        return self._make_api_call("/all")

    def get_advisory_by_id(self, advisory_id: str):
        """Fetches detailed information for a specific security advisory."""
        return self._make_api_call(f"/advisory/{advisory_id}")

    def get_cve_details(self, cve_id: str):
        """Retrieves details associated with a particular CVE identifier."""
        return self._make_api_call(f"/cve/{cve_id}")

    def get_latest_advisories(self, number: int):
        """Returns a specified number of the most recently published advisories."""
        return self._make_api_call(f"/latest/{number}")

    def get_advisories_by_severity(self, severity: str):
        """Filters advisories by their assigned severity level."""
        # Normalize severity to title case as per API examples
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low"
        }
        normalized_severity = severity_map.get(severity.lower(), severity)
        return self._make_api_call(f"/severity/{normalized_severity}")

    def get_advisories_by_product(self, product_name: str):
        """Retrieves vulnerability information by product name."""
        # The /product endpoint expects 'productName' as a query parameter
        return self._make_api_call("/product", params={"productName": product_name})

# --- MCP Server Setup ---

# Retrieve API credentials from environment variables
# IMPORTANT: Never hardcode these in your source code!
CLIENT_ID = os.environ.get("CISCO_OPENVULN_CLIENT_ID")
CLIENT_SECRET = os.environ.get("CISCO_OPENVULN_CLIENT_SECRET")

if not CLIENT_ID or not CLIENT_SECRET:
    print("ERROR: CISCO_OPENVULN_CLIENT_ID and CISCO_OPENVULN_CLIENT_SECRET environment variables are not set.")
    print("Please create a .env file in the project root with your Cisco API credentials, or set them in your environment.")
    print("Example .env file content:")
    print("CISCO_OPENVULN_CLIENT_ID=\"YOUR_CLIENT_ID\"")
    print("CISCO_OPENVULN_CLIENT_SECRET=\"YOUR_CLIENT_SECRET\"")
    print("Exiting. Please configure the credentials and restart the server.")
    sys.exit(1)

try:
    cisco_client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
except ValueError as e:
    # This catch is a safeguard, the check above should prevent this.
    print(f"Error initializing CiscoOpenVulnClient: {e}")
    print("Ensure your Client ID and Secret are correctly set in your .env file or environment variables.")
    sys.exit(1)
mcp_server = FastMCP(name="CiscoOpenVulnMCPServer")

# --- MCP Tool Definitions and Implementations ---

@mcp_server.tool()
def get_cisco_advisory_by_id(advisory_id: str):
    """Retrieves detailed information for a specific Cisco security advisory by its ID.

    Args:
        advisory_id (str): The unique identifier of the Cisco security advisory (e.g., 'cisco-sa-iosxe-trustsec-bypass-LqL32QG').
    """
    try:
        data = cisco_client.get_advisory_by_id(advisory_id)
        if not data or not data.get("advisories"):
            return {"status": "No data found", "advisory_id": advisory_id}
        
        advisory = data["advisories"][0] # Assuming one advisory for ID
        # Extract relevant fields for LLM readability
        formatted_advisory = {
            "advisoryId": advisory.get("advisoryId"),
            "cve": ", ".join([cve.get("cveId") for cve in advisory.get("cves", [])]) if advisory.get("cves") else "N/A",
            "title": advisory.get("title"),
            "publicationUrl": advisory.get("publicationUrl"),
            "firstPublished": advisory.get("firstPublished"),
            "lastUpdated": advisory.get("lastUpdated"),
            "severity": advisory.get("severity", {}).get("text"),
            "summary": advisory.get("summary"),
            # You can add more fields as needed for LLM context
        }
        return {"status": "success", "advisory": formatted_advisory}
    except Exception as e:
        print(f"Error in get_cisco_advisory_by_id: {e}")
        return {"status": "error", "message": str(e)}

@mcp_server.tool()
def get_cisco_cve_details(cve_id: str):
    """Retrieves details for a specific Common Vulnerability and Exposure (CVE) identifier from Cisco.

    Args:
        cve_id (str): The CVE ID to look up (e.g., 'CVE-2023-20078').
    """
    try:
        data = cisco_client.get_cve_details(cve_id)
        if not data or not data.get("advisories"):
            return {"status": "No data found", "cve_id": cve_id}

        # The API returns a list of advisories related to the CVE, so we process them.
        formatted_advisories = []
        for adv in data["advisories"]:
            formatted_advisories.append({
                "advisoryId": adv.get("advisoryId"),
                "title": adv.get("title"),
                "publicationUrl": adv.get("publicationUrl"),
                "severity": adv.get("severity", {}).get("text"),
                "summary": adv.get("summary")
            })
        return {"status": "success", "cve_id": cve_id, "advisories": formatted_advisories}
    except Exception as e:
        print(f"Error in get_cisco_cve_details: {e}")
        return {"status": "error", "message": str(e)}

@mcp_server.tool()
def get_latest_cisco_advisories(number: int = 5):
    """Retrieves the most recently published Cisco security advisories.

    Args:
        number (int, optional): The number of latest advisories to retrieve (e.g., 10). Defaults to 5.
    """
    try:
        data = cisco_client.get_latest_advisories(number)
        if not data or not data.get("advisories"):
            return {"status": "No data found", "number": number}
        
        formatted_advisories = []
        for adv in data["advisories"]:
            formatted_advisories.append({
                "advisoryId": adv.get("advisoryId"),
                "title": adv.get("title"),
                "firstPublished": adv.get("firstPublished"),
                "lastUpdated": adv.get("lastUpdated"),
                "severity": adv.get("severity", {}).get("text"),
            })
        return {"status": "success", "count": len(formatted_advisories), "advisories": formatted_advisories}
    except Exception as e:
        print(f"Error in get_latest_cisco_advisories: {e}")
        return {"status": "error", "message": str(e)}

@mcp_server.tool()
def list_cisco_advisories_by_severity(severity: str):
    """Lists Cisco security advisories filtered by their severity level.

    Args:
        severity (str): The severity level. Valid values: 'Critical', 'High', 'Medium', 'Low' (case-insensitive).
    """
    valid_severities = ["critical", "high", "medium", "low"]
    if severity.lower() not in valid_severities:
        return {"status": "error", "message": f"Invalid severity level. Must be one of: {', '.join(valid_severities)}."}
    
    try:
        data = cisco_client.get_advisories_by_severity(severity)
        if not data or not data.get("advisories"):
            return {"status": "No data found", "severity": severity}
        
        formatted_advisories = []
        for adv in data["advisories"]:
            formatted_advisories.append({
                "advisoryId": adv.get("advisoryId"),
                "title": adv.get("title"),
                "firstPublished": adv.get("firstPublished"),
                "lastUpdated": adv.get("lastUpdated"),
                "publicationUrl": adv.get("publicationUrl"),
            })
        return {"status": "success", "severity": severity, "count": len(formatted_advisories), "advisories": formatted_advisories}
    except Exception as e:
        print(f"Error in list_cisco_advisories_by_severity: {e}")
        return {"status": "error", "message": str(e)}

@mcp_server.tool()
def get_cisco_advisories_by_product(product_name: str):
    """Retrieves Cisco security advisories related to a specific product name.

    Args:
        product_name (str): The name of the Cisco product (e.g., 'Cisco IOS XE').
    """
    try:
        data = cisco_client.get_advisories_by_product(product_name)
        if not data or not data.get("advisories"):
            return {"status": "No data found", "product_name": product_name}

        formatted_advisories = []
        for adv in data["advisories"]:
            formatted_advisories.append({
                "advisoryId": adv.get("advisoryId"),
                "title": adv.get("title"),
                "publicationUrl": adv.get("publicationUrl"),
                "severity": adv.get("severity", {}).get("text"),
                "firstPublished": adv.get("firstPublished"),
            })
        return {"status": "success", "product_name": product_name, "count": len(formatted_advisories), "advisories": formatted_advisories}
    except Exception as e:
        print(f"Error in get_cisco_advisories_by_product: {e}")
        return {"status": "error", "message": str(e)}