# OpenVuln MCP Server

A Model Context Protocol (MCP) server for Cisco Security Advisories. This server provides tools to retrieve and list security advisories from the [Cisco OpenVuln API.](https://developer.cisco.com/docs/psirt/)

## Features

- Fetches Cisco security advisories by ID.
- Retrieves CVE details from Cisco.
- Lists the latest Cisco security advisories.
- Filters advisories by severity (Critical, High, Medium, Low).
- Gets advisories related to a specific product name.
- Handles Cisco OpenVuln API authentication and rate limiting.

## Prerequisites

- Python 3.x
- Cisco API Client ID and Client Secret. You can obtain these by registering an application on the [Cisco API Console](https://developer.cisco.com/).

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd openvuln-mcp-server
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up environment variables:**
    Create a `.env` file in the root of the project directory and add your Cisco API credentials:
    ```env
    CISCO_OPENVULN_CLIENT_ID="YOUR_CLIENT_ID"
    CISCO_OPENVULN_CLIENT_SECRET="YOUR_CLIENT_SECRET"
    ```
    The server uses `python-dotenv` to load these variables. Alternatively, you can set them directly in your shell environment.

## Running the Server

To start the MCP server, ensure your virtual environment is activated and your `.env` file is set up. Then, run the following command from the project root:

```bash
fastmcp run src/openvuln_mcp_server.py:mcp_server
```

Alternatively, if `fastmcp` is installed in your virtual environment (`.venv` by default):

```bash
.venv/bin/fastmcp run src/openvuln_mcp_server.py:mcp_server
```

The server will start using Uvicorn (via `fastmcp`) and will typically be available on `http://localhost:8000`. You'll see output indicating the server is running.

## Available MCP Tools

The server exposes the following tools via the Model Context Protocol:

-   `get_cisco_advisory_by_id`
    -   **Description:** Retrieves detailed information for a specific Cisco security advisory by its ID.
    -   **Parameters:** `advisory_id` (string) - e.g., "cisco-sa-iosxe-trustsec-bypass-LqL32QG"
-   `get_cisco_cve_details`
    -   **Description:** Retrieves details for a specific Common Vulnerability and Exposure (CVE) identifier from Cisco.
    -   **Parameters:** `cve_id` (string) - e.g., "CVE-2023-20078"
-   `get_latest_cisco_advisories`
    -   **Description:** Retrieves the most recently published Cisco security advisories.
    -   **Parameters:** `number` (integer, optional, default: 5)
-   `list_cisco_advisories_by_severity`
    -   **Description:** Lists Cisco security advisories filtered by their severity level.
    -   **Parameters:** `severity` (string) - Valid values: 'Critical', 'High', 'Medium', 'Low'.
-   `get_cisco_advisories_by_product`
    -   **Description:** Retrieves Cisco security advisories related to a specific product name.
    -   **Parameters:** `product_name` (string) - e.g., "Cisco IOS XE"

## How it Works

The `CiscoOpenVulnClient` class handles:
-   OAuth 2.0 authentication with the Cisco API.
-   Client-side rate limiting to comply with API quotas (per second, per minute, and per day).
-   Making requests to various OpenVuln API endpoints.

The `src/openvuln_mcp_server.py` script initializes this client. It then uses `FastMCP` (from `mcp.server.fastmcp`) to define an MCP server instance (named `mcp_server`). Tool functions are registered with this server instance using the `@mcp_server.tool()` decorator. These tools can then be invoked by an MCP client.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the LICENSE file for details (if one exists, otherwise specify).

