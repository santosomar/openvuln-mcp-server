# MCP Configuration for Cisco OpenVuln Server

This document details the Model Context Protocol (MCP) configuration for the Cisco OpenVuln MCP Server.

## 1. Overview of MCP

The Model Context Protocol (MCP) is a framework designed to allow language models (LLMs) to interact with external tools and services in a standardized way. It enables LLMs to request information or perform actions by calling predefined tools exposed by an MCP server.

Our server uses MCP to expose tools that interact with the Cisco OpenVuln API, providing access to security advisories.

## 2. Server Implementation with `fastmcp`

This project uses `fastmcp` to build and serve the MCP application. `fastmcp` simplifies the process of creating MCP servers by leveraging FastAPI and Uvicorn for HTTP serving and providing a convention-based approach for tool discovery.

-   **Main Server File**: The core logic for the MCP server is located in `src/openvuln_mcp_server.py`.
-   **Server Instance**: An instance of `FastMCP` (from the `mcp` package, which `fastmcp` utilizes) is created in this file:
    ```python
    from mcp.server.fastmcp import FastMCP
    # ... other imports ...

    mcp_server = FastMCP(name="CiscoOpenVulnMCPServer")
    ```
    The `name` argument gives a unique identifier to this MCP server.

## 3. Tool Definition

Tools are Python functions that the LLM can call. In this server, tools are defined using the `@mcp_server.tool()` decorator provided by the `FastMCP` instance.

-   **Decorator**: Each function intended to be an MCP tool is decorated with `@mcp_server.tool()`.
    ```python
    @mcp_server.tool()
    def get_cisco_advisory_by_id(advisory_id: str):
        """Retrieves detailed information for a specific Cisco security advisory by its ID.

        Args:
            advisory_id (str): The unique identifier of the Cisco security advisory (e.g., 'cisco-sa-iosxe-trustsec-bypass-LqL32QG').
        """
        # ... tool implementation ...
        return result
    ```
-   **Metadata Inference**: `FastMCP` automatically infers the tool's metadata:
    -   **Name**: The function name (e.g., `get_cisco_advisory_by_id`).
    -   **Description**: The main part of the function's docstring.
    -   **Parameters**: Inferred from the function's type hints and the `Args:` section in the docstring. Each argument's type hint and description (from the `Args:` section) are used to define the expected input schema for the tool.
    -   **Return Type**: The return type hint of the function helps define the output schema of the tool.

### Available Tools

This server exposes the following tools:

-   `get_cisco_advisory_by_id(advisory_id: str)`: Retrieves detailed information for a specific Cisco security advisory by its ID.
-   `get_cisco_cve_details(cve_id: str)`: Retrieves details for a specific CVE from Cisco.
-   `get_latest_cisco_advisories(number: int = 5)`: Retrieves the most recently published Cisco security advisories.
-   `list_cisco_advisories_by_severity(severity: str)`: Lists Cisco security advisories filtered by severity level (Critical, High, Medium, Low).
-   `get_cisco_advisories_by_product(product_name: str)`: Retrieves Cisco security advisories related to a specific product name.

## 4. Running the Server

To run the MCP server, use the `fastmcp` command-line tool from the root of the project directory:

```bash
/path/to/your/.venv/bin/fastmcp run src/openvuln_mcp_server.py:mcp_server
```

-   Replace `/path/to/your/.venv/bin/fastmcp` with the actual path to the `fastmcp` executable within your project's Python virtual environment (e.g., `.venv/bin/fastmcp`).
-   `src/openvuln_mcp_server.py` is the path to the Python file containing your server definition.
-   `mcp_server` is the name of the `FastMCP` instance variable within that file.

### Environment Variables

The server requires Cisco API credentials to function. These must be set as environment variables, typically in a `.env` file in the project root:

```
CISCO_OPENVULN_CLIENT_ID="your_client_id_here"
CISCO_OPENVULN_CLIENT_SECRET="your_client_secret_here"
```

### Network Configuration

By default, `fastmcp` serves the application over HTTP on `localhost` (or `0.0.0.0`) at port `8000`.

## 5. Interacting with the Server

-   **MCP Clients**: Any MCP-compliant client can interact with this server to list and execute the available tools.
-   **HTTP Interface / OpenAPI Docs**: When run with `fastmcp`, the server provides an HTTP interface. `fastmcp` typically exposes:
    -   OpenAPI (Swagger) documentation at the `/docs` endpoint (e.g., `http://localhost:8000/docs`).
    -   The raw OpenAPI schema at `/openapi.json`.
    These interfaces allow you to explore the API and tools interactively through your browser.
