# This file contains unit tests for the MCP tools
# It is automatically discovered by pytest and can be used to define
# fixtures that are available to all tests in the project.

import pytest
from unittest.mock import MagicMock, patch

# Import tool functions from your src module
from src.openvuln_mcp_server import (
    get_cisco_advisory_by_id,
    get_cisco_cve_details,
    get_latest_cisco_advisories,
    list_cisco_advisories_by_severity,
    get_cisco_advisories_by_product,
    cisco_client # We'll need to patch this global client instance for the tools
)

# Test get_cisco_advisory_by_id
@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_advisory_by_id_success(mock_client, sample_advisory_data):
    mock_client.get_advisory_by_id.return_value = sample_advisory_data
    advisory_id = "cisco-sa-test-adv-123"
    
    result = get_cisco_advisory_by_id(advisory_id)
    
    mock_client.get_advisory_by_id.assert_called_once_with(advisory_id)
    assert result["status"] == "success"
    assert result["advisory"]["advisoryId"] == advisory_id
    assert result["advisory"]["title"] == "Test Advisory Title"
    assert result["advisory"]["cve"] == "CVE-2023-12345"

@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_advisory_by_id_no_data(mock_client):
    mock_client.get_advisory_by_id.return_value = {"advisories": []} # Empty list
    advisory_id = "non-existent-id"
    
    result = get_cisco_advisory_by_id(advisory_id)
    
    mock_client.get_advisory_by_id.assert_called_once_with(advisory_id)
    assert result["status"] == "No data found"
    assert result["advisory_id"] == advisory_id

@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_advisory_by_id_client_error(mock_client):
    mock_client.get_advisory_by_id.side_effect = Exception("API Client Error")
    advisory_id = "error-id"
    
    result = get_cisco_advisory_by_id(advisory_id)
    
    mock_client.get_advisory_by_id.assert_called_once_with(advisory_id)
    assert result["status"] == "error"
    assert "API Client Error" in result["message"]

# Test get_cisco_cve_details
@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_cve_details_success(mock_client, sample_cve_data):
    mock_client.get_cve_details.return_value = sample_cve_data
    cve_id = "CVE-2023-99999"
    
    result = get_cisco_cve_details(cve_id)
    
    mock_client.get_cve_details.assert_called_once_with(cve_id)
    assert result["status"] == "success"
    assert result["cve_id"] == cve_id
    assert len(result["advisories"]) == 2
    assert result["advisories"][0]["advisoryId"] == "cisco-sa-related-adv-001"

@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_cve_details_no_data(mock_client):
    mock_client.get_cve_details.return_value = {"advisories": []}
    cve_id = "CVE-non-existent"
    
    result = get_cisco_cve_details(cve_id)
    
    assert result["status"] == "No data found"
    assert result["cve_id"] == cve_id

# Test get_latest_cisco_advisories
@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_latest_cisco_advisories_success(mock_client, sample_latest_advisories_data):
    mock_client.get_latest_advisories.return_value = sample_latest_advisories_data
    num_advisories = 2
    
    result = get_latest_cisco_advisories(number=num_advisories)
    
    mock_client.get_latest_advisories.assert_called_once_with(num_advisories)
    assert result["status"] == "success"
    assert result["count"] == 2
    assert len(result["advisories"]) == 2
    assert result["advisories"][0]["advisoryId"] == "cisco-sa-latest-1"

@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_latest_cisco_advisories_default_number(mock_client, sample_latest_advisories_data):
    mock_client.get_latest_advisories.return_value = sample_latest_advisories_data
    
    result = get_latest_cisco_advisories() # Default number is 5
    
    mock_client.get_latest_advisories.assert_called_once_with(5)
    assert result["status"] == "success"

# Test list_cisco_advisories_by_severity
@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_list_cisco_advisories_by_severity_success(mock_client, sample_advisory_data):
    # Re-use sample_advisory_data for simplicity, assuming it matches structure
    mock_client.get_advisories_by_severity.return_value = sample_advisory_data 
    severity = "High"
    
    result = list_cisco_advisories_by_severity(severity)
    
    mock_client.get_advisories_by_severity.assert_called_once_with(severity)
    assert result["status"] == "success"
    assert result["severity"] == severity
    assert result["count"] == 1 # Based on sample_advisory_data
    assert result["advisories"][0]["advisoryId"] == "cisco-sa-test-adv-123"

def test_list_cisco_advisories_by_severity_invalid_level():
    result = list_cisco_advisories_by_severity("UnknownSeverity")
    assert result["status"] == "error"
    assert "Invalid severity level" in result["message"]

# Test get_cisco_advisories_by_product
@patch('src.openvuln_mcp_server.cisco_client', new_callable=MagicMock)
def test_get_cisco_advisories_by_product_success(mock_client, sample_advisory_data):
    mock_client.get_advisories_by_product.return_value = sample_advisory_data
    product_name = "Test Product"
    
    result = get_cisco_advisories_by_product(product_name)
    
    mock_client.get_advisories_by_product.assert_called_once_with(product_name)
    assert result["status"] == "success"
    assert result["product_name"] == product_name
    assert result["count"] == 1
    assert result["advisories"][0]["advisoryId"] == "cisco-sa-test-adv-123"

# Note: 
# The mock_cisco_client fixture from conftest.py is not directly used here because
# the tool functions in openvuln_mcp_server.py directly import and use the global 'cisco_client' instance.
# Therefore, we need to patch 'src.openvuln_mcp_server.cisco_client' for each test
# where a tool function is called. If cisco_client were passed as an argument to tools,
# we could use the fixture more directly.
