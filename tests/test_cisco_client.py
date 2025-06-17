# This file contains unit tests for the CiscoOpenVulnClient class
# It is automatically discovered by pytest and can be used to define
# fixtures that are available to all tests in the project.

import pytest
import requests
import time
from datetime import datetime, timedelta
import json
from unittest.mock import patch, MagicMock

from src.openvuln_mcp_server import CiscoOpenVulnClient, CISCO_TOKEN_URL, CISCO_API_BASE_URL

# Test data
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"

def test_client_initialization_success():
    """Test successful client initialization."""
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    assert client.client_id == CLIENT_ID
    assert client.client_secret == CLIENT_SECRET
    assert client.access_token is None
    assert client.token_expiry is None

def test_client_initialization_missing_id():
    """Test client initialization fails with missing client ID."""
    with pytest.raises(ValueError, match="Client ID and Client Secret must be provided."):
        CiscoOpenVulnClient(None, CLIENT_SECRET)

def test_client_initialization_missing_secret():
    """Test client initialization fails with missing client secret."""
    with pytest.raises(ValueError, match="Client ID and Client Secret must be provided."):
        CiscoOpenVulnClient(CLIENT_ID, None)

@patch('src.openvuln_mcp_server.requests.post')
def test_get_access_token_success(mock_post):
    """Test successful access token acquisition."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "new_test_token",
        "expires_in": 3600
    }
    mock_post.return_value = mock_response

    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    client._get_access_token() # Call the protected method for testing

    assert client.access_token == "new_test_token"
    assert client.token_expiry is not None
    assert client.token_expiry > datetime.now()
    mock_post.assert_called_once_with(
        CISCO_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )

@patch('src.openvuln_mcp_server.requests.post')
def test_get_access_token_request_exception(mock_post):
    """Test access token acquisition fails due to RequestException."""
    mock_post.side_effect = requests.exceptions.RequestException("Network error")
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    with pytest.raises(ConnectionError, match="Failed to get access token: Network error"):
        client._get_access_token()

@patch('src.openvuln_mcp_server.requests.post')
def test_get_access_token_json_decode_error(mock_post):
    """Test access token acquisition fails due to JSONDecodeError."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "{}", 0)
    mock_post.return_value = mock_response
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    with pytest.raises(ValueError, match="Invalid token response: Invalid JSON"):
        client._get_access_token()

@patch('src.openvuln_mcp_server.requests.post')
def test_get_access_token_missing_token_in_response(mock_post):
    """Test access token acquisition fails if 'access_token' is not in the response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"expires_in": 3600} # Missing 'access_token'
    mock_post.return_value = mock_response
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    with pytest.raises(ValueError, match="Access token not found in response"):
        client._get_access_token()

@patch('src.openvuln_mcp_server.requests.post') # Mock post for token acquisition check
@patch.object(CiscoOpenVulnClient, '_apply_rate_limiting') # Mock rate limiting
@patch.object(CiscoOpenVulnClient, '_get_access_token') # Mock token acquisition method itself
@patch('src.openvuln_mcp_server.requests.get') # Mock the actual GET request
def test_make_api_call_success_token_valid(mock_requests_get, mock_obj_get_token, mock_rate_limit, mock_requests_post):
    """Test _make_api_call when token is valid."""
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    client.access_token = "valid_token"
    client.token_expiry = datetime.now() + timedelta(hours=1)

    mock_api_response = MagicMock()
    mock_api_response.status_code = 200
    mock_api_response.json.return_value = {"data": "success"}
    mock_requests_get.return_value = mock_api_response

    response = client._make_api_call("/test_endpoint")

    mock_rate_limit.assert_called_once()
    mock_obj_get_token.assert_called_once() # _get_access_token is always called by _make_api_call
    # Crucially, the actual http post to get a new token should not have happened if logic inside _get_access_token is correct
    mock_requests_post.assert_not_called() 
    mock_requests_get.assert_called_once_with(
        f"{CISCO_API_BASE_URL}/test_endpoint",
        headers={"Authorization": "Bearer valid_token", "Accept": "application/json"},
        params=None
    )
    assert response == {"data": "success"}

@patch.object(CiscoOpenVulnClient, '_apply_rate_limiting')
@patch.object(CiscoOpenVulnClient, '_get_access_token')
@patch('src.openvuln_mcp_server.requests.get')
def test_make_api_call_token_expired_refresh_success(mock_requests_get, mock_get_token, mock_rate_limit):
    """Test _make_api_call when token is expired and refresh is successful."""
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    client.access_token = None # Simulate expired/no token
    client.token_expiry = None

    # Configure _get_access_token mock to simulate successful refresh
    def side_effect_get_token():
        client.access_token = "refreshed_token"
        client.token_expiry = datetime.now() + timedelta(hours=1)
    mock_get_token.side_effect = side_effect_get_token

    mock_api_response = MagicMock()
    mock_api_response.status_code = 200
    mock_api_response.json.return_value = {"data": "refreshed_success"}
    mock_requests_get.return_value = mock_api_response

    response = client._make_api_call("/another_endpoint")

    mock_rate_limit.assert_called_once()
    mock_get_token.assert_called_once() # Token was expired, so new token was fetched
    mock_requests_get.assert_called_once_with(
        f"{CISCO_API_BASE_URL}/another_endpoint",
        headers={"Authorization": "Bearer refreshed_token", "Accept": "application/json"},
        params=None
    )
    assert response == {"data": "refreshed_success"}

@patch.object(CiscoOpenVulnClient, '_apply_rate_limiting')
@patch.object(CiscoOpenVulnClient, '_get_access_token')
@patch('src.openvuln_mcp_server.requests.get')
def test_make_api_call_token_refresh_fails(mock_requests_get, mock_get_token, mock_rate_limit):
    """Test _make_api_call when token refresh fails."""
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    client.access_token = None
    client.token_expiry = None

    mock_get_token.side_effect = ConnectionError("Token refresh failed")

    with pytest.raises(ConnectionError, match="Token refresh failed"):
        client._make_api_call("/fail_endpoint")
    
    # Ensure _is_token_expired() was true for _get_access_token to be called
    # (client.access_token is None, client.token_expiry is None implies _is_token_expired() is True)
    mock_get_token.assert_called_once() # This should have been called and raised an error
    mock_rate_limit.assert_not_called() # Should not be reached if _get_access_token (called earlier) fails
    mock_requests_get.assert_not_called() # API call should not happen if token refresh fails # API call should not happen if token refresh fails

@patch.object(CiscoOpenVulnClient, '_make_api_call')
def test_get_advisory_by_id_calls_make_api_call(mock_make_api_call):
    """Test that get_advisory_by_id calls _make_api_call with the correct URL."""
    client = CiscoOpenVulnClient(CLIENT_ID, CLIENT_SECRET)
    advisory_id = "cisco-sa-test-123"
    expected_url = f"/advisory/{advisory_id}"
    mock_make_api_call.return_value = {"advisoryId": advisory_id} # Sample return

    result = client.get_advisory_by_id(advisory_id)

    mock_make_api_call.assert_called_once_with(expected_url)
    assert result == {"advisoryId": advisory_id}

# TODO: Add more tests for other specific client methods (get_cve_details, etc.)
# TODO: Add tests for _apply_rate_limiting (these can be complex due to time involvement)

