import pytest
from unittest.mock import MagicMock

# Since your client is in src/openvuln_mcp_server.py, 
# pytest should handle the src directory correctly if run from the project root.
# If not, you might need to adjust PYTHONPATH or use pytest path configuration.
from src.openvuln_mcp_server import CiscoOpenVulnClient

@pytest.fixture
def mock_cisco_client(mocker): # mocker is a fixture from pytest-mock
    """Provides a MagicMock instance of CiscoOpenVulnClient."""
    # We initialize with dummy credentials because the __init__ might require them,
    # but for most unit tests, we'll be mocking its methods directly.
    mock_client = MagicMock(spec=CiscoOpenVulnClient)
    # If __init__ itself does things we want to avoid (like making a real token call),
    # we might need to mock 'src.openvuln_mcp_server.CiscoOpenVulnClient' before instantiation.
    # For now, let's assume direct method mocking on the instance is sufficient.
    
    # Pre-configure common attributes or methods if needed for all tests using this fixture
    mock_client.access_token = "test_token"
    mock_client.token_expiry = "sometime_in_the_future"
    
    return mock_client

@pytest.fixture
def sample_advisory_data():
    """Provides sample raw data as if returned by cisco_client.get_advisory_by_id."""
    return {
        "advisories": [
            {
                "advisoryId": "cisco-sa-test-adv-123",
                "cves": [{"cveId": "CVE-2023-12345"}],
                "title": "Test Advisory Title",
                "publicationUrl": "http://example.com/cisco-sa-test-adv-123",
                "firstPublished": "2023-01-01T10:00:00Z",
                "lastUpdated": "2023-01-02T12:00:00Z",
                "severity": {"text": "High"},
                "summary": "This is a test summary."
            }
        ]
    }

@pytest.fixture
def sample_cve_data():
    """Provides sample raw data as if returned by cisco_client.get_cve_details."""
    return {
        "advisories": [
            {
                "advisoryId": "cisco-sa-related-adv-001",
                "title": "Related Advisory 1 for CVE",
                "publicationUrl": "http://example.com/cisco-sa-related-adv-001",
                "severity": {"text": "Critical"},
                "summary": "Summary for related advisory 1."
            },
            {
                "advisoryId": "cisco-sa-related-adv-002",
                "title": "Related Advisory 2 for CVE",
                "publicationUrl": "http://example.com/cisco-sa-related-adv-002",
                "severity": {"text": "High"},
                "summary": "Summary for related advisory 2."
            }
        ]
    }

@pytest.fixture
def sample_latest_advisories_data():
    """Provides sample raw data for latest advisories."""
    return {
        "advisories": [
            {
                "advisoryId": "cisco-sa-latest-1",
                "title": "Latest Advisory 1",
                "firstPublished": "2023-03-01T10:00:00Z",
                "lastUpdated": "2023-03-01T12:00:00Z",
                "severity": {"text": "Medium"}
            },
            {
                "advisoryId": "cisco-sa-latest-2",
                "title": "Latest Advisory 2",
                "firstPublished": "2023-03-02T10:00:00Z",
                "lastUpdated": "2023-03-02T12:00:00Z",
                "severity": {"text": "Low"}
            }
        ]
    }

