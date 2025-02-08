import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture
def mock_keycloak_token():
    # Mock a valid Keycloak token
    return "mocked-access-token"

def test_secure_endpoint(mock_keycloak_token):
    # Send a GET request to a secure endpoint with the mocked token
    headers = {"Authorization": f"Bearer {mock_keycloak_token}"}
    response = client.get("/secure-data", headers=headers)

    # Assert the response status code and structure
    assert response.status_code == 200
    assert response.json() == {"message": "Secure data accessed successfully!"}