#pytest

import pytest

from fastapi.testclient import TestClient
from app.main import app
from keycloak import KeycloakOpenID

# Initialize Keycloak client
keycloak_openid = KeycloakOpenID(
    server_url="https://auth.mediscus.in",
    client_id="smartfhirclient",
    realm_name="smart"
)

# Get a valid token
tokens = keycloak_openid.token("username", "password")
access_token = tokens["access_token"]

# Initialize TestClient
client = TestClient(app)

def test_secure_endpoint():
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/secure-data", headers=headers)
    assert response.status_code == 200