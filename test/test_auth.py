from fastapi.testclient import TestClient
from app.main import app  # Import your FastAPI app

client = TestClient(app)

def test_signup():
    # Test data
    signup_data = {
        "email": "test@example.com",
        "password": "password",
        "first_name": "Test",
        "last_name": "User"
    }

    # Send a POST request to the /signup endpoint
    response = client.post("/signup", json=signup_data)

    # Assert the response status code and message
    assert response.status_code == 200
    assert response.json() == {"message": "Primary user created successfully"}

    
def test_login():
    # Test data
    login_data = {
        "username": "test@example.com",
        "password": "password"
    }

    # Send a POST request to the /login endpoint
    response = client.post("/login", json=login_data)

    # Assert the response status code and structure
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "user_info" in response.json()