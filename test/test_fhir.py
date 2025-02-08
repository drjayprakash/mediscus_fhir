from fastapi.testclient import TestClient
from app.main import app  # Import your FastAPI app

client = TestClient(app)

def test_get_patients():
    # Send a GET request to the /patients endpoint
    response = client.get("/patients")

    # Assert the response status code and structure
    assert response.status_code == 200
    assert isinstance(response.json(), list)  # Assuming the response is a list of patients

def test_create_patient():
    # Test data
    patient_data = {
        "name": "John Doe",
        "birthDate": "1990-01-01"
    }

    # Send a POST request to the /patients endpoint
    response = client.post("/patients", json=patient_data)

    # Assert the response status code and structure
    assert response.status_code == 201
    assert "id" in response.json()  # Assuming the response includes the created patient's ID