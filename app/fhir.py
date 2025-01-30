# app/fhir.py
from fastapi import APIRouter, Depends, HTTPException
import requests
from app.config import FHIR_SERVER_BASE
from app.models import Patient

router = APIRouter()

@router.get("/patients")
def get_patients():
    url = f"{FHIR_SERVER_BASE}/Patient"
    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch patients")
    return response.json()

@router.post("/patients")
def create_patient(patient: Patient):
    url = f"{FHIR_SERVER_BASE}/Patient"
    response = requests.post(url, json=patient.dict())
    if response.status_code != 201:
        raise HTTPException(status_code=400, detail="Failed to create patient")
    return response.json()

@router.put("/patients/{patient_id}")
def update_patient(patient_id: str, patient: Patient):
    url = f"{FHIR_SERVER_BASE}/Patient/{patient_id}"
    response = requests.put(url, json=patient.dict())
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to update patient")
    return response.json()

@router.delete("/patients/{patient_id}")
def delete_patient(patient_id: str):
    url = f"{FHIR_SERVER_BASE}/Patient/{patient_id}"
    response = requests.delete(url)
    if response.status_code != 204:
        raise HTTPException(status_code=400, detail="Failed to delete patient")
    return {"detail": "Patient deleted successfully"}
