# app/fhir.py
from fastapi import APIRouter, Depends, HTTPException
import requests
from app.config import FHIR_SERVER_BASE

router = APIRouter()

@router.get("/patients")
def get_patients():
    url = f"{FHIR_SERVER_BASE}/Patient"
    response = requests.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch patients")
    return response.json()
