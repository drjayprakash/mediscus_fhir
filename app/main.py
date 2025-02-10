# app/main.py

from fastapi import FastAPI
from app.routes.fhir import router as fhir_router

app = FastAPI()

app.include_router(fhir_router, prefix="/api")

from fastapi import APIRouter
from app.fhir_client import get_patient, search_patients

router = APIRouter()


@router.get("/fhir/patient/{patient_id}")
async def fetch_patient(patient_id: str):
    """Fetch a patient record from the FHIR server."""
    return get_patient(patient_id)


@router.get("/fhir/search")
async def search_patient_by_name(name: str):
    """Search for patients by name."""
    return search_patients(name)


app.include_router(router, prefix="/api")
