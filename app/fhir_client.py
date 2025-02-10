from fhirclient import client
from fhirclient.models.patient import Patient
from app.config import FHIR_CONFIG

# Initialize FHIR Client
smart = client.FHIRClient(settings=FHIR_CONFIG)

def get_patient(patient_id: str):
    """Retrieve a patient record from the FHIR server."""
    try:
        patient = Patient.read(patient_id, smart.server)
        return {
            "id": patient.id,
            "name": smart.human_name(patient.name[0]) if patient.name else "Unknown",
            "birth_date": patient.birthDate.isostring if patient.birthDate else "Unknown"
        }
    except Exception as e:
        return {"error": str(e)}

def search_patients(name: str):
    """Search patients by name."""
    from fhirclient.models.patient import Patient
    search = Patient.where(struct={'name': name})
    patients = search.perform_resources(smart.server)
    return [{"id": p.id, "name": smart.human_name(p.name[0]) if p.name else "Unknown"} for p in patients]
