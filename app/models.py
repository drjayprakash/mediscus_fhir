# app/models.py
from pydantic import BaseModel

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str

class Patient(BaseModel):
    id: str
    name: str
    birthDate: str
