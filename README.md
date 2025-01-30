# README.md
# SMART on FHIR FastAPI Project

## Overview
This project implements a SMART on FHIR authentication and FHIR interaction using FastAPI.

## Features
- OAuth2 authentication with Keycloak
- Fetch FHIR resources from HAPI FHIR server
- FastAPI-based backend

## Installation
```sh
pip install -r requirements.txt
```

## Running the Project
```sh
uvicorn app.main:app --reload
```

## Endpoints
- `/login` - Initiate OAuth2 authentication
- `/callback` - Handle Keycloak token exchange
- `/patients` - Fetch FHIR Patient data
