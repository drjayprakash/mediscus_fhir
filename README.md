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

python -m venv venv

source venv/Scripts/activate    #gitbash

uvicorn app.main:app --reload
```

## Endpoints
- `/login` - Initiate OAuth2 authentication
- `/callback` - Handle Keycloak token exchange
- `/patients` - Fetch FHIR Patient data



Recreate the Virtual Environment
Try the following steps:

#Delete any existing virtual environment folder if it exists


rm -rf venv  # On Windows (Git Bash), use `rm -rf venv`


#Create a new virtual environment

python -m venv venv


#Activate the virtual environment

On Windows (Command Prompt):

venv\Scripts\activate

On Windows (Git Bash):

source venv/Scripts/activate


On Mac/Linux:

source venv/bin/activate


Upgrade pip (to avoid dependency issues)

python -m pip install --upgrade pip

#install requirements

pip install -r requirements.txt
