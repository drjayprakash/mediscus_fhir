# app/utils.py
import requests

def make_get_request(url: str, headers: dict = {}):
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception("Failed GET request")
    return response.json()
