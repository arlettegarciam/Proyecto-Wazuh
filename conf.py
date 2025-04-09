import requests
from base64 import b64encode
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

protocol = 'https'
host = '54.218.56.253'
port = 55000
base_url = f"{protocol}://{host}:{port}"
username = '0224010'
password = 'Proyectociber123!'

# Obtener token
def get_token(username, password):
    url = f"{base_url}/security/user/authenticate"
    headers = {
        "Authorization": "Basic " + b64encode(f"{username}:{password}".encode()).decode(),
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()["data"]["token"]
    else:
        print("Error al autenticar")
        return None

# Consultar configuración
def get_configuration(token):
    url = f"{base_url}/manager/configuration"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers, verify=False)
    print(response.status_code)
    print(response.json())

token = get_token(username, password)
if token:
    get_configuration(token)
