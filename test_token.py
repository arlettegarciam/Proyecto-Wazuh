import requests
from base64 import b64encode
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

host = '54.218.56.253'
port = 55000
username = '0224010'  # cambia si no es el correcto
password = 'Amari110123!'

url = f"https://{host}:{port}/security/user/authenticate"

auth = f"{username}:{password}".encode()
headers = {
    "Authorization": f"Basic {b64encode(auth).decode()}",
    "Content-Type": "application/json"
}

response = requests.post(url, headers=headers, verify=False)

if response.status_code == 200:
    print("✅ ¡Token obtenido correctamente!")
    print(response.json()["data"]["token"])
else:
    print("❌ Error al autenticar.")
    print("Código de estado:", response.status_code)
    print(response.text)
