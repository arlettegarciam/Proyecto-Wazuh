import requests
from base64 import b64encode
import urllib3
import os
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parámetros de la API
protocol = 'https'
host = '54.218.56.253'
port_manager = 55000
base_url_manager = f"{protocol}://{host}:{port_manager}"

# Credenciales para el API de Wazuh
username = '0224010'  # Tu usuario
password = 'Proyectociber123!'  # Tu contraseña

# Función para obtener el token desde el archivo
def get_token_from_file():
    if os.path.exists("token.txt"):
        with open("token.txt", "r") as file:
            return file.read().strip()
    return None

# Función para obtener un nuevo token
def get_token(username, password):
    login_url = f"{base_url_manager}/security/user/authenticate"
    basic_auth = f"{username}:{password}".encode()
    headers = {
        "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        "Content-Type": "application/json"
    }
    response = requests.post(login_url, headers=headers, verify=False)
    if response.status_code == 200:
        token = response.json()["data"]["token"]
        print(f"✅ Token obtenido correctamente:\n{token}")
        # Guardamos el token en un archivo
        with open("token.txt", "w") as f:
            f.write(token)
        return token
    else:
        print("❌ Error al autenticar")
        print("Código de estado:", response.status_code)
        print(response.text)
        return None

# Función para verificar si el token ha caducado
def is_token_valid(token):
    # Lógica básica para verificar si el token es válido.
    # Deberías decodificar el JWT y verificar la fecha de expiración (exp)
    try:
        import jwt
        decoded_token = jwt.decode(token, options={"verify_exp": False})  # No verifica la firma
        exp_timestamp = decoded_token['exp']  # Obtener la fecha de expiración del token
        if exp_timestamp < time.time():
            print("❌ El token ha caducado.")
            return False
        return True
    except Exception as e:
        print("❌ Error al verificar el token:", e)
        return False

# Función principal para obtener un token válido
def get_valid_token():
    token = get_token_from_file()
    if token and is_token_valid(token):
        return token
    print("⚠️ El token ha caducado o no existe, obteniendo uno nuevo...")
    return get_token(username, password)

# Uso de Flask para manejar la lógica
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/get_vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    token = get_valid_token()  # Asegurarse de tener un token válido
    if not token:
        return jsonify({"error": "No token available"}), 400

    vulnerabilities_url = f"{base_url_manager}/vulnerabilities"
    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(vulnerabilities_url, headers=headers, verify=False)
    
    if response.status_code == 200:
        return jsonify(response.json()), 200
    else:
        return jsonify({"error": "Failed to fetch vulnerabilities"}), response.status_code

if __name__ == '__main__':
    app.run(debug=True, port=5000)
