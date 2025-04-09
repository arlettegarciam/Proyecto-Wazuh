import requests
import urllib3
from flask import Flask, render_template, request, redirect, url_for, session
from base64 import b64encode


# Desactiva advertencias de HTTPS (solo para pruebas)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuración del servidor Wazuh
protocol = 'https'
host = '54.218.56.253'
port_manager = 55000
base_url_manager = f"{protocol}://{host}:{port_manager}"

# Credenciales para Elasticsearch
es_username = '0224010'  # Sustituye con tu usuario de Elasticsearch
es_password = 'Amari110123!'  # Sustituye con tu contraseña de Elasticsearch


app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Función para leer el token desde el archivo
def get_token_from_file():
    try:
        with open('token.txt', 'r') as file:
            token = file.read().strip()
            return token
    except FileNotFoundError:
        print("El archivo token.txt no se encuentra.")
        return None

# Función para obtener el token de la API (usada solo para obtener un token nuevo)
def get_token(username, password):
    login_url = f"{base_url_manager}/security/user/authenticate"
    basic_auth = f"{username}:{password}".encode()
    headers = {
        "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        "Content-Type": "application/json"
    }
    response = requests.post(login_url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()["data"]["token"]
    else:
        print("Error al autenticar")
        return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = get_token(username, password)
        if token:
            # Guardar el token en el archivo token.txt
            with open('token.txt', 'w') as file:
                file.write(token)
            session['token'] = token
            return redirect(url_for('vulnerabilities'))  # Redirigir a la página de vulnerabilidades
        else:
            return render_template('login.html', error='Error al iniciar sesión.')
    return render_template('login.html')

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    if 'token' not in session:
        return redirect(url_for('login'))

    # Usamos el token desde el archivo
    token = get_token_from_file()
    vulnerabilities_list = []

    if token:
        # URL de la API de Elasticsearch para obtener vulnerabilidades
        url = "https://54.218.56.253:9200/wazuh-states-vulnerabilities-ip-172-31-24-173/_search?pretty=true"
        headers = {
            'Authorization': f'Bearer {token}',  # Aquí usamos el token de Wazuh para la autenticación de la API
            'Content-Type': 'application/json'
        }

        if request.method == 'POST':
            # Obtener los valores de los filtros del formulario
            severity = request.form['severity']
            agent_name = request.form['agent_name']
            vuln_id = request.form['vuln_id']
            date = request.form['date']

            # Construir los parámetros de la consulta
            params = []
            if severity:
                params.append(f"severity={severity}")
            if agent_name:
                params.append(f"agent_name={agent_name}")
            if vuln_id:
                params.append(f"vuln_id={vuln_id}")
            if date:
                params.append(f"date={date}")

            # Si hay parámetros de filtro, agregarlos a la URL
            if params:
                url += "&" + "&".join(params)

        try:
            # Realiza la solicitud a la API
            response = requests.get(url, auth=(es_username, es_password), headers=headers, verify=False)
            response.raise_for_status()  # Levantar un error si la respuesta no es 200

            # Imprimir la respuesta completa para verificar los datos
            print(response.json())  # Para ver el contenido exacto de la respuesta

            # Si la respuesta es válida, procesar los datos
            if response.status_code == 200:
                hits = response.json().get('hits', {}).get('hits', [])
                if hits:
                    vulnerabilities_list = hits
                else:
                    print("No se encontraron vulnerabilidades.")
            else:
                print(f"Error: {response.status_code} - {response.text}")

        except requests.exceptions.RequestException as e:
            print(f"Error en la petición: {e}")

    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities_list)


@app.route('/logout')
def logout():
    session.clear()  # Esto elimina la sesión de usuario
    return redirect(url_for('login'))  # Redirige al login

if __name__ == '__main__':
    app.run(debug=True)
