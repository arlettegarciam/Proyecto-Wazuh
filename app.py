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


@app.route('/dashboard')
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

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
            return redirect(url_for('dashboard'))  # Redirigir al dashboard después del login
        else:
            return render_template('login.html', error='Error al iniciar sesión.')
    return render_template('login.html')

@app.route('/search_keyword', methods=['GET', 'POST']) 
def search_keyword():
    if 'token' not in session:
        return redirect(url_for('login'))

    keyword_results = []

    if request.method == 'POST':
        keyword = request.form['keyword']

        if keyword:
            # URL del índice
            url = f"https://{host}:9200/wazuh-states-vulnerabilities-ip-172-31-24-173/_search"

            # Autenticación básica en formato base64
            credentials = f"{es_username}:{es_password}"
            b64_credentials = b64encode(credentials.encode()).decode()

            headers = {
                'Authorization': f'Basic {b64_credentials}',
                'Content-Type': 'application/json'
            }

            # Consulta: búsqueda por palabra clave en "description", "name" o "host.name"
 # Aquí creamos la consulta de búsqueda usando query_string para búsqueda flexible
            query = {
            "query": {
                "query_string": {
                    "query": f"*{keyword.lower()}*",
                    "fields": [
                        "vulnerability.description",
                        "vulnerability.id",
                        "vulnerability.reference",
                        "package.name",
                        "host.name"
                    ],
                    "analyze_wildcard": True
                }
            }
        }


            try:
                response = requests.post(url, headers=headers, json=query, verify=False)
                response.raise_for_status()

                hits = response.json().get('hits', {}).get('hits', [])
                keyword_results = hits if hits else []

            except requests.exceptions.RequestException as e:
                print(f"Error en la petición: {e}")

    return render_template('search_keyword.html', results=keyword_results)




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

        # Construir la consulta de Elasticsearch
        query = {
            "query": {
                "match_all": {}
            }
        }

        # Si se envió un filtro de gravedad, añadirlo a la consulta
        if request.method == 'POST':
            severity = request.form['severity']
            if severity:
                query = {
                    "query": {
                        "term": {
                            "vulnerability.severity": severity
                        }
                    }
                }

        try:
            # Realiza la solicitud a la API
            response = requests.post(url, auth=(es_username, es_password), headers=headers, json=query, verify=False)
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

    #Empieza parte del punto 7 
@app.route('/wazuh/config', methods=['GET'])
def get_manager_config():
    if 'token' not in session:
        return redirect(url_for('login'))

    url = f"{base_url_manager}/manager/configuration"
    headers = {
        'Authorization': f'Bearer {get_token_from_file()}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        config_data = response.json().get('data', {})
    except Exception as e:
        config_data = {"error": str(e)}

    return render_template('config.html', config=config_data)


@app.route('/wazuh/logs', methods=['GET'])
def get_logs():
    if 'token' not in session:
        return redirect(url_for('login'))

    token = get_token_from_file()
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    logs = {}
    try:
        logs_response = requests.get(f"{base_url_manager}/manager/logs", headers=headers, verify=False)
        logs_summary = requests.get(f"{base_url_manager}/manager/logs/summary", headers=headers, verify=False)

        logs = {
            "details": logs_response.json().get('data', {}),
            "summary": logs_summary.json().get('data', {})
        }

    except Exception as e:
        logs = {"error": str(e)}

    return render_template('logs.html', logs=logs)


@app.route('/wazuh/groups', methods=['GET'])
def get_groups():
    if 'token' not in session:
        return redirect(url_for('login'))

    url = f"{base_url_manager}/groups"
    headers = {
        'Authorization': f'Bearer {get_token_from_file()}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        groups = response.json().get('data', {}).get('affected_items', [])
    except Exception as e:
        groups = {"error": str(e)}

    return render_template('groups.html', groups=groups)


@app.route('/wazuh/tasks/status', methods=['GET'])
def get_task_status():
    if 'token' not in session:
        return redirect(url_for('login'))

    url = f"{base_url_manager}/tasks/status"
    headers = {
        'Authorization': f'Bearer {get_token_from_file()}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        status_data = response.json().get('data', {})
    except Exception as e:
        status_data = {"error": str(e)}

    return render_template('task_status.html', status=status_data)



@app.route('/wazuh_status')
def wazuh_status():
    if 'token' not in session:
        return redirect(url_for('login'))

    token = session['token']
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    base = f"{base_url_manager}"
    endpoints = {
        "configuration": "/manager/configuration",
        "logs": "/manager/logs",
        "logs_summary": "/manager/logs/summary",
        "groups": "/groups",
        "tasks_status": "/tasks/status"
    }

    results = {}

    try:
        for key, endpoint in endpoints.items():
            response = requests.get(f"{base}{endpoint}", headers=headers, verify=False)
            if response.status_code == 200:
                results[key] = response.json()
            else:
                results[key] = {"error": f"Error {response.status_code}"}
    except requests.exceptions.RequestException as e:
        results['error'] = str(e)

    return render_template('wazuh_status.html', results=results)

#termina parte del punto 7



@app.route('/logout')
def logout():
    session.clear()  # Esto elimina la sesión de usuario
    return redirect(url_for('login'))  # Redirige al login

if __name__ == '__main__':
    app.run(debug=True)
