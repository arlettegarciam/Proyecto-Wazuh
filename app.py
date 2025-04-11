import requests
import json
import urllib3
import subprocess
import json
from flask import Flask, render_template, request, redirect, url_for, session
from base64 import b64encode
from flask import flash, redirect, url_for


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


# Función para obtener las vulnerabilidades
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

# Función para obtener vulnerabilidades por palabra clave 
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

#Funciones para punto 3 agentes 
@app.route('/agents/upgrade', methods=['GET', 'POST'])
def upgrade_agents():
    if 'token' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        agents_list = request.form.getlist('agents_list')  # Lista de agentes a actualizar
        if agents_list:
            url = f"{base_url_manager}/agents/upgrade"
            token = get_token_from_file()  # Obtención del token desde el archivo
            if not token:
                flash("Token no disponible", "error")
                return redirect(url_for('login'))

            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            data = {
                "agents": agents_list  # Los agentes a actualizar
            }
            
            try:
                response = requests.post(url, headers=headers, json=data, verify=False)
                if response.status_code == 200:
                    flash('Agentes actualizados correctamente', 'success')
                else:
                    flash(f'Error al actualizar agentes: {response.text}', 'error')
            except requests.exceptions.RequestException as e:
                flash(f'Error en la petición: {e}', 'error')

    return render_template('agents.html')  # Página de formulario para seleccionar agentes

@app.route('/agents/restart/<agent_id>', methods=['POST'])
def restart_agent(agent_id):
    if 'token' not in session:
        return redirect(url_for('login'))

    url = f"{base_url_manager}/agents/{agent_id}/restart"
    token = get_token_from_file()  # Obtención del token desde el archivo
    if not token:
        flash("Token no disponible", "error")
        return redirect(url_for('login'))

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code == 200:
            flash(f'Agente {agent_id} reiniciado correctamente', 'success')
        else:
            flash(f'Error al reiniciar el agente {agent_id}: {response.text}', 'error')
    except requests.exceptions.RequestException as e:
        flash(f'Error en la petición: {e}', 'error')

    return redirect(url_for('list_agents'))  # Redirigir después de reiniciar

@app.route('/agents/delete/<agent_id>', methods=['POST'])
def delete_agent(agent_id):
    if 'token' not in session:
        return redirect(url_for('login'))

    url = f"{base_url_manager}/agents/{agent_id}/delete"
    token = get_token_from_file()  # Obtención del token desde el archivo
    if not token:
        flash("Token no disponible", "error")
        return redirect(url_for('login'))

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code == 200:
            flash(f'Agente {agent_id} eliminado correctamente', 'success')
        else:
            flash(f'Error al eliminar el agente {agent_id}: {response.text}', 'error')
    except requests.exceptions.RequestException as e:
        flash(f'Error en la petición: {e}', 'error')

    return redirect(url_for('list_agents'))  # Redirigir después de borrar

@app.route('/agents')
def list_agents():
    token = get_token_from_file()
    if not token:
        flash("No se pudo obtener el token de autenticación.", "danger")
        return render_template('agents.html', agents=[])

    # Usamos curl con el token para obtener los agentes
    try:
        curl_command = [
            'curl',
            '-X', 'GET',
            f'{base_url_manager}/agents',  # Endpoint para obtener agentes
            '-H', f'Authorization: Bearer {token}',
            '-H', 'Content-Type: application/json',
            '--insecure'  # Esto es para evitar problemas con SSL (si no tienes certificados válidos)
        ]
        
        # Ejecutamos el comando curl
        result = subprocess.run(curl_command, capture_output=True, text=True)

        # Verificamos si la ejecución fue exitosa
        if result.returncode == 0:
            # Convertimos el resultado JSON en un diccionario
            response_data = json.loads(result.stdout)
            agents_data = response_data.get('data', {}).get('affected_items', [])
            if not agents_data:
                flash("No se encontraron agentes.", "warning")
        else:
            flash(f"Error al obtener agentes: {result.stderr}", "danger")
            agents_data = []

    except subprocess.CalledProcessError as e:
        flash(f"Error en la solicitud curl: {e}", "danger")
        agents_data = []

    return render_template('agents.html', agents=agents_data)  # Mostrar lista de agentes



#Función para mostrar estados del servidor de Wazuh, (punto7)
#
@app.route('/top_agents')
def top_agents():

    # Construcción del token de Elasticsearch en base64
    basic_auth = f"{es_username}:{es_password}"
    b64_auth = b64encode(basic_auth.encode()).decode()

    url = "https://54.218.56.253:9200/wazuh-states-vulnerabilities-*/_search"

    headers = {
        'Authorization': f'Basic {b64_auth}',  # usa token de sesión
        'Content-Type': 'application/json'
    }

    query = {
        "size": 0,
        "aggs": {
            "by_agent": {
                "terms": {
                    "field": "agent.id",
                    "size": 10,
                    "order": { "_count": "desc" }
                },
                "aggs": {
                    "agent_info": {
                        "top_hits": {
                            "size": 1,
                            "_source": ["agent.id", "agent.name"]
                        }
                    }
                }
            }
        }
    }

    try:
        response = requests.get(url, headers=headers, json=query, auth=(es_username, es_password), verify=False)
        response.raise_for_status()
        data = response.json()

        # 👇 Esto imprime la respuesta completa en consola
        print(json.dumps(data, indent=2))

    except Exception as e:
        print(f"Error en la petición a Elasticsearch: {e}")
        return "Error consultando Elasticsearch"

    # Procesamos los datos
    top_agents = []
    for bucket in data['aggregations']['by_agent']['buckets']:
        agent_id = bucket['key']
        agent_name = bucket['agent_info']['hits']['hits'][0]['_source'].get('agent', {}).get('name', 'N/A')
        count = bucket['doc_count']
        top_agents.append({
            "id": agent_id,
            "name": agent_name,
            "count": count
        })

    return render_template("top_agents.html", agents=top_agents)
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
