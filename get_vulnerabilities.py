import requests

# Token de autenticación obtenido
token = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNzQ0MDk0MTg1LCJleHAiOjE3NDQwOTUwODUsInN1YiI6IjAyMjQwMTAiLCJydW5fYXMiOmZhbHNlLCJyYmFjX3JvbGVzIjpbMSw1LDcsM10sInJiYWNfbW9kZSI6IndoaXRlIn0.AKlz271oZy63zdA9VS0s5WP3EyLWtfSz2MsH9P45qcPX717otjklU9IrsM637NqMERugmJ4A1wH1wot78n8PLne4AIYtSMTzcGt2Gg5JvvRkhiWkmFb4WckaeJaM_Yy7OV54CVNR82_1lGdIeg7UqLJheo4_vDMQxdh0AhJUW0UNnvo-'  # Reemplaza con el token que obtuviste

# URL de la API de vulnerabilidades
url = "https://54.218.56.253:55000/vulnerability?pretty=true"

# Cabeceras de la solicitud con el token
headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}

# Realizar la solicitud GET
response = requests.get(url, headers=headers, verify=False)

if response.status_code == 200:
    # Mostrar las vulnerabilidades si la respuesta es exitosa
    print(response.json())
else:
    print("Error al consultar las vulnerabilidades:", response.status_code)
