import json
import requests

def cambiar_a_mayusculas(texto):
    return texto.upper()


def call_predict_function(texto_input):

    # URL de tu función desplegada
    # https://us-central1-cloudfunct-435801.cloudfunctions.net/predict_function
    # url = 'https://us-central1-cloudfunct-435801.cloudfunctions.net/predict_function_gen2_0'# 19.65 segundos
    # url = 'https://us-central1-cloudfunct-435801.cloudfunctions.net/predict_function_0'#51.92 segundos
    url = 'https://us-central1-cloudfunct-435801.cloudfunctions.net/predict_function_gen2_tiny_0' # 12 segundos

    # Datos que quieres enviar, ajusta según el formato esperado por tu función
    data = {
        "x": texto_input,
        "y": texto_input
    }

    # Convertir los datos a formato JSON
    json_data = json.dumps(data)

    # Enviar la solicitud POST a la función
    response = requests.post(url, data=json_data, headers={'Content-Type': 'application/json'})
    resp__ = response.json()

    print(resp__)

    # Imprimir la respuesta recibida
    print("Status Code:", response.status_code)
    print("Response Body:", response.json())
    return resp__

