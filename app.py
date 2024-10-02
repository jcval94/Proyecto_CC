from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests
import json
import os
import time
from authlib.integrations.flask_client import OAuth

from helpers.utils import cambiar_a_mayusculas, call_predict_function  # Importamos la función que cambiará a mayúsculas

#------------------------------------APP
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
#------------------------------------AUTENTICACIÓN

oauth = OAuth(app)
# Configuración de Google OAuth
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),  # Usar variables de entorno para las claves
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    # request_token_url=None,
    # access_token_method='POST',
    client_kwargs={'scope': 'email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    claims_options={
        'iss': {
            'values': ['https://accounts.google.com', 'accounts.google.com']
        }
    }
)

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    resp = google.authorize_access_token()  # Maneja la respuesta OAuth
    if resp is None or 'access_token' not in resp:
        return 'Acceso denegado: razón=%s error=%s' % (
            request.args.get('error_reason'),
            request.args.get('error_description')
        )

    # Imprime el contenido del token para ver qué contiene
    print("Token response: ", resp)
    
    # Aquí es donde el error ocurre: intenta decodificar y validar el token
    user_info = google.parse_id_token(resp)

    # Puedes imprimir la información del usuario para ver si se obtiene correctamente
    print("User info: ", user_info)

    return jsonify(user_info)


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

#------------------------------------FRONT

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    data = request.get_json()
    user_input = data.get('text_input', '')
    
    # Iniciar el temporizador antes de llamar a call_predict_function
    start_time = time.time()
    respuesta_cf = call_predict_function(user_input)
    # Finalizar el temporizador después de que call_predict_function termine
    end_time = time.time()
    
    # Calcular el tiempo transcurrido
    elapsed_time = end_time - start_time
    print(f"Tiempo de ejecución de call_predict_function: {elapsed_time:.2f} segundos")
    
    return jsonify({
        'result': respuesta_cf['respuesta'],
        'categories': respuesta_cf.get('categories', []),
        'scores': respuesta_cf.get('scores', [])
    })

if __name__ == '__main__':
    app.run(debug=True)
