"""
DETImotica API: Flask REST API module
- 'Swagger UI'-based doc system compatible.
- ABAC-based access control model.

authors: Goncalo Perna, Eurico Dias
"""

import configparser
import random
import sys
import time
import json
import uuid

from functools import wraps
from urllib.parse import parse_qs
import requests

from flask import Flask, abort, flash, jsonify, redirect, Response, request, session
from flask_paranoid import Paranoid
from flasgger import Swagger, swag_from
from flask_wtf.csrf import CSRFProtect
from requests_oauthlib import OAuth1

from datadb import DataDB
from pgdb import PGDB

from api_grafana import grafana

# API global vars
APP_BASE_ENDPOINT = 'api'
VERSION = 'v1'
TITLE = 'DETImotica API'

# Flask global vars
app = Flask(__name__)
app.register_blueprint(grafana)
app.config['JSON_SORT_KEYS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True


csrf = CSRFProtect(app)
csrf.exempt(grafana)

paranoid = Paranoid(app)
paranoid.redirect_view = "/"

# OAuth global vars
OAUTH_SIGNATURE = 'HMAC-SHA1'
ck = None
cs = None

pgdb = PGDB()
influxdb = DataDB()

# Default responses
RESP_501 = "{'resp': 'NOT IMPLEMENTED'}"

app.config['SWAGGER'] = {
    "specs": [
        {
            "endpoint": "spec",
            "route": "/docs/spec",
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
        }
    ],
    "static_url_path": "/docs/static",
    "swagger_ui": True,
    "specs_route": "/docs/",
    'title': TITLE,
    'version': VERSION,
    'description': f"DETImotica REST backend API version {VERSION}",
    'uiversion': 3
}
swagger = Swagger(app)

# Make sure user is logged in to access user data
def auth_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user') or not session.get('id') or not session.get('token'):
            abort(401)
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def before_req_f():
    if request.endpoint == "login":
        if session.get('user'):
            flash(f"You are already logged in as {session.get('user')}.")
            return redirect(request.referrer)

@app.route("/", methods=['GET', 'HEAD'])
#@auth_only
def index():
    '''API Root endpoint'''

    return f"DETImotica API {VERSION}", 200

####################################################
#---------Identity UA OAuth 1.0a endpoints---------#
####################################################

@app.route("/login")
@swag_from('docs/session/login.yml')
def login():
    """
    OAuth Authentication/Authorization endpoint.
    It consists of setting up an OAuth1.0a session up to the 'authorize' phase, redirecting to the identity's auth_url.
    Final steps of OAuth1.0a are done on the auth_callback endpoint (and emulate authentication).
    """

    oauth_p1 = OAuth1(ck,
                      client_secret=cs,
                      signature_method=OAUTH_SIGNATURE,
                      nonce=str(random.getrandbits(64)),
                      timestamp=str(int(time.time()))
                     )

    resp = requests.post("http://identity.ua.pt/oauth/request_token", auth=oauth_p1)
    resp_json = parse_qs(resp.content.decode("utf-8"))

    global req_t, req_s

    req_t = resp_json['oauth_token'][0]
    req_s = resp_json['oauth_token_secret'][0]

    return redirect(f"http://identity.ua.pt/oauth/authorize?oauth_token={req_t}&oauth_token_secret={req_s}", 307)

@app.route("/auth_callback")
@swag_from('docs/session/auth_callback.yml')
def auth_callback():
    '''
    OAuth callback endpoint (after end-user authorization phase)
    '''

    ov = request.args.get('oauth_verifier')
    ot = request.args.get('oauth_token')

    oauth_access =  OAuth1(ck,
                           client_secret=cs,
                           resource_owner_key=req_t,
                           resource_owner_secret=req_s,
                           signature_method=OAUTH_SIGNATURE,
                           nonce=str(random.getrandbits(64)),
                           timestamp=str(int(time.time())),
                           verifier=ov
                          )

    resp = requests.get("http://identity.ua.pt/oauth/access_token", auth=oauth_access)
    resp_json = parse_qs(resp.content.decode("utf-8"))

    at = resp_json['oauth_token'][0]
    ats = resp_json['oauth_token_secret'][0]

    oauth_data = OAuth1(ck,
                        client_secret=cs,
                        resource_owner_key=at,  
                        resource_owner_secret=ats,
                        signature_method=OAUTH_SIGNATURE,
                        nonce=str(random.getrandbits(64)),
                        timestamp=str(int(time.time())),
                        )

    resp = requests.get("http://identity.ua.pt/oauth/get_data", auth=oauth_data, params={'scope' : 'uu'})

    attrs = resp.content.decode('utf-8').split("@ua.pt")
    uemail = attrs[0]
    uuid = attrs[1]

    session['id'] = uuid
    session['user'] = uemail
    session['token'] = at
    session['secret'] = ats

    # add user if it doesn't exist. If it does, 
    if (influxdb.has_user(uuid)):
        pass
    else:
        influxdb.add_user(uuid, uemail)
    
    return Response("LOGIN OK", status=200)

@app.route("/logout")
@swag_from('docs/session/logout.yml')
def logout():
    '''
    Logout endpoint
    '''

    session.clear()
    return Response("Logout successful.",status=200)


##################################################
#---------Room data exposure endpoints-----------#
##################################################

@app.route("/rooms", methods=['GET'])
@swag_from('docs/rooms/rooms.yml')
def rooms():
    '''
    todo
    '''
    dic = {}
    dic.update(ids = pgdb.getRooms())
    return Response(json.dumps(dic), status=200, mimetype='application/json')


@app.route("/room", methods=['POST'])
@swag_from('docs/rooms/room.yml')
def newroom():
    '''
    todo
    '''

    # Error cases
    # 1 - at least one of the sensors is already linked to a room
    # 2 - at least one of the sensors doesnt exist

    # In a valid case we send the id of the new room

    id = uuid.uuid4()
    details = request.json  # {name: "", description: "", sensors: ["","",...] }

    error = {"non_existent": [], "non_free": []}
    for s in details["sensors"]:
        try:
            if (not pgdb.isSensorFree(s)):
                error["non_free"].append(s)
        except:
            error["non_existent"].append(s)

    if(error["non_existent"] != [] or error["non_free"] != []):
        return Response(json.dumps(error), status=400, mimetype='application/json')

    pgdb.createRoom(id, {"name":details["name"], "description":details["description"]}, details["sensors"])
    return Response(json.dumps({"id": id}), status=200, mimetype='application/json')


@app.route("/room/<roomid>", methods=['GET', 'POST', 'DELETE'])
@swag_from('docs/rooms/room_roomid_get.yml', methods=['GET'])
@swag_from('docs/rooms/room_roomid_post.yml', methods=['POST'])
@swag_from('docs/rooms/room_roomid_delete.yml', methods=['DELETE'])
def room_id(roomid):
    '''
    todo
    '''
    if request.method == 'GET':
        #TODO podemos depois aquilo restringir com as politicas as info das salas
        return Response(json.dumps(pgdb.getRoom(roomid)), status=200, mimetype='application/json')

    if request.method == 'POST':
        new_details = request.json #{name: "", description: ""}
        pgdb.updateRoom(roomid, new_details)
        return Response(json.dumps({"id":roomid}), status=200, mimetype='application/json')

    #TODO remover salas
    return jsonify(RESP_501), 501


@app.route("/room/<roomid>/sensors", methods=['GET', 'POST'])
@swag_from('docs/rooms/room_sensors_get.yml', methods=['GET'])
@swag_from('docs/rooms/room_sensors_post.yml', methods=['POST'])
def sensors_room_id(roomid):
    '''
    todo
    '''

    if request.method == 'GET':
        dic = {}
        dic.update(ids = pgdb.getSensorsFromRoom(roomid))
        return Response(json.dumps(dic), status=200, mimetype='application/json')

    if request.method == 'POST':
        details = request.json  # {"sensors": {"add" : [], "remove" : []}}
        pgdb.updateSensorsFromRoom(roomid, details)
        return Response(json.dumps({"id": roomid}), status=200, mimetype='application/json')


##################################################
#---------User data exposure endpoints-----------#
##################################################

@app.route("/users", methods=['GET'])
@swag_from('docs/users/users.yml')
def users():
    '''
    Get all users (pelo menos uma chave) from the database --> getUsers(bd)
    '''
    return jsonify(RESP_501), 501

@app.route("/user/<internalid>", methods=['POST'])
@swag_from('docs/users/user.yml')
def user_policy(internalid):
    '''
    Change access policy on the database from the JSON received.
    '''
    return jsonify(RESP_501), 501


##################################################
#---------Sensor data exposure endpoints---------#
################################################## #"Authorization": "Basic ZGV0aW1vdGljOnNRV3N4VzVkVFE4N0pQTGY=", "Host" : "iot.av.it.pt", "Accept": "*/*"

@app.route("/sensors", methods=['GET'])
@swag_from('docs/sensors/sensors.yml')
def sensors():
    '''
    Get the sensors_id for a user from the database --> getAllowedSensors(bd, user_email)
    '''
    return jsonify(RESP_501), 501


@app.route("/types", methods=['GET'])
@swag_from('docs/sensors/types.yml')
def types():
    '''
    Get all types of sensors for a user from the database --> getAllowedTypes(bd, user_email)
    '''
    return jsonify(RESP_501), 501


@app.route("/sensor", methods=['GET', 'POST'])
@swag_from('docs/sensors/sensor_get.yml', methods=['GET'])
@swag_from('docs/sensors/sensor_post.yml', methods=['POST'])
@csrf.exempt
def new_sensor():
    '''
    todo
    '''
    id = uuid.uuid4()
    details = request.json
    #TODO Veficar se a pessoa é um admin

    #url = "http://iot.av.it.pt/device/standalone"
    #data_influx = {"tenant-id": "detimotic", "device-id" : id, "password": "<password>"}
    #response = requests.post(url, headers={"Content-Type": "application/json"}, auth=("detimotic", "<pass>"), data=json.dumps(data_influx))
    #if response.status_code == 409:
    #    return Response(json.dumps({"error_description": "O Id ja existe"}), status=409, mimetype='application/json')


    pgdb.createSensor(id, details)
    return Response(json.dumps({"id": id}), status=200, mimetype='application/json')


@app.route("/sensor/<sensorid>", methods=['GET', 'POST', 'DELETE'])
@swag_from('docs/sensors/sensor_sensorid_get.yml', methods=['GET'])
@swag_from('docs/sensors/sensor_sensorid_post.yml', methods=['POST'])
@swag_from('docs/sensors/sensor_sensorid_delete.yml', methods=['DELETE'])
def sensor_description(sensorid):
    '''
    todo
    '''
    if request.method == 'GET':
        return Response(json.dumps(pgdb.getSensor(sensorid)), status=200, mimetype='application/json')

    if request.method == 'POST':
        details = request.json #{"description": "", "data" : { "type" : "", "unit_symbol" : ""}, room_id: ""}
        pgdb.updateSensor(sensorid, details)
        return Response(json.dumps({"id":sensorid}), status=200, mimetype='application/json')

    #TODO falta remover sensores
    return jsonify(RESP_501), 501


@app.route("/sensor/<sensorid>/measure/<option>", methods=['GET'])
@swag_from('docs/sensors/sensor_measure.yml')
def sensor_measure(sensorid, option):
    '''
    Verify if the sensor supports a "measure" from database getTypeFromSensor()
    '''
    if option == "instant":
        return Response(influxdb.query_last(sensorid), status=200, mimetype='application/json')
    if option == "interval":
        extremo_min = request.args.get('start')
        extremo_max = request.args.get('end')
        return Response(influxdb.query_interval(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')
    if option == "mean":
        extremo_min = request.args.get('start')
        extremo_max = request.args.get('end')
        return Response(influxdb.query_avg(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')
    return Response(jsonify(RESP_501), status=501, mimetype='application/json')

@app.route("/sensor/<sensorid>/event/<option>", methods=['GET'])
@swag_from('docs/sensors/sensor_event.yml')
def sensor_event(sensorid, option):
    '''
    Verify if the sensor supports "Events" from database
    '''
    # get data from influx
    return jsonify(RESP_501), 501

####################################################
####################################################

# run self-signed and self-managed PKI instead of self-signed certificate
# (or a real cert?) 
if __name__ == "__main__":
    try:
        config = configparser.ConfigParser()

        config.read(".appconfig")
        ck = config['info']['consumer_key']
        cs = config['info']['consumer_secret']

        app.config['SECRET_KEY'] = config['info']['app_key']
        app.config['APPLICATION_ROOT'] = f"/{APP_BASE_ENDPOINT}/{VERSION}"
        
        csrf.init_app(app)
        paranoid.init_app(app)
        app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        sys.exit("[ABORT] " + str(ex))
    finally:
        print("Goodbye!")
        sys.exit(0)
