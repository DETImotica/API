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
import xmltodict

from collections import OrderedDict
from functools import wraps
from urllib.parse import parse_qs
import requests
import datetime

from flask import Flask, abort, flash, g, jsonify, redirect, Response, request, session, url_for
from flask_caching import Cache
from flask_paranoid import Paranoid
from flasgger import Swagger, swag_from
from flask_wtf.csrf import CSRFProtect
from hashlib import sha3_256
from requests_oauthlib import OAuth1

from access import PDP, PolicyManager
from datadb import DataDB
from pgdb import PGDB

from api_grafana import grafana

class ArgumentException(ValueError):
    pass

# API global vars
APP_BASE_ENDPOINT = 'api'
VERSION = 'v1'
TITLE = 'DETImotica API'
_SUPPORTED_SCOPES = ['uu', 'name',
                     'student_info', 'student_schedule', 'student_courses',
                     'teacher_schedule', 'teacher_courses']

# Flask global vars
app = Flask(__name__)
app.register_blueprint(grafana)
app.config['JSON_SORT_KEYS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['CACHE_TYPE'] = "filesystem"
app.config['CACHE_DIR'] = ".app_attr_cache/"
app.config['CACHE_DEFAULT_TIMEOUT'] = 3600*24
app.config['CACHE_OPTIONS'] = {'mode': 600}
app.config['SWAGGER'] = {
    'ui_params': {
        'supportedSubmitMethods': ['get']
    },
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
    "termsOfService": '',
    "basePath": f"/{APP_BASE_ENDPOINT}/{VERSION}/",
    "specs_route": "/docs/",
    'title': TITLE,
    'version': VERSION,
    'description': f"DETImotica REST backend API version {VERSION}",
    'uiversion': 3
}

csrf = CSRFProtect(app)
csrf.exempt(grafana)

paranoid = Paranoid(app)
paranoid.redirect_view = "/"

cache = Cache(app)
session_cache = Cache(app, config={'CACHE_DIR': ".app_session_cache/",
                                   'CACHE_DEFAULT_TIMEOUT': 3600*24*30
                                  })

swagger = Swagger(app)

_pdp = PDP()
_access_mgr = PolicyManager()

# OAuth global vars
OAUTH_SIGNATURE = 'HMAC-SHA1'
config = configparser.ConfigParser()

config.read(".appconfig")
ck = config['info']['consumer_key']
cs = config['info']['consumer_secret']

pgdb = PGDB()
influxdb = DataDB()

# Default responses
RESP_501 = "{'resp': 'NOT IMPLEMENTED'}"

# attribute dataset methods
def _simplify_attr_dict(xmldict):
    res = {}

    for key in xmldict:
        if key[0] != '@':
            if isinstance(xmldict[key], OrderedDict):
                res.update(_simplify_attr_dict(xmldict[key]))
            elif isinstance(xmldict[key], list):
                res[key] = [_simplify_attr_dict(item) if isinstance(item, OrderedDict) else item for item in xmldict[key]]
            else:
                res[key] = xmldict[key]
    return res

@cache.memoize(hash_method=sha3_256)
def _get_attr(scope, at, ats):
    if not scope or scope not in _SUPPORTED_SCOPES:
        raise ArgumentException("Invalid scope")
    if not at:
        raise ArgumentException("No value for AT")
    if not ats:
        raise ArgumentException("No value for AT secret")

    oauth_data = OAuth1(ck,
                        client_secret=cs,
                        resource_owner_key=at,
                        resource_owner_secret=ats,
                        signature_method=OAUTH_SIGNATURE,
                        nonce=str(random.getrandbits(64)),
                        timestamp=str(int(time.time()))
                        )

    resp = requests.get("https://identity.ua.pt/oauth/get_data", auth=oauth_data, params={'scope' : scope})

    if resp.status_code != 200:
        return None

    return _simplify_attr_dict(xmltodict.parse(resp.content.decode()))

# validate the token
def _validate_token(uuid, email):
    at = session_cache.get(uuid)
    ats = session_cache.get(at)

    if not at or not ats:
        return False

    uu = _get_attr('uu', at, ats)

    return uu is not None and uuid == uu['iupi'] and email == uu['email']

# return a dict with all user attributes.
def _get_user_attrs(s):
    at = session_cache.get(s.get('uuid'))
    ats = session_cache.get(at)

    return {**_get_attr('uu', at, ats),
                    **_get_attr('name', at, ats),
                    **_get_attr('student_info', at, ats),
                    **_get_attr('student_courses', at, ats),
                    **_get_attr('teacher_courses', at, ats)
           }

# Admin only endpoint decorator
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        id = session.get('uuid')
        if not id:
            return Response(json.dumps({"error_description": f"You are not logged in."}), status=401, mimetype='application/json')
        if not pgdb.isAdmin(id):
            return Response(json.dumps({"error_description": f"Access denied: admin only endpoint."}), status=401, mimetype='application/json')
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def before_req_f():
    if request.path == "/login":
        if session.get('user') and session.get('uuid'):
            if _validate_token(session.get('uuid'), session.get('user')):
                if request.referer:
                    return redirect(url_for(request.referer))
                else:
                    return redirect(url_for('.index'))
    elif request.path != "/spec" and "grafana" not in request.path and "auth_callback" not in request.path:
        if not session.get('user') or not session.get('uuid') or not _validate_token(session.get('uuid'), session.get('user')):
            return redirect(url_for('.login'), code=307)

@app.route("/", methods=['GET', 'HEAD'])
def index():
    '''API Root endpoint'''

    return f"DETImotica API {VERSION}", 200









####################################################
#---------Identity UA OAuth 1.0a endpoints---------#
####################################################

@app.route("/login", methods=['GET'])
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

    resp = requests.post("https://identity.ua.pt/oauth/request_token", auth=oauth_p1)

    if resp.status_code != 200:
        return Response(json.dumps({
                         "error_description": f"Error on OAuth Session.<br>Server returned: <b>{resp.content.decode()}</b><br>Please contact an administrator."
                        }),
                        status=resp.status_code,
                        content_type="application/json"
                        )

    resp_json = parse_qs(resp.content.decode("utf-8"))

    session['_rt'] = (resp_json['oauth_token'][0], resp_json['oauth_token_secret'][0])

    return redirect(f"https://identity.ua.pt/oauth/authorize?oauth_token={session['_rt'][0]}&oauth_token_secret={session['_rt'][0]}", 302)

@app.route("/auth_callback", methods=['GET'])
@swag_from('docs/session/auth_callback.yml')
def auth_callback():
    '''
    OAuth callback endpoint (after end-user authorization phase)
    '''

    ov = request.args.get('oauth_verifier')
    ot = request.args.get('oauth_token')

    if not ov or not ot:
        return Response(json.dumps({"error_descrption": "OAuth error.<br>Server returned: <b>Invalid request.</b>"}),
                        status=400,
                        mimetype="application/json")

    if request.args.get('consent'):
        return Response(json.dumps({"error_description": "OAuth authorization aborted.<br>Server returned: <b>No consent from end-user.</b>"}),
                        status=401,
                        mimetype="application/json")

    rt = session.pop('_rt')
    oauth_access =  OAuth1(ck,
                           client_secret=cs,
                           resource_owner_key=ot,
                           resource_owner_secret=rt[1],
                           signature_method=OAUTH_SIGNATURE,
                           nonce=str(random.getrandbits(64)),
                           timestamp=str(int(time.time())),
                           verifier=ov
                          )

    resp = requests.get("https://identity.ua.pt/oauth/access_token", auth=oauth_access)
    resp_json = parse_qs(resp.content.decode("utf-8"))

    if not resp_json:
        return Response(json.dumps({"error_description": f"OAuth Error.<br>Server returned: <b>{resp.content.decode()}</b>"}),
                        status=resp.status_code,
                        mimetype="application/json")

    try:
        at = resp_json['oauth_token'][0]
        ats = resp_json['oauth_token_secret'][0]
    except KeyError:
        return Response(json.dumps({'error_description': """OAuth Error. Please contact an administrator.<br>
                        Server returned: <b>OAuth Server error</b>"""}),
                        status=500, 
                        mimetype="application/json")

    # cache attributes
    uu = _get_attr('uu', at, ats)
    name = _get_attr('name', at, ats)
    _get_attr('student_info', at, ats)
    _get_attr('student_courses', at, ats)
    _get_attr('student_schedule', at, ats)
    _get_attr('teacher_schedule', at, ats)
    _get_attr('teacher_courses', at, ats)

    session['uuid'] = uu['iupi']
    session['user'] = uu['email']
    session['fname'] = name['name']
    session['lname'] = name['surname']

    session_cache.set(uu['iupi'], at)
    session_cache.set(at, ats)
    
    session['ts'] = int(time.time())

    # add user if it doesn't exist.
    if (not pgdb.hasUser(uu['iupi'])):
        pgdb.addUser(uu['iupi'], uu['email'], False)

    return Response(json.dumps({**uu, **name}), status=200, mimetype='application/json')

@app.route("/logout", methods=['GET'])
@swag_from('docs/session/logout.yml')
def logout():
    '''
    Logout endpoint
    '''
    if not session.get('user') or not session.get('uuid') or not session.get('x'):
        Response({"error_description": "Bad request. Server returned: <b>You are not logged in.<b>"},
                    status=400,
                    content_type="application/json")
    
    #clear cache
    for s in _SUPPORTED_SCOPES:
        cache.delete_memoized(_get_attr, s, session.get('x'), session.get('y'))

    at = session_cache.get(session.get('uuid'))
    session_cache.delete(at)

    session_cache.delete(session.get('uuid'))

    #clear session
    session.clear()
    return Response("Logout successful.",status=200)








##################################################
#---------Room data exposure endpoints-----------#
##################################################

@app.route("/rooms", methods=['GET'])
@swag_from('docs/rooms/rooms.yml')
def rooms():
    '''
    Get all rooms id that exist on our API
    '''

    dic = {}
    
    user_attrs = _get_user_attrs(session)
                 
    rooms = []
    for r in pgdb.getRooms():
        #Verificar quais salas podem ser acedidas pelo utilizador
        if _pdp.get_http_req_access(request, user_attrs, opt_resource={'room': r}):
            rooms.append(r)
    
    dic.update(ids = rooms)

    return Response(json.dumps(dic), status=200, mimetype='application/json')


@admin_only
@app.route("/room", methods=['POST'])
@swag_from('docs/rooms/room.yml')
def newroom():
    '''
    Create a new room
    '''

    id = uuid.uuid4()
    details = request.json  # {name: "", description: "", sensors: ["","",...] }

    #Validar as meta-informações acerca das salas
    if "name" not in details:
        return Response(json.dumps({"error_description" : "Room details incomplete"}), status=400, mimetype='application/json')

    if len(details["name"])>50 or ("description" in details and len(details["description"])>50) :
        return Response(json.dumps({"error_description" : "One of the detail fields has more than 50 characters"}), status=400, mimetype='application/json')

    #Dois arrays para guardar os sensores que não existem e o aqueles que já estão atribuidos a uma sala
    error = {"non_existent": [], "non_free": [], "error_description": "Some of the sensors does not exist or are not free"}

    if sensors in details:
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


@app.route("/room/<roomid>", methods=['GET'])
@swag_from('docs/rooms/room_roomid_get.yml', methods=['GET'])

def room_id(roomid):
    '''
    [GET] Get meta-info from a room <roomid>
    '''

    if not pgdb.roomExists(roomid):
        return Response(json.dumps({"error_description": "The roomid does not exist"}), status=404, mimetype='application/json')

    if request.method == 'GET': 
        user_attrs = _get_user_attrs(session)
        if not _pdp.get_http_req_access(request, user_attrs, opt_resource={'room': roomid}):
            return Response(json.dumps({"error_description": f"Access denied to room {roomid}. Talk to an administrator"}), status=401, mimetype='application/json')

        return Response(json.dumps(pgdb.getRoom(roomid)), status=200, mimetype='application/json')

    return jsonify(RESP_501), 501


@admin_only
@app.route("/room/<roomid>", methods=['POST', 'DELETE'])
@swag_from('docs/rooms/room_roomid_post.yml', methods=['POST'])
@swag_from('docs/rooms/room_roomid_delete.yml', methods=['DELETE'])
def room_id_admin(roomid):
    '''
    [POST] Change meta-info from a room <roomid>
    [DELETE] Delete a room <roomid> from the system
    '''

    if not pgdb.roomExists(roomid):
        return Response(json.dumps({"error_description": "The roomid does not exist"}), status=404, mimetype='application/json')

    if request.method == 'POST':
        new_details = request.json #{name: "", description: ""}"
        if ("name" in new_details and (new_details["name"])>50):
            return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}), status=400, mimetype='application/json')
        if ("description" in new_details and (new_details["description"]>50)):
            return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}), status=400, mimetype='application/json')

        pgdb.updateRoom(roomid, new_details)
        return Response(json.dumps({"id":roomid}), status=200, mimetype='application/json')

    if request.method == 'DELETE':
        pgdb.deleteRoom(roomid, new_details)
        return Response(json.dumps({"id": roomid}), status=200, mimetype='application/json')

    return jsonify(RESP_501), 501


@app.route("/room/<roomid>/sensors", methods=['GET'])
@swag_from('docs/rooms/room_sensors_get.yml', methods=['GET'])
def sensors_room_id(roomid):
    '''
    [GET] Get all sensors id from a room <room-id>
    '''
    user_attrs = _get_user_attrs(session)
    if not _pdp.get_http_req_access(request, user_attrs, opt_resource={'room': roomid}):
        return Response(json.dumps({"error description": f"Access denied to room {roomid}. Talk to an administrator."}), status=401, mimetype='application/json')
    
    if request.method == 'GET': 
        if pgdb.roomExists(roomid):
            dic = {}
            sensors = [s for s in pgdb.getSensorsFromRoom(roomid) if _pdp.get_http_req_access(request, user_attrs, opt_resource={'sensor': s})]
            dic.update(ids = sensors)
            return Response(json.dumps(dic), status=200, mimetype='application/json')
        return Response(json.dumps({"error_description" : "The roomid does not exist"}), status=404, mimetype='application/json')


@admin_only    
@app.route("/room/<roomid>/sensors", methods=['POST'])
@swag_from('docs/rooms/room_sensors_post.yml', methods=['POST'])
def sensors_room_id_admin(roomid):
    '''
    [POST] Change the sensors that exist in a room <room-id>
    '''

    if request.method == 'POST':
        if pgdb.roomExists(roomid):

            details = request.json  # {"sensors": {"add" : [], "remove" : []}}
            error = {"add_sensors" : {"non_free": [], "non_existent": []}, "rm_sensors": {"diferent_room" : [], "non_existent" : []}, "error_description" : "One of the sensors sent is invalid"}

            for s in details["sensors"]["add"]:
                try:
                    if (not pgdb.isSensorFree(s)):
                        error["add_sensors"]["non_free"].append(s)
                except:
                    error["add_sensors"]["non_existent"].append(s)

            for s in details["sensores"]["remove"]:
                try:
                    if (not pgdb.isSensorRoom(s, roomid)):
                        error["rm_sensors"]["diferent_room"].append(s)
                except:
                    error["rm_sensors"]["non_existent"].append(s)

            if len(error["add_sensors"]["non_free"]) > 0 or len(error["add_sensors"]["non_existent"]) > 0 or len(error["rm_sensors"]["diferent_room"]) > 0 or len(error["rm_sensors"]["non_existent"]) > 0 :
                return Response(json.dumps(error), status=400, mimetype='application/json')

            pgdb.updateSensorsFromRoom(roomid, details)
            return Response(json.dumps({"id": roomid}), status=200, mimetype='application/json')


@app.route("/room/<roomid>/sensors/full", methods=['GET'])
##@swag_from('docs/rooms/room_sensors_get.yml', methods=['GET'])
def sensors_room_id_fullversion(roomid):
    '''
    [GET] Get full meta_info from all the sensors in a room <roomid>
    '''

    if pgdb.roomExists(roomid):
        user_attrs = _get_user_attrs(session)
        if not _pdp.get_http_req_access(request, user_attrs, opt_resource={'room': roomid}):
            return Response(json.dumps({"error description": f"Access denied to room {roomid}. Talk to an administrator."}), status=401, mimetype='application/json')

        ##{"id": "", "description": "", "data" : { "type" : "", "unit_symbol" : ""}}
        sensors = [s for s in pgdb.getSensorsFullDescriptionFromRoom(roomid) if _pdp.get_http_req_access(request, user_attrs, opt_resource={'sensor': s["id"]})]
        return Response(json.dumps(sensors), status=200, mimetype='application/json')
    return Response(json.dumps({"error_description": "The roomid does not exist"}), status=404, mimetype='application/json')









##################################################
#---------User data exposure endpoints-----------#
##################################################

@admin_only
@app.route("/users", methods=['GET'])
@swag_from('docs/users/users.yml')
def users():
    '''
    Get all users (pelo menos uma chave) from the database --> getUsers(bd)
    '''
    return jsonify(RESP_501), 501

@app.route("/identity", methods=['GET'])
def identity():
    '''
    Get user session information
    '''
    at = session_cache.get(session.get('uuid'))
    ats = session_cache.get(at)

    return Response(json.dumps({**_get_attr('uu', at, ats),
            **_get_attr('name', at, ats),
            **_get_attr('student_info', at, ats),
            **_get_attr('student_courses', at, ats),
            **_get_attr('teacher_courses', at, ats)
    }), status=200, content_type='application/json')

@admin_only
@app.route("/user/<internalid>", methods=['POST'])
@swag_from('docs/users/user.yml')
def user_policy(internalid):
    '''
    Change access policy on the database from the JSON received.
    '''
    return jsonify(RESP_501), 501

@admin_only
@app.route("/add_admin", methods=['POST'])
def add_admin():
    if not request.json:
        return Response(json.dumps({"error_description": "Empty JSON or empty body."}), status=400,mimetype='application/json')

    if 'user' in request.json:
        pgdb.updateUserAdminStatus(request.json['user'])
    else:
        return Response(json.dumps({"error_description": "No 'user' specified for the action."}), status=400,mimetype='application/json')
    return Response(json.dumps({"status": "OK"}), status=200,mimetype='application/json')









##################################################
#---------Sensor data exposure endpoints---------#
##################################################

@app.route("/sensors", methods=['GET'])
@swag_from('docs/sensors/sensors.yml')
def sensors():
    '''
    Get the sensors_id for a user from the database
    '''

    user_attrs = _get_user_attrs(session)

    s_list = pgdb.getAllSensors()
    d = {"ids" : [tuplo[0] for tuplo in s_list if _pdp.get_http_req_access(request, user_attrs, {'sensor' : tuplo[0]})]} #{"ids" : [uuid1, uuid2]}
    return Response(json.dumps(d), status=200, mimetype='application/json')

@app.route("/types", methods=['GET'])
@swag_from('docs/sensors/types.yml')
def types():
    '''
    Get all types of sensors for a user from the database
    '''

    user_attrs = _get_user_attrs(session)

    d = {"types" : [tuplo[0] for tuplo in pgdb.getAllSensorTypes() if _pdp.get_http_req_access(request, user_attrs, {'sensor_type' : tuplo[0]})]} # {"types" : ["Temperatura", "Humidade", "Som"]}
    return Response(json.dumps(d), status=200, mimetype='application/json')


@admin_only
@app.route("/sensor", methods=['POST'])
@swag_from('docs/sensors/sensor.yml')
@csrf.exempt
def new_sensor():
    '''
    Create a new Sensor, and register it on Hono
    '''

    id = uuid.uuid4()
    details = request.json #{"description" : "", data : { type : "", unit_symbol : ""}, "room_id" : ""}

     if "data" not in details:
        return Response(json.dumps({"error_description": "Sensor Details Incomplete"}), status=400, mimetype='application/json')

    if "description" in details and len(details["description"])>50:
        return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}), status=400,mimetype='application/json')

    if "type" not in details["data"] or "unit_symbol" not in details["data"]:
        return Response(json.dumps({"error_description": "Sensor Details Incomplete"}), status=400, mimetype='application/json')

    if len(details["data"]["type"])>50:
        return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}), status=400,mimetype='application/json')

    if len(details["data"]["unit_symbol"])>3:
        return Response(json.dumps({"error_description": "The Unit Symbol has more than 3 characters"}), status=400,mimetype='application/json')

    if not pgdb.datatypeExists(details["data"]["type"]):
        return Response(json.dumps({"error_description": "The data type does not exist"}), status=404, mimetype='application/json')
    
    user_attrs = _get_user_attrs(session)
    if not _pdp.get_http_req_access(request, user_attrs, {'sensor' : id}):
        return Response(json.dumps({"error description": f"Access denied: you can't add a new sensor."}), status=401, mimetype='application/json')

    if "room_id" in details:
        if not pgdb.roomExists(details["room_id"]):
            return Response(json.dumps({"error_description": "The roomid does not exist"}), status=404, mimetype='application/json')
    
    if not _pdp.get_http_req_access(request, user_attrs, {'room' : details['room_id']}):
        return Response(json.dumps({"error description": f"Access denied: you can't add a new sensor to room {details['room_id']}."}), status=401, mimetype='application/json')
        
    # url = "http://iot.av.it.pt/device/standalone"
    # data_influx = {"tenant-id": "detimotic", "device-id" : id, "password": "<password>"}
    # response = requests.post(url, headers={"Content-Type": "application/json"}, auth=("detimotic", "<pass>"), data=json.dumps(data_influx))
    # if response.status_code == 409:
    #    return Response(json.dumps({"error_description": "O Id ja existe"}), status=409, mimetype='application/json')

    pgdb.createSensor(id, details)
    return Response(json.dumps({"id": id}), status=200, mimetype='application/json')


@app.route("/sensor/<sensorid>", methods=['GET'])
@swag_from('docs/sensors/sensor_sensorid_get.yml', methods=['GET'])
def sensor_description(sensorid):
    '''
    Get meta-info from a sensor <sensorid>
    '''
    
    try:
        pgdb.isSensorFree(sensorid)
        if not _pdp.get_http_req_access(request, _get_user_attrs(session), {'sensor' : sensorid}):
            return Response(json.dumps({"error description": f"Access denied to sensor {sensorid}. Talk to an administrator."}), status=401, mimetype='application/json')
        return Response(json.dumps(pgdb.getSensor(sensorid)), status=200, mimetype='application/json')
    except:
        return Response(json.dumps({"error_description" : "The sensorid does not exist"}), status=404, mimetype='application/json')


@admin_only
@app.route("/sensor/<sensorid>", methods=['POST', 'DELETE'])
@swag_from('docs/sensors/sensor_sensorid_post.yml', methods=['POST'])
@swag_from('docs/sensors/sensor_sensorid_delete.yml', methods=['DELETE'])
def sensor_description_admin(sensorid):
    '''
    [POST] Change the meta-info from a sensor <sensorid>
    [DELETE] Delete a sensor <sensorid> from the system
    '''

    if request.method == 'POST':
        details = request.json #{"description": "", "data" : { "type" : "", "unit_symbol" : ""}, room_id: ""}

        try:
            pgdb.isSensorFree(sensorid)
        except:
            return Response(json.dumps({"error_description" : "The sensorid does not exist"}), status=404, mimetype='application/json')

        if len(details["description"]) > 50:
            return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}),status=400, mimetype='application/json')

        if "data" in details:
            if "type" in details["data"]:
                    if not pgdb.datatypeExists(details["data"]["type"]):
                        return Response(json.dumps({"error_description": "The data type does not exist"}), status=404, mimetype='application/json')
                    if len(details["data"]["type"])>50:
                        return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}),status=400, mimetype='application/json')
            if "unit_symbol" in details["data"]:
                    if len(details["data"]["unit_symbol"])>3:
                        return Response(json.dumps({"error_description": "The Unit Symbol has more than 3 characters"}),status=400, mimetype='application/json')


        if "data" in details and "type" in details["data"] and not pgdb.datatypeExists(details["data"]["type"]):
            return Response(json.dumps({"error_description": "The data type does not exist"}), status=404, mimetype='application/json')


        if "room_id" in details:
            if not pgdb.roomExists(details["room_id"]):
                return Response(json.dumps({"error_description": "The roomid does not exist"}), status=404, mimetype='application/json')

        pgdb.updateSensor(sensorid, details)
        return Response(json.dumps({"id":sensorid}), status=200, mimetype='application/json')

    if request.method == 'DELETE':
        try:
            pgdb.isSensorFree(sensorid)
            pgdb.deleteSensor(sensorid)
            return Response(json.dumps({"id": sensorid}), status=200, mimetype='application/json')
        except:
            return Response(json.dumps({"error_description": "The sensorid does not exist"}), status=404, mimetype='application/json')

    return jsonify(RESP_501), 501


@app.route("/sensor/<sensorid>/measure/<option>", methods=['GET'])
@swag_from('docs/sensors/sensor_measure.yml')
def sensor_measure(sensorid, option):
    '''
    Get the measures from a sensor <sensorid>
        - <option> instant  - get the last value
        - <option> interval - get the all the value in an interval
        - <option> median   - get the median of the values in an interval
    '''

    if not _pdp.get_http_req_access(request, _get_user_attrs(session), {'sensor' : sensorid}):
            return Response(json.dumps({"error description": f"Access denied to sensor {sensorid}. Talk to an administrator."}), status=401, mimetype='application/json')

    try:
        pgdb.isSensorFree(sensorid)
    except:
        return Response(json.dumps({"error_description": "The sensorid does not exist"}), status=404,mimetype='application/json')

    #TODO Verificar se o intervalo é válido para o influx

    if option == "instant":
        return Response(influxdb.query_last(sensorid), status=200, mimetype='application/json')
    if option == "interval":
        extremo_min = request.args.get('start')
        if extremo_min == None:
            return Response(json.dumps({"error_description": "The start parameter was not specified"}), status=400, mimetype='application/json')

        extremo_max = request.args.get('end')
        if extremo_max == None:
            extremo_max = datetime.datetime.utcnow().isoformat("T")+"Z"
        return Response(influxdb.query_interval(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')


    if option == "mean":
        extremo_min = request.args.get('start')
        if extremo_min == None:
            return Response(json.dumps({"error_description": "The start parameter was not specified"}), status=400,
                            mimetype='application/json')

        extremo_max = request.args.get('end')
        if extremo_max == None:
            extremo_max = datetime.datetime.utcnow().isoformat("T") + "Z"
        return Response(influxdb.query_avg(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')
    return Response(json.dumps({"error_description" : "Option does not exist"}), status=404, mimetype='application/json')

@app.route("/sensor/<sensorid>/event/<option>", methods=['GET'])
@swag_from('docs/sensors/sensor_event.yml')
def sensor_event(sensorid, option):
    '''
    Verify if the sensor supports "Events" from database
    '''
    # get data from influx
    return jsonify(RESP_501), 501










####################################################
##              Type Data Methods                 ##
####################################################

@admin_only
@app.route("/type", methods=['POST'])
##@swag_from('docs/sensors/types.yml')
def new_type():
    details = request.json  # {"name" : "" ,"description" : ""}

    if "description" not in details or "name" not in details:
        return Response(json.dumps({"error_description": "New Data Type Details Incomplete"}), status=400, mimetype='application/json')

    if len(details["description"]) > 50 or len(details["name"]) > 50:
        return Response(json.dumps({"error_description": "One of the detail fields has more than 50 characters"}), status=400, mimetype='application/json')

    if pgdb.datatypeExists(details["name"]) :
        return Response(json.dumps({"error_description": "This data type already exists"}), status=400, mimetype='application/json')

    pgdb.createSensorType(details)
    return Response(json.dumps({"name": details["name"]}), status=200, mimetype='application/json')

@app.route("/type/<typename>", methods=['GET'])
##@swag_from('docs/sensors/types.yml')
def typesFromName(typename):
    user_attrs = _get_user_attrs(session)
    
    if not pddb.datatypeExists(typename):
        return Response(json.dumps({"error_description": "The name type sent does not exist"}), status=400, mimetype='application/json')

    if not _pdp.get_http_req_access(request, user_attrs, {'sensor_type' : typename}):
        Response(json.dumps({"error description": f"Access denied to type of sensor {typename}. Talk to an administrator."}), status=401, mimetype='application/json')

    return Response(json.dumps(pgdb.getSensorType(typename)), status=200, mimetype='application/json')

    

@admin_only
@app.route("/type/<typename>", methods=['POST', 'DELETE'])
##@swag_from('docs/sensors/types.yml')
def typesFromName_admin(typename):

    if request.method == 'POST':

        details = request.json #{"description" : ""}

        if ("description" in details) and len(details["description"] > 50):
            return Response(json.dumps({"error_description" : "One of the detail fields has more than 50 characters"}), status=400, mimetype='application/json')

        pgdb.updateSensorType(typename, details)
        return Response(json.dumps({"name" : typename}), status=200, mimetype='application/json')

    if request.method == 'DELETE':
        if pgdb.getSensorsFromType(typename) != []:
            return Response(json.dumps({"error_description" : "Cannot remove a sensor type that has at least one sensor"}, status=400, mimetype='application/json'))

        pgdb.deleteSensorType(typename)
        return Response(json.dumps({"name" : typename}, status=200, mimetype='application/json'))








####################################################
##            Access Control Database             ##
####################################################

@admin_only
@app.route("/accessPolicy", methods=['POST'])
##@swag_from('docs/sensors/types.yml')
def newAccessPolicy():
    response = _access_mgr.create_policy(request)
        if not response[0]:
            return Response(json.dumps({"error_description" : response[1]}, status=400, mimetype='application/json'))
        return Response(json.dumps({"response" : "OK"}, status=200, mimetype='application/json')

@admin_only
@app.route("/accessPolicy/<policy-id>", methods=['POST', 'DELETE'])
##@swag_from('docs/sensors/types.yml')
def accessPolicy(policy_id):

    if request.method == 'POST' :
        response = _access_mgr.update_policy(policy_id)
        return Response(json.dumps({"response" : "OK"}, status=200, mimetype='application/json')
        
    if request.method == 'DELETE' :
        response = _access_mgr.delete_policy(policy_id)
        return Response(json.dumps({"response" : "OK"}, status=200, mimetype='application/json')

@admin_only
@app.route("/accessPolicies", methods=['GET'])
##@swag_from('docs/sensors/types.yml')
def getAllAccessPolicies():
    return Response(json.dumps(_access_mgr.get_policies()), status=200, mimetype='application/json')




# run self-signed and self-managed PKI instead of self-signed certificate
# (or a real cert?)
if __name__ == "__main__":
    try:
        config.read(".appconfig")

        app.config['SECRET_KEY'] = config['info']['app_key']
        app.config['APPLICATION_ROOT'] = f"/{APP_BASE_ENDPOINT}/{VERSION}"

        csrf.init_app(app)
        paranoid.init_app(app)
        cache.init_app(app)
        session_cache.init_app(app)

        app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        sys.exit("[ABORT] " + str(ex))
    finally:
        print("Goodbye!")
        sys.exit(0)
