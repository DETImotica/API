"""
DETImotica API: Flask REST API module
- 'Swagger UI'-based doc system compatible.
- ABAC-based access control model.

authors: Goncalo Perna, Eurico Dias
"""

from requests_oauthlib import OAuth1
import requests
from urllib.parse import parse_qs
import configparser
import random
import re
import sys
import time

from flask import Flask, request, jsonify, Response, redirect, session, url_for, flash, abort
from flask_swagger import swagger
from flask_paranoid import Paranoid
from flask_wtf.csrf import CSRFProtect

from functools import wraps

import db

# API global vars
VERSION = '1'
TITLE = 'DETImotica API'

# Flask global vars
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

csrf = CSRFProtect(app)
paranoid = Paranoid(app)
paranoid.redirect_view = '/'

# OAuth global vars
OAUTH_SIGNATURE = 'HMAC-SHA1'
ck = None
cs = None

# Default responses
RESP_501 = "{'resp': 'NOT IMPLEMENTED'}"

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
            abort(200)
        

@app.route("/1", methods=['GET', 'HEAD'])
@auth_only
def index():
    '''API Root endpoint'''

    return "DETImotica API v1", 200

@app.route("/1/spec")
def spec():
    '''Swagger UI wrapper endpoint'''
    swag_obj = swagger(app)
    swag_obj['info']['title'] = TITLE
    swag_obj['info']['description'] = f"DETImotica REST backend API version {VERSION}."
    swag_obj['info']['version'] = VERSION
    return jsonify(swag_obj)

####################################################
#---------Indentity UA OAuth 1.0a endpoints--------#
####################################################

@app.route("/login")
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

    return redirect (f"http://identity.ua.pt/oauth/authorize?oauth_token={req_t}&oauth_token_secret={req_s}", 307)

@app.route("/auth_callback")
def auth_callback():
    '''OAuth callback endpoint (after end-user authorization phase)'''

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
    if (db.has_user(uuid)):
        pass
    else:
        db.add_user(uuid, uemail)
    
    return Response("LOGIN OK", status=200)

@app.route("/logout")
def logout():
    '''Logout endpoint'''

    session.clear()
    # expire AT and cookie from user, revoking all access
    # NOTE: front-end applications should redirect to login page and delete all
    # tokens/cookies, if applicable
    return Response("Logout successful.",status=200)

##################################################
##################################################

##################################################
#---------Room data exposure endpoints-----------#
##################################################

@app.route('/1/rooms', methods=['GET'])
def rooms():
    '''Get all rooms id from database --> getRooms(db).'''
    return jsonify(RESP_501), 501


@app.route('/1/room/<roomid>', methods=['GET', 'POST', 'DELETE'])
def room_id(roomid):
    '''Get all the sensors_id that are in the room from database -->  getSensorsFromRoom(bd, roomid).'''
    return jsonify(RESP_501), 501

##################################################
#---------User data exposure endpoints-----------#
##################################################

@app.route('/1/users', methods=['GET'])
def users():
    '''Get all users (pelo menos uma chave) from the database --> getUsers(bd).'''
    return jsonify(RESP_501), 501

@app.route('/1/user/<internalid>', methods=['POST'])
def user_policy(internalid):
    '''change access policy on the database from the JSON received.'''
    return jsonify(RESP_501), 501

##################################################
#---------Sensor data exposure endpoints---------#
##################################################

@app.route('/1/sensors', methods=['GET'])
def sensors():
    '''Get the sensors_id for a user from the database --> getAllowedSensors(bd, user_email).'''
    return jsonify(RESP_501), 501


@app.route('/1/types', methods=['GET'])
def types():
    '''Get all types of sensors for a user from the database --> getAllowedTypes(bd, user_email)'''
    return jsonify(RESP_501), 501


@app.route('/1/sensor/<sensorid>', methods=['GET', 'POST', 'DELETE'])
def sensor_description(sensorid):
    '''Get the meta-data about the sensor from the database --> getSensor(bd, sensorid)'''
    return jsonify(RESP_501), 501


@app.route('/1/sensor/<sensorid>/measure/<option>', methods=['GET'])
def sensor_measure(sensorid, option):
    '''Verify if the sensor supports a "measure" from database getTypeFromSensor()'''
    if option == "instant":
        return Response(db.query_last(sensorid), status=200, mimetype='application/json')
    if option == "interval":
        extremo_min = request.args.get('start')
        extremo_max = request.args.get('end')
        return Response(db.query_interval(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')
    if option == "mean":
        extremo_min = request.args.get('start')
        extremo_max = request.args.get('end')
        return Response(db.query_avg(sensorid, extremo_min, extremo_max), status=200, mimetype='application/json')
    return Response(jsonify(RESP_501), status=501, mimetype='application/json')

@app.route('/1/sensor/<sensorid>/event/<option>', methods=['GET'])
def sensor_event(sensorid, option):
    '''Verify if the sensor supports "Events" from database'''
    # get data from influx
    return jsonify(RESP_501), 501

####################################################
####################################################

# run self-signed and self-managed PKI instead of self-signed certificate
# (or a real cert?) 
if __name__ == "__main__":
    try:
        config = configparser.ConfigParser()
        config.read('options.conf')

        IURL = config['influxdb']['URL']
        IPORT = config['influxdb']['PORT']
        IDB = config['influxdb']['DB']
        IUSER = config['influxdb']['USER']
        IPW = config['influxdb']['PW']

        PGURL = config['postgresql']['URL']
        PGPORT = config['postgresql']['PORT']
        PGDB = config['postgresql']['DB']
        PGUSER = config['postgresql']['USER']
        PGPW = config['postgresql']['PW']

        config.read(".appconfig")
        ck = config['info']['consumer_key']
        cs = config['info']['consumer_secret']

        app.config['SECRET_KEY'] = config['info']['app_key']
        db.init_dbs(PGURL, PGPORT, PGDB, PGUSER, PGPW, IURL, IUSER, IPW, IPORT, IDB)

        
        csrf.init_app(app)
        paranoid.init_app(app)
        app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))

    except KeyboardInterrupt:
        pass
    except Exception as ex:
        db.close_dbs()
        sys.exit("[ABORT] " + str(ex))
    finally:
        db.close_dbs()
        print("Goodbye!")
        sys.exit(0)
