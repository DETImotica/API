"""
Flask REST API module. 'Swagger UI'-based documentation compatible. 
authors: Goncalo Perna, Eurico Dias
"""

import configparser
import sys

from flask import Flask, request, jsonify, Response
from flask_swagger import swagger

import db


# API global vars
VERSION = '1'
TITLE = 'DETImotica API'

# Flask global vars
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# OAuth static global vars
OAUTH_VERSION = '1.0a'
OAUTH_IDENTITY_CYPHER = 'HMAC-SHA1'

# Default responses
RESP_501 = "{'resp': 'NOT IMPLEMENTED'}"

# Root endpoint

@app.route("/1", methods=['GET', 'HEAD'])
def index():
    return "DETImotica API v1", 200

# Swagger endpoint
@app.route("/1/spec")
def spec():
    swag_obj = swagger(app)
    swag_obj['info']['title'] = TITLE
    swag_obj['info']['description'] = "DETImotica REST backend API version {}.".format(VERSION)
    swag_obj['info']['version'] = VERSION
    return jsonify(swag_obj)

####################################################
#---------Indentity UA OAuth 1.0a endpoints--------#
####################################################

# Start login endpoint
@app.route("/login")
def login():
    # hardcode values (DONT COMMIT JUST YET, TEST FIRST), then convert it to a more secure and
    # scalable solution
    # research for token and key storage
    # secure check the token/cookie
    # check login status: if cookie/token is 100% valid (untempered), authorize immediatly
    # get oauth parameter information
    # do the request, wait for auto-redirect
    # ask for authorization
    # wait for user permission
    # do the request, get AT and redirect to oauth callback endpoint
    return jsonify(RESP_501), 501

# Login callback OAuth endpoint (should not be an endpoint maybe...?)
@app.route("/auth_callback")
def login_callback():
    # see confirm flag
    # check AT
    # send OK
    return jsonify(RESP_501), 501

# Logout endpoint
@app.route("/logout")
def logout():
    # expire AT from user, revoking all access
    # NOTE: front-end applications should redirect to login page and revoke all locally stored
    # tokens/cookies, if applicable
    return jsonify(RESP_501), 501

##################################################
##################################################

##################################################
#---------Room data exposure endpoints-----------#
##################################################

@app.route('/1/rooms', methods=['GET'])
def rooms():
    # Get all rooms id from database --> getRooms(db)
    return jsonify(RESP_501), 501


@app.route('/1/room/<roomid>', methods=['GET', 'POST', 'DELETE'])
def room_id(roomid):
    # Get all the sensors_id that are in the room from database -->  getSensorsFromRoom(bd, roomid)
    return jsonify(RESP_501), 501

##################################################
#---------User data exposure endpoints-----------#
##################################################


@app.route('/1/users', methods=['GET'])
def users():
    # Get all users (pelo menos uma chave) from the database --> getUsers(bd)
    return jsonify(RESP_501), 501

@app.route('/1/user/<internalid>', methods=['POST'])
def user_policy(internalid):
    # change access policy on the database from the JSON received
    return jsonify(RESP_501), 501

##################################################
#---------Sensor data exposure endpoints---------#
##################################################

@app.route('/1/sensors', methods=['GET'])
def sensors():
    # Get the sensors_id for a user from the database --> getAllowedSensors(bd, user_email)
    return jsonify(RESP_501), 501


@app.route('/1/types', methods=['GET'])
def types():
    # Get all types of sensors for a user from the database --> getAllowedTypes(bd, user_email)
    return jsonify(RESP_501), 501


@app.route('/1/sensor/<sensorid>', methods=['GET', 'POST', 'DELETE'])
def sensor_description(sensorid):
    # Get the meta-data about the sensor from the database --> getSensor(bd, sensorid)
    return jsonify(RESP_501), 501


@app.route('/1/sensor/<sensorid>/measure/<option>', methods=['GET'])
def sensor_measure(sensorid, option):
    # verify if the sensor supports a "measure" from database getTypeFromSensor()
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
    return Response(jsonify(RESP_501), status=401, mimetype='application/json')

@app.route('/1/sensor/<sensorid>/event/<option>', methods=['GET'])
def sensor_event(sensorid, option):
    # verify if the sensor supports "Events" from database
    # get data from influx
    return jsonify(RESP_501), 501


####################################################
####################################################

# try to run HTTPS (view certificates)
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

        db.init_dbs(PGURL, PGPORT, PGDB, PGUSER, PGPW, IURL, IUSER, IPW, IPORT, IDB)
        app.run(host='0.0.0.0', port=80)
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("An error occurred initializing the app: \n" + str(ex))
    finally:
        db.close_dbs()
        print("Goodbye!")
        sys.exit(0)
