"""
Flask REST API endpoints for Mobile support
"""

import json
import requests
from flask import Blueprint, jsonify, request, Response, abort
from flask_cors import CORS
from pgdb import PGDB

mobile= Blueprint ('mobile', __name__, url_prefix='/mobile')
CORS (mobile)

pgdb = PGDB()
# Push Notifications
#@admin_only
#Webhook that handles Grafana Alerts and sends notifications to FirebaseCM
#ruleName should be sensor id, otherwise the notification will not work
@mobile.route('/notifications', methods=['POST'])
def mobile_notifications ():
    req= request.json
    if not ('message' in req.keys() and 'ruleName' in req.keys()):
        return Response(json.dumps({"error_description" : "Invalid request"}), status=400, mimetype='application/json')
    
    try:
        pgdb.isSensorFree(sensorid)
    except:
        return Response(json.dumps({"error_description" : "The sensorid does not exist"}), status=404, mimetype='application/json')

    try: 
        with open('.secret_config.json') as json_file:
            secret= json.load(json_file)
    except:
        # Webhook handle is ok, notifcation is not sent
        return "OK", 200

    #Message Payload
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'key=' + secret['key'],
    }

    body = {
        'notification': {'title': 'Sensor' + str(req['ruleName']) +'notification',
                         'body': req['message']
                        },
        'topic': req['ruleName'],
        'android': { 'priority': 'normal' }
    }
    # Send a notification to the devices subscribed to the provided topic
    response = requests.post("https://fcm.googleapis.com/fcm/send",headers = headers, data=json.dumps(body))
    
    #print(response.status_code)
    return "OK", 200    
