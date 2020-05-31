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
    if not request.json:
        return Response(json.dumps({"error_description": "Empty JSON or empty body."}), status=400,mimetype='application/json')
    
    req= request.json
    if not ('message' in req.keys() and 'title' in req.keys()):
        return Response(json.dumps({"error_description" : "Invalid request"}), status=400, mimetype='application/json')
    
    data= {}
    topicName= ''
    
    try:
        if len(req['evalMatches']) == 1 and 'metric' in ((req['evalMatches'][0]).keys()):
            topicName= (req['evalMatches'][0])['metric']
        else:
            return Response(json.dumps({"error_description" : "Invalid request. Can only send a notification to a single sensor topic"}), status=400, mimetype='application/json')        
    except KeyError:
        topicName= 'control'
    except:
        return Response(json.dumps({"error_description" : "Invalid request"}), status=400, mimetype='application/json')                    

    if topicName!= 'control':
        try:
            pgdb.isSensorFree(topicName)
            sensorInfo= pgdb.getSensor(topicName)
            data['id']= topicName
            data['room']= sensorInfo['room_id']
            data['type']= sensorInfo['data']['type'] 
        except:
            return Response(json.dumps({"error_description" : "The sensorid does not exist"}), status=404, mimetype='application/json')

    try: 
        with open('.secret_config.json') as json_file:
            secret= json.load(json_file)
    except:
        # Webhook handle is ok, notifcation is not sent
        return Response(json.dumps({"error_description" : "Could not open or locate config file"}), status=500, mimetype='application/json')

    #Message Payload
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'key=' + secret['key'],
    }

    body = {
        'notification': {'title': req['title'],
                         'body': req['message']
                        },
        'to': '/topics/' + topicName,
        'data': data
    }
    # Send a notification to the devices subscribed to the provided topic
    response = requests.post("https://fcm.googleapis.com/fcm/send",headers = headers, data=json.dumps(body))
    
    if response.status_code == 200:
        return Response(json.dumps({}), status=200, mimetype='application/json')   
    else:
        return Response(json.dumps({"error_description" : "Could not sent notification"}), status=response.status_code, mimetype='application/json')