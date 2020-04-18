"""
Flask REST API endpoints for Grafana support
"""

import uuid
import json

from calendar import timegm
from datetime import datetime
from flask import Blueprint, jsonify, request, Response
from flask_cors import CORS

from pgdb import PGDB
from datadb import DataDB

grafana = Blueprint('grafana', __name__,url_prefix='/grafana')
CORS(grafana)

pgdb = PGDB()
influxdb = DataDB()

def convert_to_time_ms(timestamp):
    try:
        return 1000 * timegm(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ').timetuple())
    except ValueError:
        return 1000 * timegm(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').timetuple())


@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200

@grafana.route('/search', methods=['POST'])
def graf_search():
    #rooms= pgdb.getRooms()
    rooms= [('1')]
    res= []
    for r in rooms:
        #sensors= pgdb.getSensorsFromRoom(r)
        sensors= [uuid.UUID('55fbf7d0-cc47-4642-9290-a493d383ad8c'),uuid.UUID('e7cdb45b-e370-4d74-bb3a-8ebe7527e458')]
        for s in sensors:
            res.append('Room'+r+'_'+str(s))
    return jsonify(res)

@grafana.route('/query', methods=['POST'])
def graf_query():
    req= request.get_json()
    targets= []
    for t in req['targets']:
        if 'target' in t.keys():
            targets.append((t['target']).split('_')[1])
    if targets == []:
        return jsonify([])
    time_st= req['range']['from']
    time_end= req['range']['to']
    res= []
    for t in targets:
        query= influxdb.query_interval(t,time_st,time_end)
        result= json.loads(query)['values']
        datapoints= []
        for r in result:
            datapoints.append([r['value'],convert_to_time_ms(r['time'])])
        res.append({"target":t,"datapoints":datapoints})    
    return jsonify(res)

@grafana.route('/annotations', methods=['POST'])
def graf_annotations():
    return jsonify([])    

