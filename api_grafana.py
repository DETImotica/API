"""
Flask REST API endpoints for Grafana support
"""

import uuid

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
    return 1000 * timegm(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ').timetuple())

@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200

@grafana.route('/search', methods=['POST'])
def graf_search():
    rooms= pgdb.getRooms()
    #rooms= [('12'),('23'),('34')]
    res= []
    for r in rooms:
        sensors= pgdb.getSensorsFromRoom(r)
        #sensors= [(uuid.uuid4()),(uuid.uuid4()),(uuid.uuid4())]
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
    time_st= convert_to_time_ms(req['range']['from'])
    time_end= convert_to_time_ms(req['range']['to'])
    res= []
    for t in targets:
        query= influxdb.query_interval(uuid.UUID(t),time_st,time_end)
        if not query=={}:
            result= query['values']
            datapoints= []
            for r in result:
                datapoints.append([r['value'],convert_to_time_ms(r['time'])])
            res.append({"target":t,"datapoints":datapoints})    
    return jsonify(res)

@grafana.route('/annotations', methods=['POST'])
def graf_annotations():
    return jsonify([])    

print(graf_query())