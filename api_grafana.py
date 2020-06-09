"""
Flask REST API endpoints for Grafana support
"""
 
import uuid
import json
import time
import re
from calendar import timegm
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, Response, abort
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
<<<<<<< HEAD
    except:
        return 1000 * timegm(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').timetuple())


=======
    except ValueError:
        return 1000 * timegm(datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').timetuple())
 
 
>>>>>>> untested
@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200
 
@grafana.route('/search', methods=['POST'])
def graf_search():
    rooms= pgdb.getRooms()
    #rooms= [('1')]
    res= []
    for r in rooms:
        sensors= pgdb.getSensorsFromRoom(r)
        #sensors= [uuid.UUID('55fbf7d0-cc47-4642-9290-a493d383ad8c'),uuid.UUID('e7cdb45b-e370-4d74-bb3a-8ebe7527e458')]
<<<<<<< HEAD

=======
>>>>>>> untested
        for s in sensors:
            res.append('Room'+pgdb.getRoom(r)['name']+'_'+str(s)+' ('+pgdb.getSensor(s)['data']['type']+')')
    return jsonify(res)

@grafana.route('/query', methods=['POST'])
def graf_query():
    if not request.json:
        return Response(json.dumps({"error_description": "Empty JSON or empty body."}), status=400,mimetype='application/json')
    req= request.json
    targets= []
    for t in req['targets']:
        if 'target' in t.keys():
            targets.append(((t['target']).split('_')[1]).split(' (')[0])
    if targets == []:
        return jsonify([])
    res= []
    for t in targets:
<<<<<<< HEAD
        query= influxdb.query_interval(uuid.UUID(t),time_st,time_end)
        result= json.loads(query)['values']
=======
>>>>>>> untested
        datapoints= []
        try:
            time_st= time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(req['range']['from'])/1000))
            time_end= time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(req['range']['to'])/1000))
        except ValueError:
            # Alerts (range example: ['5m', 'now'])
            if len((req['range']['to']).split('-')) > 1:
                if 'm' in (req['range']['to']).split('-')[1]:
                    time_end= datetime.utcnow()-timedelta(minutes= int(re.findall(r'\d+',(req['range']['to']).split('-')[1])[0]))
                elif 'h' in (req['range']['to']).split('-')[1]:
                    time_end= datetime.utcnow()-timedelta(hours= int(re.findall(r'\d+',(req['range']['to']).split('-')[1])[0]))
                else:
                    return Response(json.dumps({"error_description": "Invalid time format"}), status=400, mimetype='application/json')
            else:
                time_end= datetime.utcnow()
            if 'm' in req['range']['from']:
                time_st= time_end-timedelta(minutes= int(re.findall(r'\d+',req['range']['from'])[0]))
            elif 'h' in req['range']['from']:
                time_st= time_end-timedelta(hours= int(re.findall(r'\d+',req['range']['from'])[0]))
            else:
                return Response(json.dumps({"error_description": "Invalid time format"}), status=400, mimetype='application/json')    
        try:
            query= json.loads(influxdb.query_avg(t,time_st, time_end,'30s'))
        except ValueError:
            return Response(json.dumps({"error_description": "There was a error obtaning data, try again later"}), status=500, mimetype='application/json')
        datapoints= [[r['value'],convert_to_time_ms(r['time'])] for r in query['values'] if r['value']!= None]
        res.append({"target":t,"datapoints":datapoints})    
    return jsonify(res)

 
@grafana.route('/annotations', methods=['POST'])
def graf_annotations():
    # No annotations implemented
    return jsonify([])     