"""
Flask REST API endpoints for Grafana support
"""

import db_queries

from flask import Blueprint, jsonify, Response
from flask_cors import CORS

grafana = Blueprint('grafana', __name__,url_prefix='/grafana')
CORS(grafana)

@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200

@grafana.route('/search', methods=['POST'])
def graf_search():
    rooms= db_queries.getRooms()
    #rooms= [(1),(2),(3)]
    res= []
    for r in rooms:
        sensors= db_queries.getSensorsFromRoom(r[0])
        #sensors= [(1),(2),(4)]
        for s in sensors:
            res.append("Room"+str(r)+"_Sensor"+str(s))
    return jsonify(res)

@grafana.route('/query')
def graf_query():
    return 'OK', 200

@grafana.route('/annotations')
def graf_annotations():
    return 'OK', 200 