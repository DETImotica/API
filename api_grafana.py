"""
Flask REST API endpoints for Grafana support
"""

import db_queries
import uuid

from flask import Blueprint, jsonify, request, Response
from flask_cors import CORS

grafana = Blueprint('grafana', __name__,url_prefix='/grafana')
CORS(grafana)

@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200

@grafana.route('/search', methods=['POST'])
def graf_search():
    rooms= db_queries.getRooms()
    #rooms= [('12'),('23'),('34')]
    res= []
    for r in rooms:
        sensors= db_queries.getSensorsFromRoom(r)
        #sensors= [(uuid.uuid4()),(uuid.uuid4()),(uuid.uuid4())]
        for s in sensors:
            res.append("Room"+r+"_Sensor"+str(s))
    return jsonify(res)

@grafana.route('/query', methods=['POST'])
def graf_query():
    return jsonify([])

@grafana.route('/annotations', methods=['POST'])
def graf_annotations():
    return jsonify([])    