"""
Flask REST API endpoints for Grafana support
"""

from flask import Blueprint, jsonify, Response
from flask_cors import CORS

grafana = Blueprint('grafana', __name__,url_prefix='/grafana')
CORS(grafana)

@grafana.route('/', methods=['GET', 'POST', 'OPTIONS'])
def graf_root():
    return "OK", 200

@grafana.route('/search')
def graf_search():
    return 'OK', 200

@grafana.route('/query')
def graf_query():
    return 'OK', 200

@grafana.route('/annotations')
def graf_annotations():
    return 'OK', 200