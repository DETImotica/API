import psycopg2
import psycopg2.extras
import json
import sys
import os

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError
from pymongo import MongoClient

# class InfluxClient:
#     def __init__(self,host,dbname,user,pw):
#         influxdb = 

METRIC_INT = "1m"

# db connections
# pg_conn = None
influx_conn = None

# Initialize relational and read-only metrics database
def init_dbs(pgurl, pgport, pgdb, pguser, pgpw, iurl, iuser, ipw, iport, idb):
    # global pg_conn
    global influx_conn
    # pg_conn = psycopg2.connect(host = pgurl, port = pgport, user = pguser, dbname = pgdb)
    influx_conn = InfluxDBClient(host = iurl, port = iport, username = iuser, password = ipw, database = idb)

    # if not pg_conn:
    #     print("Error on relational database connection. Quitting...")
    #     quit(1)
    if not influx_conn:
        print("Error on metrics database connection. Quitting...")
        quit(1)

# Close database connections
def close_dbs():
    global pg_conn
    global influx_conn

#    pg_conn.close()
    influx_conn.close()

    pg_conn = None
    influx_conn = None

# Query the last value of a sensor
def query_last(id):
    if not influx_conn:
        raise InfluxDBClientError("Connection to metrics database was not set.")

    res = influx_conn.query(f"SELECT LAST(\"value\") AS \"value\" FROM value WHERE time > now()-{METRIC_INT} AND \"device\" = '{id}'")

    for p in res.get_points():
        return json.dumps(dict({'values': [{"time": p['time'], "value": p['value']}]}))
    return json.dumps({})

# Get a set of metrics from a sensor
def query_interval(id, int1, int2):
    if not influx_conn:
        raise InfluxDBClientError("Connection to metrics database was not set.")

    if not int1 or not int2:
        return json.dumps({})
    
    res = influx_conn.query(f"SELECT \"value\" FROM value WHERE (time >= '{int1}' AND time <= '{int2}') AND \"device\" = '{id}'")
    if not res:
        return json.dumps({})
    
    result = []
    for p in res.get_points():
        result += [dict({'time': p['time'], 'value': p['value']})]
    return json.dumps({'values' : result})

# Query the average of a set of values
def query_avg(id, int1, int2):
    if not influx_conn:
        raise InfluxDBClientError("Connection to metrics database was not set.")

    if not int1 or not int2:
        return json.dumps({})

    res = influx_conn.query(f"SELECT MEAN(\"value\") AS \"value\" FROM value WHERE (time >= '{int1}' AND time <= '{int2}') AND \"device\" = '{id}'")
    
    for p in res.get_points():
        return json.dumps(dict({'values': [{"time": p['time'], "value": p['value']}]}))
    return json.dumps({})

# Query users in the database
def query_users():
    return None