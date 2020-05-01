import configparser
import json
import sys
import os

from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError

class DataDB(object):
    '''Relational database class definition.'''

    def __init__(self):
        self._METRIC_INT = "1m"

        config = configparser.ConfigParser()
        config.read('options.conf')

        self.url = config['influxdb']['URL']
        self.port = config['influxdb']['PORT']
        self.db = config['influxdb']['DB']
        self.user = config['influxdb']['USER']
        self._pw = config['influxdb']['PW']

    # Open an InfluxDB connection
    def _open(self):
        conn = InfluxDBClient(host=self.url, port=self.port, username=self.user, password=self._pw, database=self.db)
        if not conn:
            raise InfluxDBClientError("Connection to metrics database was not set.")
        return conn
    
    # Query the last value of a sensor
    def query_last(self, id):
        influx_conn = self._open()

        res = influx_conn.query(f"SELECT LAST(\"value\") AS \"value\" FROM value WHERE time > now()-{self._METRIC_INT} AND \"device\" = '{id}'")

        for p in res.get_points():
            influx_conn.close()
            return json.dumps(dict({'values': [{"time": p['time'], "value": p['value']}]}))
        influx_conn.close()
        return json.dumps({'values': []})

    # Get a set of metrics from a sensor
    def query_interval(self, id, int1, int2):
        if not int1 or not int2:
            return json.dumps({"values": []})

        influx_conn = self._open()

        res = influx_conn.query(f"SELECT \"value\" FROM value WHERE (time >= '{int1}' AND time <= '{int2}') AND \"device\" = '{id}'")
        if not res:
            influx_conn.close()
            return json.dumps({'values': []})
        
        result = []
        for p in res.get_points():
            result += [dict({'time': p['time'], 'value': p['value']})]
        influx_conn.close()
        return json.dumps({'values' : result})

    # Query the average of a set of values in a given time interval
    # Supports grouped query by timeframe and limit of datapoints
    def query_avg(self, id, int1, int2, group_interval=None, limit=None):
        if not int1 or not int2:
            return json.dumps({"values": []})
        
        influx_conn = self._open()

        res = influx_conn.query(f"SELECT MEAN(\"value\") AS \"value\" FROM value WHERE (time >= '{int1}' AND time <= '{int2}') AND \"device\" = '{id}' " 
                                + (f"GROUP BY time({group_interval}),* " if group_interval else "")
                                + (f"LIMIT {limit}" if limit else "")
                               )
        result = []
        for p in res.get_points():
            res.append({"time": p['time'], "value": p['value']})    
        influx_conn.close()
        return json.dumps({"values": result})
