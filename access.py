"""
ABAC-based access control module
requires: python3.6+
author: Eurico Dias
"""

#import random

#from flask import request
import arrow
import configparser
import json

from uuid import uuid4

from pymongo import MongoClient
from vakt import EnfoldCache, MemoryStorage, RulesChecker, Inquiry, Policy, Guard, rules, ALLOW_ACCESS, DENY_ACCESS
from vakt.storage.mongo import MongoStorage
from vakt.exceptions import Irreversible
from datadb import DataDB
from pgdb import PGDB

class ABAC(object):
    """
    ABAC base class definition.
    Example of a JSON request body / dictionary:
        {
            'subjects' :
                          [{'uuid'   :   'user-uuid1',
                          'admin'  :   False,
                          'courses':   {
                                            ...
                                       },
                            ...
                           },
                           {'uuid'   :   user-uuid2,
                            'admin'  :   True,
                            ....
                           }]
                        },
            'actions'  : ['GET', 'POST'],
            'resource': {
                          'sensor' : '01234567-89ab-cddc-ba98-76543210',
                          'measure': 'average'
                        },
            'context' : {
                          'local_only'  : True,
                          'hours'       : {
                                            'start': '08:00:00',
                                            'end'  : '18:00:00'
                                          },
                          'weekdays'    : True
                        },
            'description': "Allow access to end-users with uuid1 and uuid2 to read an average from a specific sensor"
        }
    """

    def __init__(self, config_file='options.conf'):
        config = configparser.ConfigParser()
        config.read(config_file)
        try:
                client = MongoClient(config['mongodb']['host'], int(config['mongodb']['port']))
                self._storage = EnfoldCache(MongoStorage(client, config['mongodb']['db']), cache=MemoryStorage())
                self._influxdb = DataDB()
                self._pgdb = PGDB()
        except KeyError as v:
            ex_str = None
            if 'v' == 'mongodb':
                ex_str = f"Configuration file error: \"{config_file}\" has no 'mongodb' section."
            else:
                ex_str = f"Configuration file error: \"{config_file}\" has no {str(v)} value defined on 'mongodb' section."
            raise Irreversible(ex_str)

    def __str__(self):
        return "ABAC(" + str(self._storage) + ")"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def daytime_in_s(time='00:00:00'):
        if type(time) is str:
            hms = [int(v) for v in time.split(':')]
            if 0 <= hms[0] < 24 and 0 <= hms[1] < 60 and 0 <= hms[2] < 60:
                return 3600*hms[0] + 60*hms[1] + hms[2]
        else:
            raise ValueError("Time must be a string in 24h format (e.g. hh:mm:ss)")
        raise ValueError("Incorrect timestamp")

    @staticmethod
    def unix_timestamp(timestamp):
        if type(timestamp) is str:
            return arrow.get(timestamp).timestamp
        raise ValueError("Timestamp must be a string.")

    def get_storage_type(self):
        return ("MongoDB", str(self._storage.cache))

    def check_information_points(self):
        return (str(self._pgdb), "Indentity@UA OAuth")

class PolicyManager(ABAC):
    '''Policy manager class (PAP) for ABAC-based policy manager usage.'''

    def __init__(self):
        super(PolicyManager, self).__init__()

    def __str__(self):
        return "PolicyManager(" + str(self._storage) + ")"

    def __repr__(self):
        return self.__str__()

    def get_policies(self):
        '''PAP - get policies by given request attributes.'''
        stored_policies = self._storage.retrieve_all()
        set_policies = []
        for p in stored_policies:
            set_policies.append(p.to_json())
        return set_policies

    def create_policy(self, req):
        '''Creates a policy based on the JSON-type request body and stores it onto the PRP.'''
        try:
            print(req.data)
            if not req.data:
                return False, "ERROR: request body is empty"

            # load JSON body
            try:
                req_json = req.json
            except:
                return False, "ERROR: malformed JSON - syntax error"
            
            ####
            # 'subjects' is mandatory and has to be a list of key-value subject definitions
            ####
            if type(req_json['subjects']) is not list:
                return False, "ERROR: malformed access JSON - 'subjects' must be a list."

            subject = [{k : rules.Eq(s[k])} for s in req_json['subjects'] for k in s]
            if not subject:
                return False, "ERROR: malformed access JSON - 'subjects' has no value defined."
            ####
            # 'actions' value has to be a json list, although not mandatory
            ####
            if type(req_json['actions']) is not list:
                return False, "ERROR: malformed access JSON - 'actions' must be a list."

            action = [rules.Eq(a) for a in req_json['actions']]
            if not action:
                return False, "ERROR: malformed access JSON - 'actions' has no value defined."

            ####
            # 'resource' is not mandatory, defaults to any element
            ####
            resource = rules.Any()
            if 'resource' in req_json:
                resource = [{k : rules.Eq(req_json['resource'][k])} for k in req_json['resource']]
            
            ####
            # 'context' is not mandatory, defaults to empty
            ####
            context = {}
            if 'context' in req_json:
                context = req_json['context']
                for k in req_json['context']:
                    if k == 'hour':
                        if 'start' in context['hour'] and 'end' in context['hour']:
                            context['hour'] = rules.And(rules.GreaterOrEqual(ABAC.daytime_in_s(time=req_json['context']['hour']['start'])),
                                                   rules.LessOrEqual(ABAC.daytime_in_s(time=req_json['context']['hour']['end']))
                                                  )
                        else:
                            return "ERROR: Malformed access JSON - 'context':'hours' needs attribute 'start' and 'end'!"
                    elif k == 'date':
                        if 'from' in context['date'] and 'until' in context['date']:
                            context['date'] = rules.And(rules.GreaterOrEqual(ABAC.unix_timestamp(req_json['context']['date'])),
                                                   rules.LessOrEqual(ABAC.unix_timestamp(req_json['context']['date']))
                                                  )
                        elif 'from' in context['date']:
                            context['date'] = rules.GreaterOrEqual(ABAC.unix_timestamp(req_json['context']['date']))
                        elif 'until' in context['date']:
                            context['date'] = rules.LessOrEqual(ABAC.unix_timestamp(req_json['context']['date']))
                    elif k == 'ip':
                        context['ip'] = rules.CIDR(req_json['context']['ip'])
                    else:
                        context[k] = rules.Eq(req_json['context'][k])
            ####
            # 'description is not mandatory, defaults to None
            ####
            description = None
            if 'description' in req_json:
                description = req_json['description']

            ####
            # 'effect' is not mandatory, defaults to allow
            ####
            effect = ALLOW_ACCESS                       # default effect - not needed in JSON
            if 'effect' in req_json:
                effect = ALLOW_ACCESS if 'allow' in req_json['effect'].lower() else DENY_ACCESS

        except KeyError as e:
            return False, f"ERROR: malformed policy JSON - no {str(e)} key."

        # add uid to JSON
        uid = str(uuid4())
        
        self._storage.add(Policy(uid,
                          subjects=subject,
                          effect=effect,
                          resources=resource,
                          actions=action,
                          context=context,
                          description=description
                         ))
        
        return True, "OK"

    def update_policy(self, req):
        '''PAP - modify policy'''
        return False, "Not implemented"

    def delete_policy(self, id):
        '''Deletes a policy from the PRP, given UUID4-type ID.'''
        self._storage.delete(id)
        return True, "OK"

class PDP(ABAC):
    '''PDP for ABAC-type ruling class definition.'''

    def __init__(self):
        super(PDP, self).__init__()

    def __str__(self):
        return "PolicyManager(" + str(self._storage) + ")"

    def __repr__(self):
        return self.__str__()

    def get_http_req_access(self, req, subject_data, opt_resource=None):
        """
        Transforms an HTTP request (req) and retrieves subject data in a PDP request.
        Evaluates if the user/subject given has access given its current attributes.
        Returs result as a boolean.
        """
        if not subject_data:
            return False

        resource_path = req.path.split("/")

        resource = {}
        if resource_path[1] in ['rooms', 'types', 'sensor', 'newroom']: ### newroom nao existe
            if opt_resource:
                resource.update(opt_resource)
            else:
                return False
        if resource_path[1] == 'room': ### prob mais um if
            resource.update({resource_path[1]: resource_path[2]})
        elif resource_path[1] == 'sensor':
            if len(resource_path) < 3:
                if opt_resource:
                    resource.update(opt_resource) ##verficar pois isto ja e feito em cima
                else:
                    return False
            else:
                resource.update({resource_path[1]: resource_path[2]})
                details = self._pgdb.getSensor(resource_path[2])
                resource.update({'type': details['data']['type']})
            
            if len(resource_path) > 3 and resource_path[3] == 'measure':
                resource.update({resource_path[3]: resource_path[4]})
            
        current_date = arrow.utcnow()
        time = current_date.strftime("%H:%M:%S")
        day = current_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        inq = Inquiry(subject=subject_data,
                      action=req.method,
                      resource=resource,
                      context={'ip': req.remote_addr, 'hour': ABAC.daytime_in_s(time), 'date': ABAC.unix_timestamp(day)}
                    )

        g = Guard(self._storage, RulesChecker())

        return g.is_allowed(inq)


    def get_access(self, struct_inquiry):
        '''Inquires about an access request given an attribute dictionary.'''
        if not struct_inquiry:
            return False

        g = Guard(self._storage, RulesChecker())
        return g.is_allowed(Inquiry.from_json(struct_inquiry))
