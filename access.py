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

from pymongo import MongoClient, ReturnDocument
from vakt import EnfoldCache, MemoryStorage, RulesChecker, Inquiry, Policy, Guard, rules, ALLOW_ACCESS, DENY_ACCESS
from vakt.storage.mongo import MongoStorage
from vakt.exceptions import Irreversible
from datadb import DataDB
from pgdb import PGDB

class ABAC(object):
    """
    ABAC base class definition.
    Example of a JSON policy:
        {
            'subjects' :
                          [{
                              'email'  :   'some_email@ua.pt',
                              'courses':   [PEI, BD]
                           },
                           {  'email'  :   "an_email@ua.pt",
                              'admin'  :   True,
                           }]
                        },
            'actions'  : ['GET'],
            'resources': [{
                              'sensor' : '01234567-89ab-cddc-ba98-76543210',
                              'measure': 'average'
                         }],
            'context' : {
                            'hours' : {
                                        'start': '08:00:00',
                                        'end'  : '18:00:00'
                                      },
                        },
            'description': "Allow access to either some_email having PEI and/or BD courses or an_email (only if admin) to read an average from a specific sensor from 8am to 6pm"
        }
    """

    def __init__(self, config_file='options.conf'):
        config = configparser.ConfigParser()
        config.read(config_file)
        try:
                client = MongoClient(config['mongodb']['host'], int(config['mongodb']['port']))
                
                self._mongo_client = client
                self._raw_policy_collection = client.get_database(config['mongodb']['db']).get_collection(config['mongodb']['raw_collection'])
                self._storage = MongoStorage(client, config['mongodb']['collection'])

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
            try:
                hms = [int(v) for v in time.split(':')]
            except (ValueError, IndexError):
                raise ValueError("'time' must be a string in 24h format (e.g. hh:mm:ss)")
        
            if 0 <= hms[0] < 24 and 0 <= hms[1] < 60 and 0 <= hms[2] < 60:
                return 3600*hms[0] + 60*hms[1] + hms[2]
            else:
                raise ValueError("'time' must be a string in 24h format (e.g. hh:mm:ss)")
        raise ValueError("'time' given must be in string format")

    @staticmethod
    def unix_timestamp(timestamp):
        if type(timestamp) is str:
            return arrow.get(timestamp).timestamp
        raise ValueError("Timestamp must be a string.")

    def get_storage_type(self):
        return ("MongoDB", str(self._storage))

    def check_information_points(self):
        return (str(self._pgdb), "Indentity@UA OAuth")

class PolicyManager(ABAC):
    '''Policy manager class (PAP) for ABAC-based policy manager usage.'''

    def __init__(self):
        super(PolicyManager, self).__init__()
        if self._raw_policy_collection.estimated_document_count() < 1 and len(list(self._storage.retrieve_all())) < 1:
            admin_pol = {'subjects': [{'admin': 'true'}], 'description': '[DEFAULT] All admins have full access to the system'}
            self.create_policy(admin_pol, internal=True)

    def __str__(self):
        return "PolicyManager(" + str(self._storage) + ")"

    def __repr__(self):
        return self.__str__()

    def get_policies(self, req=None):
        '''PAP - get policies by given request attributes.'''
        if not req:
            return [p for p in self._raw_policy_collection.find(projection={'_id': False})]

        # load JSON body
        try:
           req_json = req.json
        except:
           return False, "ERROR: malformed JSON - syntax error"

        return [p for p in self._raw_policy_collection.find(req_json, projection={'_id': False})]

    def create_policy(self, req, internal=False):
        # '''Creates a policy based on the JSON-type request body and stores it onto the PRP.'''
        if internal:
            req_json = req
        else:
            if not req.data:
                return False, "ERROR: request body is empty"

                # load JSON body
            try:
                req_json = req.json
            except:
                return False, "ERROR: malformed JSON - syntax error"

        try:
            ####
            # 'subjects' is mandatory and has to be a list of key-value subject definitions
            ####
            if type(req_json['subjects']) is not list:
                return False, "ERROR: malformed access JSON - 'subjects' must be a list."

            subject = []

            for s in req_json['subjects']:
                sub = {}
                for k in s:
                    if k in ['admin', 'student', 'teacher']:
                        sub.update({k : (rules.Truthy() if s[k].lower() == 'true' else rules.Falsy())})
                    elif k == 'courses':
                        sub.update({k : rules.AnyIn(*s[k])})
                    else:
                        sub.update({k : rules.string.Equal(s[k])})
                    
                subject.append(sub)
        
            if not subject:
                return False, "ERROR: malformed access JSON - 'subjects' doesn't have attributes defined."
            ####
            # 'actions' value has to be a json list, although not mandatory
            ####

            if 'actions' in req_json:
                if type(req_json['actions']) is not list:
                    return False, "ERROR: malformed access JSON - 'actions' must be a list."
                
                action = [rules.string.Equal(a) for a in req_json['actions']]
            ####
            # 'resource' is not mandatory, defaults to any element
            ####
            resource = [rules.Any()]
            if 'resources' in req_json:
                if type(req_json['resources']) is not list:
                    return False, "ERROR: malformed access JSON - 'actions' must be a list."
                resource = [{k : rules.string.Equal(s[k])} for s in req_json['resources'] for k in s]
            
            ####
            # 'context' is not mandatory, defaults to empty
            ####
            context = {"ip": rules.Any(), "hour": rules.Any(), "date": rules.Any()}
            if 'context' in req_json:
                for k in req_json['context']:
                    if k == 'hour':
                        if 'from' in req_json['context']['hour'] and 'to' in req_json['context']['hour']:
                            context['hour'] = rules.And(rules.GreaterOrEqual(ABAC.daytime_in_s(time=req_json['context']['hour']['from'])),
                                                   rules.LessOrEqual(ABAC.daytime_in_s(time=req_json['context']['hour']['to'])))
                        else:
                            return False, "ERROR: Malformed access JSON - context's hours needs 'from' and 'to' attributes!"
                    elif k == 'date':
                        if 'from' in req_json['context']['date'] and 'to' in req_json['context']['date']:
                            context['date'] = rules.And(rules.GreaterOrEqual(ABAC.unix_timestamp(req_json['context']['date']['from'])),
                                                   rules.LessOrEqual(ABAC.unix_timestamp(req_json['context']['date']['to'])))
                        elif 'from' in req_json['context']['date']:
                            context['date'] = rules.GreaterOrEqual(ABAC.unix_timestamp(req_json['context']['date']['from']))
                        elif 'to' in req_json['context']['date']:
                            context['date'] = rules.LessOrEqual(ABAC.unix_timestamp(req_json['context']['date']['to']))
                        else:
                            return False, "ERROR: Malformed access JSON - context's date needs 'from' and 'to' attributes!"
                    # elif k == 'ip':
                    #     internal_rule = [rules.CIDR('10.0.0.0/8'), rules.CIDR('172.16.0.0/12'), rules.CIDR('192.168.0.0/16')]
                    #     if req_json['context']['ip'].lower() == "internal":
                    #         context['ip'] = internal_rule
                    #     else:
                    #         context['ip'] = rules.Not(rules.Or(internal_rule))
                    else:
                        context[k] = rules.string.Equal(req_json['context'][k])
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
            return False, f"ERROR: malformed policy JSON - invalid '{str(e)}' key."

        # add uid to JSON
        uid = str(uuid4())
        req_json.update({'uid': uid})
        
        self._raw_policy_collection.insert_one(req_json)
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
        details = req.json

        uid = details.pop('uid', None)

        self.delete_policy(uid)
        self.create_policy(details, internal=True)

        # inicial_policy = self._storage.get(details["id"]).to_json()
        # self._storage.delete(details["id"])


        # #TODO Verificações
        # if "subjects" in details:
        #     inicial_policy["subjects"] = details["subjects"]
        # if "effect" in details:
        #     inicial_policy["effect"] = details["effect"]
        # if "resources" in details:
        #     inicial_policy["resources"] = details["resources"]
        # if "actions" in details:
        #     inicial_policy["actions"] = details["actions"]
        # if "context" in details:
        #     inicial_policy["context"] = details["context"]
        # if "description" in details:
        #     inicial_policy["description"] = details["description"]

        # self._storage.add(inicial_policy.from_json())
        return True

    def delete_policy(self, id):
        '''Deletes a policy from the PRP, given UUID4-type ID.'''
        self._raw_policy_collection.delete_one({'uid': id})
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

        subject_data.update({'admin': self._pgdb.isAdmin(subject_data['iupi'])})

        resource_path = req.path.split("/")

        resource = {}
        if resource_path[1] in ['rooms', 'types', 'sensors']:
            if opt_resource:
                resource.update(opt_resource)
            else:
                return False
        elif resource_path[1] == 'type':
            resource.update({resource_path[1]: resource_path[2]})
        elif resource_path[1] == 'room':
            resource.update({resource_path[1]: resource_path[2]})
        elif resource_path[1] == 'sensor':
            if len(resource_path) < 3:
                if opt_resource:
                    resource.update(opt_resource)
                else:
                    return False
            else:
                # get the respective sensor's room and type attributes alongside its id
                sensor_type = str(self._pgdb.getSensorTypeID(resource_path[2]))
                sensor_roomid = (self._pgdb.getSensor(resource_path[2]))['room_id']

                resource.update({resource_path[1]: resource_path[2], 'type': sensor_type, 'room': sensor_roomid})
                #resource.update({resource_path[1]: resource_path[2]})
                #details = self._pgdb.getSensor(resource_path[2])
                #resource.update({'type': details['data']['type']})
            
            if len(resource_path) > 3 and resource_path[3] == 'measure':
                resource.update({resource_path[3]: resource_path[4]})
            
        current_date = arrow.utcnow()
        time = current_date.strftime("%H:%M:%S")
        day = current_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        inq = Inquiry(subject=subject_data,
                      action=req.method,
                      resource=resource,
                      context={'hour': ABAC.daytime_in_s(time), 'date': ABAC.unix_timestamp(day)}
                      #context={'ip': req.headers['X-Forwarded-For'].split(',')[0].strip(), 'hour': ABAC.daytime_in_s(time), 'date': ABAC.unix_timestamp(day)}
                    )

        print(inq.to_json())

        g = Guard(self._storage, RulesChecker())

        res = g.is_allowed(inq)
        print(res)
        return res


    def get_access(self, struct_inquiry):
        '''Inquires about an access request given an attribute dictionary.'''
        if not struct_inquiry:
            return False

        g = Guard(self._storage, RulesChecker())
        return g.is_allowed(Inquiry.from_json(struct_inquiry))
