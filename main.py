import os
import json
from functools import wraps

from flask import Flask, request
from pymongo import MongoClient

import auth

app = Flask(__name__)
mongo = MongoClient()['magicalsystem']


def auth_public_keys(mongo, msgobj):
    user = mongo.users.find_one({'username': msgobj['username']})
    keys = mongo.public_keys.find({'user': user['_id']})

    verified = False

    for k in keys:
        verified = auth.verify(msgobj['signature'], msgobj['message'].encode('utf-8'), str(k['key']))
        if verified:
            break
    return verified, user

def auth_none(mongo, msgobj):
    return True, dict()

AUTH_MODULE = very_user_message


def auth_required(f, *args, **kwargs):
    """ Authorization required decorator
    """
    @wraps(f)
    def inner_func():
        payload = json.loads(request.data)
        outcome, user = AUTH_MODULE(mongo, payload)
        if outcome:
            return f(user=user, 
                     message=json.loads(payload['message']),
                     *args, **kwargs)
        else:
            return json.dumps({'error': 'Access denied'}), 401
    return inner_func

def ansible_dynamic_inventory(groups, hosts):
    inv = dict()
    ancestors = dict()

    for g in groups:
        inv[g['name']] = {
                'hosts': list(),
                'vars': g['vars'],
                }
        ancestors[g['name']] = g['ancestors']

    inv['_meta'] = {'hostvars': dict()}
    
    for h in hosts:
        inv['_meta']['hostvars'][h['name']] = h['vars']
        
        for g in h['groups']:
            inv[g]['hosts'].append(h['name'])

            #  append to ancestor group
            for a in ancestors[g]:
                if h['name'] not in inv[a]['hosts']:
                    inv[a]['hosts'].append(h['name'])
    return inv

def criteria2mongo(criteria):
    def _or_group(k, vs):
        return {'$or': [{k: v} for v in vs]}

    return {
            '$and': [_or_group(k, vs) 
                     for k, vs in criteria.iteritems()]
    }


try:
    app.config.from_envvar('MAIN_CFG')
except RuntimeError:
    pass

@app.route("/")
def index():
    return "Index"

@app.route("/verify", methods=['POST'])
@auth_required
def verify(user, message):
    return json.dumps({'message': 'OK'}), 200

@app.route("/keys/add", methods=['POST'])
@auth_required
def keys_add(user, message):
    # TODO: add user rights
    target = mongo.users.find_one({'username': message['username']})
    mongo.public_keys.insert(
            {
                "user": target['_id'], 
                "key": message['public_key']
            })

    return json.dumps({'message': 'Key added'}), 200


@app.route("/groups/update", methods=["POST"])
@auth_required
def groups_update(user, message):
    for g in message:
        mongo.groups.update(
                {"_id": g['name']},
                g,
                upsert=True)
    return json.dumps({'message': 'Groups updated'}), 200

@app.route("/groups", methods=["POST"])
@auth_required
def groups_list(user, message):
    query = criteria2mongo(message['pattern'])
    return json.dumps(list(mongo.groups.find(query))), 200

@app.route("/servers", methods=["POST"])
@auth_required
def servers_list(user, message):
    query = criteria2mongo(message['pattern'])
    return json.dumps(list(mongo.servers.find(query))), 200

@app.route("/servers/update", methods=["POST"])
@auth_required
def servers_update(user, message):
    for g in message:
        mongo.servers.update(
                {"_id": g['name']},
                g,
                upsert=True)
    return json.dumps({'message': 'Servers updated'}), 200

@app.route("/ansible/inv", methods=["POST"])
@auth_required
def ansible_di(user, message):
    query = criteria2mongo(message['pattern'])
    hosts = mongo.servers.find(query)
    groups = mongo.groups.find()

    di = ansible_dynamic_inventory(groups, hosts)
    return json.dumps(di), 200

if __name__ == "__main__":
    if os.getenv('DEBUG') is not None:
        app.debug = True
    app.run(port=int(os.getenv('PORT', 5000)))
