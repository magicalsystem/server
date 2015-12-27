import os
import json

from flask import Flask, request
from pymongo import MongoClient

import auth

app = Flask(__name__)
mongo = MongoClient()['magicalsystem']

def verify_user_message(mongo, msgobj):
    user = mongo.users.find_one({'username': msgobj['username']})
    keys = mongo.public_keys.find({'user': user['_id']})

    verified = False

    for k in keys:
        verified = auth.verify(msgobj['signature'], msgobj['message'].encode('utf-8'), str(k['key']))
        if verified:
            break
    return verified


def auth_required(f, *args, **kwargs):
    """ Authorization required decorator
    """
    def inner_func():
        payload = json.loads(request.data)
        if verify_user_message(mongo, payload):
            return f(*args, **kwargs)
        else:
            return json.dumps({'error': 'Access denied'}), 401
    return inner_func

try:
    app.config.from_envvar('MAIN_CFG')
except RuntimeError:
    pass

@app.route("/")
def index():
    return "Index"

@app.route("/verify", methods=['POST'])
@auth_required
def verify():
    return json.dumps({'message': 'OK'}), 200

@app.route("/keys/add", methods=['POST'])
def keys_add():
    payload = json.loads(request.data)
    msg = json.loads(payload['message'])
    user = mongo.users.find_one({"username": msg["username"]})
    mongo.public_keys.insert({"user": user['_id'], "key": msg['public_key']})

    return "", 200

if __name__ == "__main__":
    if os.getenv('DEBUG') is not None:
        app.debug = True
    app.run(port=int(os.getenv('PORT', 5000)))
