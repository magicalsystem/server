import os
import json

from flask import Flask, request
from pymongo import MongoClient

# CRYPTOGRAPHY MODULE
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions


def _get_privatekey(path):
    # TODO: 
    # handle encrypted keys
    with open(path, 'rb') as kfile:
        pk = serialization.load_pem_private_key(
                kfile.read(),
                password=None,
                backend=default_backend()
                )
        return pk

def _public_key(content):
    pk = serialization.load_ssh_public_key(
            content,
            backend=default_backend()
            )
    return pk

def sign(message, kpath):
    pk = _get_privatekey(kpath)
    signer = pk.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    signer.update(message)
    return base64.b64encode(signer.finalize())

def verify(signature, message, key):
    pk = _public_key(key)
    verifier = pk.verifier(
            base64.b64decode(signature),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    verifier.update(message)
    try:
        verifier.verify()
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

# END OF CRYPTOGRAPHY MODULE

app = Flask(__name__)
mongo = MongoClient()['magicalsystem']

def verify_user_message(mongo, msgobj):
    user = mongo.users.find_one({'username': msgobj['username']})
    keys = mongo.public_keys.find({'user': user['_id']})

    verified = False

    for k in keys:
        verified = verify(msgobj['signature'], msgobj['message'].encode('utf-8'), str(k['key']))
        if verified:
            break
    return verified


try:
    app.config.from_envvar('MAIN_CFG')
except RuntimeError:
    pass

@app.route("/")
def index():
    return "Index"

@app.route("/verify", methods=['POST'])
def verify2():
    payload = json.loads(request.data)
    if verify_user_message(mongo, payload):
        return "", 200
    else:
        return "", 401

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
