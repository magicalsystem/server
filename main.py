import os
import json

from flask import Flask, request

app = Flask(__name__)

try:
    app.config.from_envvar('MAIN_CFG')
except RuntimeError:
    pass

@app.route("/")
def index():
    return "Index"

@app.route("/verify", methods=['POST'])
def verify():
    payload = json.loads(request.data)
    print payload


if __name__ == "__main__":
    app.run(port=int(os.getenv('PORT', 5000)))
