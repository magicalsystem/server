import os

from flask import Flask

app = Flask(__name__)

try:
    app.config.from_envvar('MAIN_CFG')
except RuntimeError:
    pass

@app.route("/")
def index():
    return "Index"

if __name__ == "__main__":
    app.run()
