# Deliberately vulnerable test code for Phoenix repository coverage (SAST column). Do not deploy.

import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess
import tarfile

import requests
import yaml
from flask import Flask, redirect, request
from jinja2 import Environment
from lxml import etree

app = Flask(__name__)
from extra import extra  # noqa: E402
app.register_blueprint(extra)
log = logging.getLogger(__name__)


@app.route("/user")
def user():
    # SQL injection
    conn = sqlite3.connect("app.db")
    return str(conn.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'").fetchall())


@app.route("/run")
def run():
    # Command injection
    return subprocess.check_output("ls " + request.args["dir"], shell=True)


@app.route("/read")
def read():
    # Path injection
    with open(os.path.join("/srv/files", request.args["name"])) as f:
        return f.read()


@app.route("/greet")
def greet():
    # Reflected XSS
    return "<p>Hello " + request.args.get("name", "") + "</p>"


@app.route("/eval")
def evaluate():
    # Code injection
    return str(eval(request.args["expr"]))


@app.route("/load", methods=["POST"])
def load():
    # Unsafe deserialization
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def config():
    # Unsafe YAML load
    return str(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/proxy")
def proxy():
    # Server-side request forgery, and no certificate validation
    return requests.get(request.args["url"], verify=False).text


@app.route("/next")
def next_page():
    # Open redirect
    return redirect(request.args["to"])


@app.route("/xml", methods=["POST"])
def xml():
    # XML external entity expansion
    parser = etree.XMLParser(resolve_entities=True)
    return etree.tostring(etree.fromstring(request.data, parser))


@app.route("/template")
def template():
    # Server-side template injection
    return Environment().from_string(request.args["tpl"]).render()


@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    # Weak hashing of a password, and clear-text logging of it
    digest = hashlib.md5(password.encode()).hexdigest()
    log.warning("registered with password %s", password)
    return digest


@app.route("/untar", methods=["POST"])
def untar():
    # Tar slip
    with tarfile.open(fileobj=request.files["archive"].stream) as tar:
        tar.extractall("/tmp/upload")
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
