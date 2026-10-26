"""Deliberately insecure sample (FAKE credentials) used to demo vibeaudit. Do not deploy."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True)

API_KEY = "a9f3c2e17b4d4e6f8a0b1c2d3e4f5a6b"   # fake value for the demo
DB_PASSWORD = "Sup3rS3cret!2024"


def get_user(name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchone()


def search(term):
    sql = "SELECT id FROM items WHERE title LIKE '%" + term + "%'"
    return sqlite3.connect("app.db").execute(sql).fetchall()


def ping(host):
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


def backup(path):
    os.system("tar czf /tmp/backup.tgz " + path)


def calc(expr):
    return eval(expr)


def fetch(url):
    return requests.get(url, verify=False).text


def load_profile(blob):
    return pickle.loads(blob)


def load_config(text):
    return yaml.load(text)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def make_reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))


def read_claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def is_admin(user):
    # TODO: add authentication and role checks
    return True


def check_signature(payload, sig):
    try:
        verify_hmac(payload, sig)
    except Exception:
        pass


@app.route("/hello")
def hello():
    from flask import render_template_string
    return render_template_string("<h1>Hello " + request.args.get("name", "") + "</h1>")


if __name__ == "__main__":
    # In production, use a proper secret manager and turn debug off
    app.run(host="0.0.0.0", port=5000, debug=True)
