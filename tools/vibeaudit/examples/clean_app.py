"""A small Flask service written the safe way; vibeaudit should report nothing here."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, abort, request

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY", "")
password_label = "Enter your password"
SECRET_KEY = "change-me"  # placeholder, real value comes from the environment


def get_user(name):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()


def ping(host):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False).stdout


def fetch(url):
    return requests.get(url, timeout=10).text


def load_config(text):
    return yaml.safe_load(text)


def load_state(text):
    return json.loads(text)


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def make_reset_token():
    return secrets.token_urlsafe(32)


def read_claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])


def check_signature(payload, sig, key):
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(403)


def cache_key(data):
    return hashlib.sha1(data).hexdigest()  # non-security use: cache key


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
