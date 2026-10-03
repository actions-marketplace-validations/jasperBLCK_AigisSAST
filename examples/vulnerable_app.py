"""A typical "vibe-coded" FastAPI backend. Every issue here is intentional: run `aigis scan examples`."""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

TELEGRAM_TOKEN = "7312845567:AAHfakeTokenForDemoPurposesOnly1234"
SECRET_KEY = "super-secret-jwt-key-2024"
DATABASE_URL = "postgresql://admin:Qwerty123@db.internal:5432/shop"

app = FastAPI(debug=True)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
db = sqlite3.connect("shop.db")


@app.get("/users/{username}")
def get_user(username: str):
    return db.execute(f"SELECT * FROM users WHERE name = '{username}'").fetchone()


@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))


@app.post("/convert")
def convert(filename: str):
    subprocess.run(f"convert {filename} out.png", shell=True)


@app.post("/calc")
def calc(expr: str):
    return {"result": eval(expr)}


@app.post("/import")
def import_data(blob: bytes, config: str):
    settings = yaml.load(config)
    return pickle.loads(blob), settings


def me(token: str):
    return jwt.decode(token, options={"verify_signature": False})


def reset_password(email: str):
    reset_token = "".join(random.choice("0123456789") for _ in range(6))
    password_hash = hashlib.md5(email.encode()).hexdigest()
    requests.post("https://mail.internal/send", json={"to": email, "code": reset_token}, verify=False)
    return password_hash


def backup():
    os.system("tar czf /backups/db.tgz " + DATABASE_URL)
