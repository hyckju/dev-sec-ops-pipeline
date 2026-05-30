"""CWE-89: SQL Injection — 의도적 취약 픽스처.

p/sql-injection 룰팩이 탐지해야 하는 패턴:
- f-string으로 SQL에 사용자 입력 삽입
- 문자열 연결로 SQL 조립
- str.format() 사용

실제 실행되지 않는다 (의존 모듈도 import만 시도되지 않을 수 있다).
"""

import sqlite3

import psycopg2
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # ruleid: tainted-sql-string
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchall()


@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    conn = psycopg2.connect("dbname=app")
    cur = conn.cursor()
    # ruleid: tainted-sql-string
    cur.execute(
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    return cur.fetchone()


@app.route("/search")
def search():
    keyword = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # ruleid: tainted-sql-string
    query = "SELECT * FROM articles WHERE title LIKE '%{}%'".format(keyword)
    cur.execute(query)
    return cur.fetchall()
