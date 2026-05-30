"""CWE-78: OS Command Injection — 의도적 취약 픽스처.

p/command-injection 룰팩 탐지 대상:
- os.system + 사용자 입력
- subprocess shell=True + 사용자 입력
- os.popen + 사용자 입력
"""

import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # ruleid: dangerous-system-call
    return str(os.system(f"ping -c 1 {host}"))


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    # ruleid: dangerous-subprocess-use
    out = subprocess.check_output(f"nslookup {domain}", shell=True)
    return out


@app.route("/whois")
def whois():
    name = request.args.get("name", "")
    # ruleid: dangerous-system-call
    with os.popen("whois " + name) as p:
        return p.read()


@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "")
    # ruleid: dangerous-subprocess-use
    subprocess.Popen(cmd, shell=True)
    return "ok"
