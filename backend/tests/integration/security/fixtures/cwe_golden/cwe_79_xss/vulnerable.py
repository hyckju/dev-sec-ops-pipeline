"""CWE-79: Cross-Site Scripting — 의도적 취약 픽스처.

p/xss 룰팩이 탐지해야 하는 패턴:
- 사용자 입력을 escape 없이 HTML 응답에 삽입
- jinja2 autoescape 비활성화
- Markup() 으로 escape 우회
"""

from flask import Flask, Markup, make_response, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: raw-html-concat
    return f"<h1>Hello {name}</h1>"


@app.route("/render")
def render_user_template():
    user_template = request.args.get("template", "")
    # ruleid: jinja2-autoescape-disabled
    t = Template(user_template, autoescape=False)
    return t.render()


@app.route("/profile")
def profile():
    bio = request.args.get("bio", "")
    # ruleid: flask-markup-bypass
    resp = make_response("<div>" + Markup(bio) + "</div>")
    return resp


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    # ruleid: raw-html-concat
    return "<p>" + msg + "</p>"
