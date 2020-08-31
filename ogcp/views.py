from flask import g, render_template, url_for
from ogcp.og_server import OGServer
from flask_babel import _
from ogcp import app

@app.before_request
def load_config():
    g.server = OGServer()
    g.server.load_config('ogcp/cfg/ogserver.json')

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/scopes/')
def scopes():
    return render_template('base.html')
