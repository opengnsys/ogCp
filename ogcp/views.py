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
    def add_state_to_scopes(scope, clients):
        if 'ip' in scope:
            filtered_client = filter(lambda x: x['addr']==scope['ip'], clients)
            client = next(filtered_client, False)
            if client:
                scope['state'] = client['state']
            else:
                scope['state'] = 'OFF'
            scope['ip'] = [scope['ip']]
        else:
            scope['ip'] = []
            for child in scope['scope']:
                scope['ip'] += add_state_to_scopes(child, clients)
        return scope['ip']

    r = g.server.get('/scopes')
    scopes = r.json()
    r = g.server.get('/clients')
    clients = r.json()
    add_state_to_scopes(scopes, clients['clients'])
    return render_template('scopes.html', scopes=scopes, clients=clients)
