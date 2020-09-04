from flask import g, render_template, url_for, request, jsonify, make_response
from ogcp.forms.action_forms import WOLForm
from ogcp.og_server import OGServer
from flask_babel import _
from ogcp import app

def parse_ips(checkboxes_dict):
    ips = set()
    for ips_list in checkboxes_dict.values():
        ips.update(ips_list.split(' '))
    return ips

@app.before_request
def load_config():
    g.server = OGServer()
    g.server.load_config('ogcp/cfg/ogserver.json')

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/scopes/')
def scopes():
    def add_state_and_ips(scope, clients):
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
                scope['ip'] += add_state_and_ips(child, clients)
        return scope['ip']

    r = g.server.get('/scopes')
    scopes = r.json()
    r = g.server.get('/clients')
    clients = r.json()
    add_state_and_ips(scopes, clients['clients'])
    return render_template('scopes.html', scopes=scopes, clients=clients)

@app.route('/action/poweroff', methods=['POST'])
def action_poweroff():
    ips = parse_ips(request.form.to_dict())
    payload = {'clients': list(ips)}
    g.server.post('/poweroff', payload)
    return make_response("200 OK", 200)

@app.route('/action/wol', methods=['GET', 'POST'])
def action_wol():
    form = WOLForm(request.form)
    if request.method == 'POST' and form.validate():
        wol_type = form.wol_type.data
        ips = parse_ips(request.form.to_dict())
        payload = {'type': wol_type, 'clients': list(ips)}
        g.server.post('/wol', payload)
        return make_response("200 OK", 200)
    else:
        ips = parse_ips(request.args.to_dict())
        form.ips.data = " ".join(ips)
        return render_template('actions/wol.html', form=form)

@app.route('/action/reboot', methods=['POST'])
def action_reboot():
    ips = parse_ips(request.form.to_dict())
    payload = {'clients': list(ips)}
    g.server.post('/reboot', payload)
    return make_response("200 OK", 200)

@app.route('/action/refresh', methods=['POST'])
def action_refresh():
    ips = parse_ips(request.form.to_dict())
    payload = {'clients': list(ips)}
    g.server.post('/refresh', payload)
    return make_response("200 OK", 200)
