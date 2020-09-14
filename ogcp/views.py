from flask import g, render_template, url_for, request, jsonify, make_response
from ogcp.forms.action_forms import WOLForm, PartitionForm
from ogcp.og_server import OGServer
from flask_babel import _
from ogcp import app
import requests

def parse_ips(checkboxes_dict):
    ips = set()
    for key, ips_list in checkboxes_dict.items():
        if key != 'csrf_token':
            ips.update(ips_list.split(' '))
    return ips

@app.before_request
def load_config():
    g.server = OGServer()
    g.server.load_config('ogcp/cfg/ogserver.json')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', message=error), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', message=error), 500

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

@app.route('/action/setup', methods=['GET'])
def action_setup_show():
    ips = parse_ips(request.args.to_dict())
    payload = {'client': list(ips)}
    r = g.server.get('/client/setup', payload)
    db_partitions = r.json()['partitions']
    forms = [PartitionForm() for _ in db_partitions]
    forms = list(forms)
    for form, db_part in zip(forms, db_partitions):
        form.ips.data = " ".join(ips)
        form.disk.data = db_part['disk']
        form.partition.data = db_part['partition']
        form.size.data = db_part['size']
        form.modify.render_kw = {"formaction": url_for('action_setup_modify')}
        form.delete.render_kw = {"formaction": url_for('action_setup_delete')}
    return render_template('actions/setup.html', forms=forms)

@app.route('/action/setup/modify', methods=['POST'])
def action_setup_modify():
    form = PartitionForm(request.form)
    if form.validate():
        ips = form.ips.data.split(' ')
        r = g.server.get('/client/setup', payload={'client': ips})

        payload = {'clients': ips,
                   'disk': str(form.disk.data),
                   'cache': str(0),
                   'cache_size': str(0),
                   'partition_setup': []}

        for i in range(1,5):
            partition_placeholder = {'partition': str(i),
                                     'filesystem': 'EMPTY',
                                     'code': 'EMPTY',
                                     'size': str(0),
                                     'format': str(int(False))}
            payload['partition_setup'].append(partition_placeholder)

        modified_part = payload['partition_setup'][int(form.partition.data) - 1]
        modified_part['partition'] = str(form.partition.data)
        modified_part['filesystem'] = str(form.fs.data)
        modified_part['code'] = str(form.part_type.data)
        modified_part['size'] = str(form.size.data)
        modified_part['format'] = str(int(form.format_partition.data))

        r = g.server.post('/setup', payload=payload)
        if r.status_code == requests.codes.ok:
            return make_response("200 OK", 200)
    return make_response("400 Bad Request", 400)

@app.route('/action/setup/delete', methods=['POST'])
def action_setup_delete():
    return make_response("200 OK", 200)

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
