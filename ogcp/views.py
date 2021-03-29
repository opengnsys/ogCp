from flask import (
    g, render_template, url_for, flash, redirect, request, jsonify, make_response
)
from ogcp.forms.action_forms import (
    WOLForm, PartitionForm, ClientDetailsForm, HardwareForm, SessionForm,
    ImageRestoreForm, ImageCreateForm, SoftwareForm, BootModeForm
)
from flask_login import (
    current_user, LoginManager,
    login_user, logout_user,
    login_required
)

from ogcp.models import User
from ogcp.forms.auth import LoginForm
from ogcp.og_server import OGServer
from flask_babel import _
from ogcp import app
import requests
import datetime

FS_CODES = {
    0: 'DISK',
    1: 'EMPTY',
    2: 'CACHE',
    6: 'EXT4',
    9: 'FAT32',
    13: 'NTFS'
}

PART_TYPE_CODES = {
    0: 'EMPTY',
    1: 'DISK',
    7: 'NTFS',
    131: 'LINUX',
    202: 'CACHE',
    218: 'DATA'
}

PART_SCHEME_CODES = {
    1: 'MSDOS',
    2: 'GPT'
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def validate_ips(ips, min_len=1, max_len=float('inf')):
    valid = True
    if len(ips) < min_len:
        flash(_(f'Please, select at least {min_len} computer(s)'),
              category='error')
        valid = not valid
    elif len(ips) > max_len:
        flash(_(f'No more than {max_len} computer(s) can be selected for the given action'),
              category='error')
        valid = not valid
    return valid

def parse_ips(checkboxes_dict):
    ips = set()
    for key, ips_list in checkboxes_dict.items():
        if key != 'csrf_token':
            ips.update(ips_list.split(' '))
    return ips

def get_client_setup(ip):
    payload = payload = {'client': list(ip)}
    r = g.server.get('/client/setup', payload)
    db_partitions = r.json()['partitions']
    for partition in db_partitions:
        if partition['partition'] == 0:
            partition['code'] = PART_SCHEME_CODES[partition['code']]
        else:
            partition['code'] = PART_TYPE_CODES[partition['code']]

        partition['filesystem'] = FS_CODES[partition['filesystem']]

    return db_partitions

def get_clients(state_filter=None):
    r = g.server.get('/clients')
    clients = r.json()
    if state_filter:
        return filter(clients.items(), lambda c: c.state == state_filter)
    return clients

def parse_scopes_from_tree(tree, scope_type):
    scopes = []
    for scope in tree['scope']:
        if scope['type'] == scope_type:
            scopes.append(scope)
        else:
            scopes += parse_scopes_from_tree(scope, scope_type)
    return scopes

@login_manager.user_loader
def load_user(user_id):
    if user_id == 1:
        return User()
    return None

@app.before_request
def load_config():
    g.server = OGServer()

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', message=error), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('error.html', message=error), 500

def image_modified_date_from_str(image):
    return datetime.datetime.strptime(image['modified'], '%a %b %d %H:%M:%S %Y')

@app.route('/')
def index():
    clients = None
    if current_user.is_authenticated:
        clients = get_clients()
        images_response = g.server.get('/images')
        images = images_response.json()['images']
        images.sort(key=image_modified_date_from_str, reverse=True)
        return render_template('dashboard.html', clients=clients,
                               images=images)
    return render_template('base.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User()
        form_user = request.form['user']
        pwd = request.form['pwd']
        if form_user != app.config['USER']:
            flash(_('Incorrect user name'))
            return render_template('auth/login.html', form=form)
        if pwd != app.config['PASS']:
            flash(_('Incorrect password'))
            return render_template('auth/login.html', form=form)
        login_user(user)
        return redirect(url_for('index'))
    return render_template('auth/login.html', form=LoginForm())

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/scopes/')
@login_required
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
@login_required
def action_poweroff():
    ips = parse_ips(request.form.to_dict())
    payload = {'clients': list(ips)}
    g.server.post('/poweroff', payload)
    return redirect(url_for("scopes"))

@app.route('/action/wol', methods=['GET', 'POST'])
@login_required
def action_wol():
    form = WOLForm(request.form)
    if request.method == 'POST' and form.validate():
        wol_type = form.wol_type.data
        ips = form.ips.data.split(' ')
        payload = {'type': wol_type, 'clients': ips}
        g.server.post('/wol', payload)
        flash(_('Wake On Lan request sent successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        ips = parse_ips(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if validate_ips(ips, min_len=1):
            return render_template('actions/wol.html', form=form)
        else:
            return redirect(url_for('scopes'))

@app.route('/action/setup', methods=['GET'])
@login_required
def action_setup_show():
    ips = parse_ips(request.args.to_dict())
    db_partitions = get_client_setup(ips)
    forms = [PartitionForm() for _ in db_partitions]
    forms = list(forms)

    for form, db_part in zip(forms, db_partitions):
        form.ips.data = " ".join(ips)
        form.disk.data = db_part['disk']
        form.partition.data = db_part['partition']
        # XXX: Should separate whole disk form from partition setup form
        if db_part['filesystem'] == "DISK":
            form.part_type.choices = list(PART_SCHEME_CODES.values())
            form.fs.render_kw = {'disabled': ''}

        form.part_type.data = db_part['code']
        form.fs.data = db_part['filesystem']
        form.size.data = db_part['size']
        form.modify.render_kw = {"formaction": url_for('action_setup_modify')}
        form.delete.render_kw = {"formaction": url_for('action_setup_delete')}
    return render_template('actions/setup.html', forms=forms)

@app.route('/action/setup/modify', methods=['POST'])
@login_required
def action_setup_modify():
    form = PartitionForm(request.form)
    if form.validate():
        ips = form.ips.data.split(' ')
        db_partitions = get_client_setup(ips)

        payload = {'clients': ips,
                   'disk': str(form.disk.data),
                   'cache': str(0),
                   'cache_size': str(0),
                   'partition_setup': []}

        for db_part in db_partitions:
            if db_part['partition'] == 0:
                # Set partition scheme
                payload['type'] = db_part['code']
                continue
            partition_setup = {'partition': str(db_part['partition']),
                               'code': db_part['code'],
                               'filesystem': db_part['filesystem'],
                               'size': str(db_part['size']),
                               'format': str(int(False))}
            payload['partition_setup'].append(partition_setup)

        # Ensure a 4 partition setup
        for i in range(len(db_partitions), 5):
            empty_part = {
                'partition': str(i),
                'code': 'EMPTY',
                'filesystem': 'EMPTY',
                'size': '0',
                'format': '0',
            }
            payload['partition_setup'].append(empty_part)

        modified_part = payload['partition_setup'][int(form.partition.data) - 1]
        modified_part['filesystem'] = str(form.fs.data)
        modified_part['code'] = str(form.part_type.data)
        modified_part['size'] = str(form.size.data)
        modified_part['format'] = str(int(form.format_partition.data))

        r = g.server.post('/setup', payload=payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for("scopes"))
    return make_response("400 Bad Request", 400)

@app.route('/action/setup/delete', methods=['POST'])
@login_required
def action_setup_delete():
    form = PartitionForm(request.form)
    if form.validate():
        ips = form.ips.data.split(' ')
        db_partitions = get_client_setup(ips)

        payload = {'clients': ips,
                   'disk': str(form.disk.data),
                   'cache': str(0),
                   'cache_size': str(0),
                   'partition_setup': []}

        for db_part in db_partitions:
            if db_part['partition'] == 0:
                # Skip if this is disk setup.
                continue
            partition_setup = {'partition': str(db_part['partition']),
                               'code': db_part['code'],
                               'filesystem': db_part['filesystem'],
                               'size': str(db_part['size']),
                               'format': str(int(False))}
            payload['partition_setup'].append(partition_setup)

        modified_part = payload['partition_setup'][int(form.partition.data) - 1]
        modified_part['filesystem'] = FS_CODES[1]
        modified_part['code'] = PART_TYPE_CODES[0]
        modified_part['size'] = str(0)
        modified_part['format'] = str(int(True))

        r = g.server.post('/setup', payload=payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for("scopes"))
    return make_response("400 Bad Request", 400)

@app.route('/action/image/restore', methods=['GET', 'POST'])
@login_required
def action_image_restore():
    def search_image(images_list, image_id):
        for image in images_list:
            if image['id'] == image_id:
                return image
        return False

    form = ImageRestoreForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.partition.data.split(' ')
        image_id = form.image.data
        r = g.server.get('/images')
        images_list = r.json()['images']
        image = search_image(images_list, int(image_id))
        if not image:
            return make_response("400 Bad Request", 400)

        payload = {'disk': disk,
                   'partition': partition,
                   'name': image['name'],
                   'repository': g.server.ip,
                   'clients': ips,
                   'type': form.method.data,
                   'profile': str(image['software_id']),
                   'id': str(image['id'])}
        g.server.post('/image/restore', payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for("scopes"))
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_ips(request.args.to_dict())
        if not validate_ips(ips):
            return redirect(url_for('scopes'))
        form.ips.data = ' '.join(ips)

        part_choices = []

        r = g.server.get('/images')
        for image in r.json()['images']:
            form.image.choices.append((image['id'], image['name']))

        for ip in ips:
            r = g.server.get('/client/setup', payload={'client': [ip]})
            if r.status_code == requests.codes.ok:
                partitions = r.json()['partitions']
                parts = []
                for partition in partitions:
                    disk_id = partition['disk']
                    part_id = partition['partition']
                    if part_id == 0:  # This is the disk data, not a partition.
                        continue

                    choice_value = (disk_id, part_id)
                    parts.append(choice_value)

                if not part_choices:  # Use first computer as reference part setup conf
                    part_choices = [part for part in parts]
                elif part_choices != parts:
                    flash(_(f'Computers have different partition setup'), category='error')
                    return redirect(url_for("scopes"))

            else:
                flash(_(f'ogServer was unable to obtain setup of selected computer {ip}'), category='error')
                return redirect(url_for("scopes"))

        form.partition.choices = [ (f'{disk_id} {part_id}', _(f'Disk: {disk_id} | Part: {part_id}'))
                                    for disk_id, part_id in part_choices ]

        return render_template('actions/image_restore.html', form=form)

@app.route('/action/hardware', methods=['GET', 'POST'])
@login_required
def action_hardware():
    form = HardwareForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        r = g.server.post('/hardware', payload={'clients': ips})
        if r.status_code == requests.codes.ok:
            return make_response("200 OK", 200)
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_ips(request.args.to_dict())
        if not validate_ips(ips, max_len=1):
            return redirect(url_for('scopes'))

        form.ips.data = ' '.join(ips)
        r = g.server.get('/hardware', payload={'client': list(ips)})
        hardware = r.json()['hardware']
        return render_template('actions/hardware.html', form=form,
                               hardware=hardware)

@app.route('/action/software', methods=['GET', 'POST'])
@login_required
def action_software():
    form = SoftwareForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.os.data.split(' ')
        if form.view.data:
            r = g.server.get('/software', payload={'client': ips,
                                               'disk': int(disk),
                                               'partition': int(partition)})
            if r.status_code == requests.codes.ok:
                return r.json()

        elif form.update.data:
            r = g.server.post('/software', payload={'clients': ips,
                                                    'disk': disk,
                                                    'partition': partition})
            if r.status_code == requests.codes.ok:
                flash(_('Software profile request sent successfully'), category='info')
                return redirect(url_for("scopes"))
            flash(_(f'Error processing software profile request: ({r.status})'), category='error')
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_ips(request.args.to_dict())
        if not validate_ips(ips, max_len=1):
            return redirect(url_for('scopes'))

        form.ips.data = ' '.join(ips)
        r = g.server.get('/client/setup', payload={'client': list(ips)})

        for part in r.json()['partitions'][1:]:
            form.os.choices.append(
                (f"{part.get('disk')} {part.get('partition')}",
                 f"Disco {part.get('disk')} | Partición {part.get('partition')} "
                 f"| {PART_TYPE_CODES[part.get('code')]} "
                 f"{FS_CODES[part.get('filesystem')]}")
            )
    return render_template('actions/software.html', form=form)

@app.route('/action/session', methods=['GET', 'POST'])
@login_required
def action_session():
    form = SessionForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.os.data.split(' ')
        r = g.server.post('/session', payload={'clients': ips,
                                               'disk': str(disk),
                                               'partition': str(partition)})
        if r.status_code == requests.codes.ok:
            return redirect(url_for("scopes"))
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_ips(request.args.to_dict())
        if not validate_ips(ips, max_len=1):
            return redirect(url_for('scopes'))

        form.ips.data = ' '.join(ips)
        r = g.server.get('/session', payload={'client': list(ips)})
        sessions = r.json()['sessions']
        for os in sessions:
            choice = (f"{os['disk']} {os['partition']}",
                      f"{os['name']} ({os['disk']},{os['partition']})")
            form.os.choices.append(choice)
        return render_template('actions/session.html', form=form)

@app.route('/action/client/info', methods=['GET'])
@login_required
def action_client_info():
    form = ClientDetailsForm()
    ips = parse_ips(request.args.to_dict())
    if not validate_ips(ips, max_len=1):
        return redirect(url_for("scopes"))

    payload = {'client': list(ips)}
    r = g.server.get('/client/info', payload)
    db_client = r.json()

    form.name.data = db_client['name']
    form.ip.data = db_client['ip']
    form.mac.data = db_client['mac']
    form.serial_number.data = db_client['serial_number']
    form.netmask.data = db_client['netmask']
    form.livedir.data = db_client['livedir']
    form.remote.data = db_client['remote']
    form.maintenance.data = db_client['maintenance']
    form.netiface.data = db_client['netiface']
    form.netdriver.data = db_client['netdriver']
    form.repo.data = db_client['repo_id']
    form.room.data = db_client['room']
    form.boot.data = db_client['boot']

    r = g.server.get('/mode')
    available_modes = [(mode, mode) for mode in r.json()['modes']]
    form.boot.choices = list(available_modes)

    r = g.server.get('/scopes')
    rooms = parse_scopes_from_tree(r.json(), 'room')
    rooms = [(room['id'], room['name']) for room in rooms]
    form.room.choices = list(rooms)

    form.create.render_kw = {"style": "visibility:hidden;"}
    return render_template('actions/client_details.html', form=form)

@app.route('/action/client/add', methods=['GET', 'POST'])
@login_required
def action_client_add():
    form = ClientDetailsForm(request.form)
    if request.method == 'POST':
        payload = {"boot": form.boot.data,
                   "ip": form.ip.data,
                   "livedir": form.livedir.data,
                   "mac": form.mac.data,
                   "maintenance": form.maintenance.data,
                   "name": form.name.data,
                   "netdriver": form.netdriver.data,
                   "netiface": form.netiface.data,
                   "netmask": form.netmask.data,
                   "remote": form.remote.data,
                   "repo_id": int(form.repo.data),
                   "room": int(form.room.data),
                   "serial_number": form.serial_number.data}

        r = g.server.post('/client/add', payload)
        if r.status_code == requests.codes.ok:
            return make_response("200 OK", 200)
        return make_response("400 Bad Request", 400)
    else:
        r = g.server.get('/mode')
        available_modes = [(mode, mode) for mode in r.json()['modes']]
        form.boot.choices = list(available_modes)

        r = g.server.get('/scopes')
        rooms = parse_scopes_from_tree(r.json(), 'room')
        rooms = [(room['id'], room['name']) for room in rooms]
        form.room.choices = list(rooms)

        form.create.render_kw = {"formaction": url_for('action_client_add')}
        return render_template('actions/client_details.html', form=form)

@app.route('/action/mode', methods=['GET', 'POST'])
@login_required
def action_mode():
    form = BootModeForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        payload = { 'clients': ips, 'mode': form.boot.data }
        print(payload)
        r = g.server.post('/mode', payload)
        if r.status_code == requests.codes.ok:
            flash(_('Client set boot mode request sent successfully'), category='info')
        else:
            flash(_('Ogserver replied with status code not ok'), category='error')
        return redirect(url_for("scopes"))

    else:
        r = g.server.get('/mode')
        available_modes = [(mode, mode) for mode in r.json()['modes']]
        form.boot.choices = list(available_modes)

        ips = parse_ips(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if not validate_ips(ips):
            return redirect(url_for("scopes"))

        form.ok.render_kw = { 'formaction': url_for('action_mode') }
        return render_template('actions/mode.html', form=form)


@app.route('/action/image/create', methods=['GET', 'POST'])
@login_required
def action_image_create():
    form = ImageCreateForm(request.form)
    if request.method == 'POST':
        ip = form.ip.data
        r = g.server.get('/client/info', payload={"client": [ip]})
        disk, partition, code = form.os.data.split(' ')
        payload = {"clients": [ip],
                   "disk": disk,
                   "partition": partition,
                   "code": code,
                   "name": form.name.data,
                   "repository": g.server.ip,
                   "id": "0", # This is ignored by the server.
                   "description": form.description.data,
                   "group_id": 0, # Default group.
                   "center_id": r.json()["center"]}
        r = g.server.post('/image/create', payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for("scopes"))
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_ips(request.args.to_dict())
        form.ip.data = " ".join(ips)
        if not validate_ips(ips, max_len=1):
            return redirect(url_for("scopes"))

        r = g.server.get('/client/setup', payload={'client': list(ips)})
        for partition in r.json()['partitions']:
            disk_id = partition['disk']
            part_id = partition['partition']
            fs_id = partition['filesystem']
            code = partition['code']

            if part_id == 0:
                # This is the disk data, not a partition.
                continue

            choice_value = f"{disk_id} {part_id} {code}"
            choice_name = (f"{_('Disk')} {disk_id} | "
                           f"{_('Partition')} {part_id} | "
                           f"{_('FS')} {FS_CODES[fs_id]}")
            form.os.choices.append((choice_value, choice_name))
        return render_template('actions/image_create.html', form=form)

@app.route('/action/reboot', methods=['POST'])
@login_required
def action_reboot():
    ips = parse_ips(request.form.to_dict())
    if not validate_ips(ips):
        return redirect(url_for('scopes'))

    payload = {'clients': list(ips)}
    r = g.server.post('/reboot', payload)
    if r.status_code != requests.codes.ok:
        flash(_('OgServer replied with a non ok status code'), category='error')
    else:
        flash(_('Refresh request processed successfully'), category='info')
    return redirect(url_for("scopes"))

@app.route('/action/refresh', methods=['POST'])
@login_required
def action_refresh():
    ips = parse_ips(request.form.to_dict())
    if not validate_ips(ips):
        return redirect(url_for('scopes'))

    payload = {'clients': list(ips)}
    r = g.server.post('/refresh', payload)
    if r.status_code != requests.codes.ok:
        flash(_('OgServer replied with a non ok status code'), category='error')
    else:
        flash(_('Refresh request processed successfully'), category='info')
    return redirect(url_for("scopes"))
