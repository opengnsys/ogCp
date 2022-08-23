# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from flask import (
    g, render_template, url_for, flash, redirect, request, jsonify, make_response
)
from ogcp.forms.action_forms import (
    WOLForm, SetupForm, ClientDetailsForm, ImageDetailsForm, HardwareForm,
    SessionForm, ImageRestoreForm, ImageCreateForm, SoftwareForm, BootModeForm,
    RoomForm, DeleteRoomForm, CenterForm, DeleteCenterForm, OgliveForm,
    GenericForm, SelectClientForm, ImageUpdateForm, ImportClientsForm,
    RepositoryForm, DeleteRepositoryForm
)
from flask_login import (
    current_user, LoginManager,
    login_user, logout_user,
    login_required
)

from pathlib import Path

from ogcp.models import User
from ogcp.forms.auth import LoginForm, UserForm, DeleteUserForm
from ogcp.og_server import servers
from flask_babel import lazy_gettext as _l
from flask_babel import _
from ogcp import app
import requests
import datetime
import hashlib
import json
import os
import re

FS_CODES = {
    0: 'DISK',
    1: 'EMPTY',
    2: 'CACHE',
    6: 'EXT4',
    9: 'FAT32',
    13: 'NTFS',
    18: 'EXFAT',
    19: 'LINUX-SWAP'
}

PART_TYPE_CODES = {
    0: 'EMPTY',
    1: 'DISK',
    5: 'EXTENDED',
    7: 'NTFS',
    11: 'FAT32',
    23: 'HNTFS',
    27: 'HFAT32',
    39: 'HNTFS-WINRE',
    130: 'LINUX-SWAP',
    131: 'LINUX',
    142: 'LINUX-LVM',
    202: 'CACHE',
    218: 'DATA',
    253: 'LINUX-RAID',
    1792: 'NTFS',
    9984: 'WIN-RECOV',
    33280: 'LINUX-SWAP',
    33536: 'LINUX',
    36352: 'LINUX-LVM',
    51712: 'CACHE',
    61184: 'EFI',
    64768: 'LINUX-RAID',
    65535: 'UNKNOWN'
}

PART_SCHEME_CODES = {
    0: 'EMPTY',
    1: 'MSDOS',
    2: 'GPT'
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def validate_elements(elements, min_len=1, max_len=float('inf')):
    valid = True
    if len(elements) < min_len:
        flash(_('Please, select at least {} element(s)').format(min_len),
              category='error')
        valid = not valid
    elif len(elements) > max_len:
        flash(_('No more than {} element(s) can be selected for the given action').format(max_len),
              category='error')
        valid = not valid
    return valid

def parse_elements(checkboxes_dict):
    unwanted_elements = ['csrf_token', 'scope-server', 'scope-center',
                         'scope-room']
    elements = set()
    for key, elements_list in checkboxes_dict.items():
        if key not in unwanted_elements:
            elements.update(elements_list.split(' '))
    return elements

def get_client_setup(ip):
    payload = {'client': [ip]}
    server = get_server_from_clients([ip])
    r = server.get('/client/setup', payload)
    db_partitions = r.json()['partitions']
    for partition in db_partitions:
        if partition['partition'] == 0:
            partition['code'] = PART_SCHEME_CODES.get(partition['code'], 'MSDOS')
        else:
            partition['code'] = PART_TYPE_CODES.get(partition['code'], 'EMPTY')

        partition['filesystem'] = FS_CODES.get(partition['filesystem'], 'EMPTY')

    return db_partitions

def get_clients(state_filter=None):
    responses = multi_request('get', '/clients')

    clients_list = []
    for r in responses:
        clients_list = clients_list + r['json']['clients']

    clients = {}
    clients['clients'] = clients_list

    if state_filter:
        return filter(clients.items(), lambda c: c.state == state_filter)

    return clients


def get_repository(repository_id):
    repositories = get_repositories()
    [repository] = [repository for repository in repositories
                    if repository['id'] == repository_id]
    return repository


def get_repositories():
    r = g.server.get('/repositories')
    repositories = r.json()['repositories']
    return repositories


def parse_scopes_from_tree(tree, scope_type):
    scopes = []
    for scope in tree['scope']:
        if scope['type'] == scope_type:
            if 'name' in tree:
                scope['parent'] = tree['name']
            scopes.append(scope)
        else:
            scopes += parse_scopes_from_tree(scope, scope_type)
    return scopes

def add_state_and_ips(scope, clients, ips):
    scope['selected'] = False
    if 'ip' in scope:
        filtered_client = filter(lambda x: x['addr']==scope['ip'], clients)
        client = next(filtered_client, False)
        if client:
            scope['state'] = client['state']
            scope['link'] = client.get('speed')
            scope['last_cmd'] = {}
            scope['last_cmd']['result'] = client.get('last_cmd').get('result')
        else:
            scope['state'] = 'off'
        scope['ip'] = [scope['ip']]
        scope['selected'] = set(scope['ip']).issubset(ips)
    else:
        scope['ip'] = []
        for child in scope['scope']:
            scope['ip'] += add_state_and_ips(child, clients, ips)
            scope['selected'] = (len(scope['ip']) < 0 and
                                 set(scope['ip']).issubset(ips))
    return scope['ip']

def get_allowed_scopes(scopes, allowed_scopes):
    for scope in scopes.get('scope'):
        if scope.get('name') in current_user.scopes:
            allowed_scopes.append(scope)
        else:
            get_allowed_scopes(scope, allowed_scopes)

def multi_request(method, uri, payload=None):
    responses = []

    for server in servers:
        response = {}

        if method == 'get':
            r = server.get(uri, payload)
        elif method == 'post':
            r = server.post(uri, payload)
        else:
            raise Exception('Invalid method, use get or post')

        response['server'] = server
        response['json'] = r.json()
        responses.append(response)

    return responses


def get_server_from_clients(selected_clients):
    server = None

    responses = multi_request('get', '/scopes')
    for r in responses:
        server_clients = [c['ip'] for c in parse_scopes_from_tree(r['json'],
                                                                  'computer')]
        if all(client in server_clients for client in selected_clients):
            server = r['server']
            break

    if not server:
        raise Exception('Selected clients not found in any server')

    return server


def get_server_from_ip_port(str_ip_port):
    ip, port = str_ip_port.split(':')

    for s in servers:
        if s.ip == ip and s.port == int(port):
            return s

    raise Exception('Server with address ' + str_ip_port + 'is not configured')


def get_scopes(ips=set()):
    list_scopes = []
    responses = multi_request('get', '/scopes')
    for r in responses:
        scopes = r['json']
        server_scope = {}
        server_scope['name'] = r['server'].name
        server_scope['type'] = "server"
        server_scope['server_ip_port'] = (r['server'].ip + ":" +
                                          str(r['server'].port))
        server_scope.update(scopes)
        list_scopes.append(server_scope)
    all_scopes = {'scope': list_scopes}
    if current_user.scopes:
        allowed_scopes = []
        get_allowed_scopes(all_scopes, allowed_scopes)
        all_scopes = {'scope': allowed_scopes}
    clients = get_clients()
    add_state_and_ips(all_scopes, clients['clients'], ips)

    return all_scopes, clients


def hash_password(pwd):
    sha = hashlib.sha512()
    sha.update(pwd.encode())
    pwd_hash = sha.hexdigest()

    return pwd_hash


def authenticate_user(username, pwd):
    for user in app.config['USERS']:
        if user.get("USER") == username:
            if user.get("PASS") == pwd:
                return user
            else:
                flash(_('Incorrect password'))
                return None
    flash(_('Incorrect user name'))
    return None

def get_user(username):
    for user in app.config['USERS']:
        if user.get("USER") == username:
            return user
    return None


intervals = (
    (_l('days'), 86400),    # 60 * 60 * 24
    (_l('hours'), 3600),    # 60 * 60
    (_l('minutes'), 60),
)


def display_time(seconds):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{} {}".format(value, name))
    return ', '.join(result)


@login_manager.user_loader
def load_user(username):
    user_dict = get_user(username)
    if not user_dict:
        return None

    user = User(username, user_dict.get('SCOPES'), user_dict.get('ADMIN'))
    return user

@app.before_request
def load_config():
    g.server = servers[0]

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
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    try:
        clients = get_clients()
    except requests.exceptions.RequestException as err:
        flash(_('ogServer connection failed: {}.').format(err),
              category='error')
        logout_user()
        return redirect(url_for('index'))
    images_response = g.server.get('/images')
    images = images_response.json()['images']
    images.sort(key=image_modified_date_from_str, reverse=True)
    disk = images_response.json()['disk']
    oglive_list = g.server.get('/oglive/list').json()
    stats = g.server.get('/stats').json()
    timestamp = datetime.datetime.fromtimestamp(stats.get('time').get('now'))
    now = timestamp.strftime('%Y-%m-%d  %H:%M:%S')
    boot = display_time(stats.get('time').get('boot'))
    start = display_time(stats.get('time').get('start'))
    time_dict = {'now': now, 'boot': boot, 'start': start}
    return render_template('dashboard.html', clients=clients,
                           images=images, disk=disk, colsize="6",
                           oglive_list=oglive_list, stats=stats,
                           time_dict=time_dict)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        form_user = request.form['user']
        pwd = request.form['pwd']
        pwd_hash = hash_password(pwd)
        user_dict = authenticate_user(form_user, pwd_hash)
        if not user_dict:
            return render_template('auth/login.html', form=form)
        user = User(form_user, user_dict.get('SCOPES'), user_dict.get('ADMIN'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('auth/login.html', form=LoginForm())

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/scopes/status')
@login_required
def scopes_status():
    scopes, _clients = get_scopes()
    return jsonify(scopes)


@app.route('/client/mac', methods=['GET'])
@login_required
def get_client_mac():
    ip = parse_elements(request.args.to_dict())
    payload = {'client': list(ip)}
    resp = g.server.get('/client/info', payload)
    client_info = resp.json()
    mac = client_info.get('mac')
    pretty_mac = (':'.join(mac[i:i+2] for i in range(0, 12, 2))).upper()
    return jsonify(pretty_mac)


@app.route('/scopes/')
@login_required
def scopes():
    scopes, clients = get_scopes()
    return render_template('scopes.html', scopes=scopes, clients=clients)

@app.route('/action/poweroff', methods=['GET', 'POST'])
@login_required
def action_poweroff():
    form = GenericForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        if not validate_elements(ips):
            return redirect(url_for('commands'))

        payload = {'clients': ips}
        server = get_server_from_clients(ips)
        r = server.post('/poweroff', payload)
        if r.status_code != requests.codes.ok:
            flash(_('ogServer: error powering off client'),
                  category='error')
        else:
            flash(_('Client powered off successfully'),
                  category='info')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if validate_elements(ips):
            scopes, clients = get_scopes(set(ips))
            selected_clients = list(get_selected_clients(scopes['scope']).items())
            return render_template('actions/poweroff.html', form=form,
                                   selected_clients=selected_clients,
                                   scopes=scopes)
        else:
            return redirect(url_for('commands'))


@app.route('/action/wol', methods=['GET', 'POST'])
@login_required
def action_wol():
    form = WOLForm(request.form)
    if request.method == 'POST' and form.validate():
        wol_type = form.wol_type.data
        ips = form.ips.data.split(' ')
        payload = {'type': wol_type, 'clients': ips}
        server = get_server_from_clients(ips)
        server.post('/wol', payload)
        flash(_('Wake On Lan request sent successfully'), category='info')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if validate_elements(ips, min_len=1):
            scopes, clients = get_scopes(set(ips))
            selected_clients = list(get_selected_clients(scopes['scope']).items())
            return render_template('actions/wol.html', form=form,
                                   selected_clients=selected_clients,
                                   scopes=scopes)
        else:
            return redirect(url_for('commands'))


@app.route('/action/setup/select', methods=['GET'])
@login_required
def action_setup_select():
    args = request.args.copy()

    ips = parse_elements(args.to_dict())
    if not validate_elements(ips):
        return redirect(url_for('commands'))

    if len(ips) == 1:
        ip = list(ips)[0]
        return redirect(url_for('action_setup_show', ip=ip))

    form = SelectClientForm()
    form.ips.data = " ".join(ips)
    form.selected_client.choices = list(ips)

    scopes, _ = get_scopes(ips)
    selected_clients = list(get_selected_clients(scopes['scope']).items())

    return render_template('actions/select_client.html',
                           selected_clients=selected_clients,
                           form=form, scopes=scopes)


@app.route('/action/setup', methods=['GET'])
@login_required
def action_setup_show():
    args = request.args.copy()

    default_disk = 1
    selected_disk = int(args.pop('disk', default_disk))

    if args.get('ip'):
        ips = {args['ip']}
        ips_str = base_client = args['ip']
    else:
        ips_str = args['ips']
        ips = set(args['ips'].split(' '))
        base_client = args['selected_client']

    db_partitions = get_client_setup(base_client)
    filtered_partitions = [p for p in db_partitions
                           if p.get('disk') == selected_disk]

    disk_partition = 0
    disks = [d.get('disk') for d in db_partitions
             if d.get('partition') == disk_partition]

    form = SetupForm()
    form.ips.data = ips_str
    form.disk.data = selected_disk
    # If partition table is empty, set MSDOS
    form.disk_type.data = filtered_partitions[0]['code'] or 1

    disk_size = filtered_partitions[0]['size'] // 1024

    # Make form.partition length equal to (filtered_partitions - 1) length
    diff = len(filtered_partitions) - 1 - len(form.partitions)
    [form.partitions.append_entry() for _ in range(diff)]

    for partition, db_part in zip(form.partitions, filtered_partitions[1:]):
        partition.partition.data = str(db_part['partition'])
        partition.part_type.data = db_part['code']
        partition.fs.data = db_part['filesystem']
        partition.size.data = db_part['size'] // 1024
    scopes, _clients = get_scopes(ips)
    return render_template('actions/setup.html',
                           selected_disk=selected_disk,
                           disks=disks,
                           form=form,
                           disk_size=disk_size,
                           ips=ips_str,
                           base_client=base_client,
                           scopes=scopes)

@app.route('/action/setup', methods=['POST'])
@login_required
def action_setup_modify():
    form = SetupForm(request.form)
    if form.validate():
        ips = form.ips.data.split(' ')

        payload = {'clients': ips,
                   'disk': str(form.disk.data),
                   'type': str(form.disk_type.data),
                   'cache': str(0),
                   'cache_size': str(0),
                   'partition_setup': []}

        required_partitions = ["1", "2", "3", "4"]
        for partition in form.partitions:
            print(partition)
            partition_setup = {'partition': str(partition.partition.data),
                               'code': str(partition.part_type.data),
                               'filesystem': str(partition.fs.data),
                               'size': str(partition.size.data * 1024),
                               'format': str(int(partition.format_partition.data))}
            payload['partition_setup'].append(partition_setup)
            if partition.partition.data in required_partitions:
                required_partitions.remove(partition.partition.data)
            if partition.part_type.data == 'CACHE':
                payload['cache'] = '1'
                payload['cache_size'] = str(partition.size.data * 1024)

        for partition in required_partitions:
            empty_part = {
                'partition': partition,
                'code': 'EMPTY',
                'filesystem': 'EMPTY',
                'size': '0',
                'format': '0',
            }
            payload['partition_setup'].append(empty_part)

        server = get_server_from_clients(list(ips))
        r = server.post('/setup', payload=payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for('commands'))
    flash(_(f'Invalid setup form'), category='error')
    return redirect(url_for('commands'))

def search_image(images_list, image_id):
    for image in images_list:
        if image['id'] == image_id:
            return image
    return False

@app.route('/action/image/restore', methods=['GET', 'POST'])
@login_required
def action_image_restore():
    form = ImageRestoreForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.partition.data.split(' ')
        image_id = form.image.data
        server = get_server_from_clients(ips)
        r = server.get('/images')
        images_list = r.json()['images']
        image = search_image(images_list, int(image_id))
        if not image:
            flash(_(f'Image to restore was not found'), category='error')
            return redirect(url_for('commands'))
        repository = get_repository(image['repo_id'])

        payload = {'disk': disk,
                   'partition': partition,
                   'name': image['name'],
                   'repository': repository['ip'],
                   'clients': ips,
                   'type': form.method.data,
                   'profile': str(image['software_id']),
                   'id': str(image['id'])}
        server.post('/image/restore', payload)
        if r.status_code == requests.codes.ok:
            flash(_(f'Image restore command sent sucessfully'), category='info')
        else:
            flash(_(f'There was a problem sending the image restore command'), category='error')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        if not validate_elements(ips):
            return redirect(url_for('commands'))
        form.ips.data = ' '.join(ips)

        part_choices = []

        r = server.get('/images')
        for image in r.json()['images']:
            form.image.choices.append((image['id'], image['name']))

        for ip in ips:
            r = server.get('/client/setup', payload={'client': [ip]})
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
                    return redirect(url_for('commands'))

            else:
                flash(_('ogServer was unable to obtain setup of selected computer {}').format(ip), category='error')
                return redirect(url_for('commands'))

        form.partition.choices = [ (f'{disk_id} {part_id}', _('Disk: {} | Part: {}').format(disk_id, part_id))
                                    for disk_id, part_id in part_choices ]

        scopes, clients = get_scopes(set(ips))
        selected_clients = list(get_selected_clients(scopes['scope']).items())

        return render_template('actions/image_restore.html', form=form,
                               selected_clients=selected_clients,
                               scopes=scopes)

@app.route('/action/hardware', methods=['GET', 'POST'])
@login_required
def action_hardware():
    form = HardwareForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        server = get_server_from_clients(ips)
        r = server.post('/hardware', payload={'clients': ips})
        if r.status_code == requests.codes.ok:
            flash(_(f'Hardware inventory command has been sent'), category='info')
        else:
            flash(_(f'There was a problem sending the hardware inventory command'), category='error')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        scopes, _clients = get_scopes(ips)
        if not validate_elements(ips, max_len=1):
            return redirect(url_for('commands'))

        form.ips.data = ' '.join(ips)
        server = get_server_from_clients(ips)
        r = server.get('/hardware', payload={'client': list(ips)})
        hardware = r.json()['hardware']
        return render_template('actions/hardware.html', form=form,
                               hardware=hardware, scopes=scopes)

@app.route('/action/software', methods=['GET', 'POST'])
@login_required
def action_software():
    form = SoftwareForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.os.data.split(' ')
        server = get_server_from_clients(ips)
        if form.view.data:
            r = server.get('/software', payload={'client': ips,
                                               'disk': int(disk),
                                               'partition': int(partition)})
            if r.status_code == requests.codes.ok:
                software = r.json()['software']
                scopes, clients = get_scopes(set(ips))
                return render_template('actions/software_list.html',
                                       software=software, form=form, scopes=scopes)
        elif form.update.data:
            r = server.post('/software', payload={'clients': ips,
                                                    'disk': disk,
                                                    'partition': partition})
            if r.status_code == requests.codes.ok:
                flash(_('Software profile request sent successfully'), category='info')
            else:
                flash(_('Error processing software profile request: ({})').format(r.status), category='error')
        else:
            flash(_('Error processing software profile form'), category='error')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        scopes, clients = get_scopes(set(ips))
        if not validate_elements(ips, max_len=1):
            return redirect(url_for('commands'))

        form.ips.data = ' '.join(ips)
        server = get_server_from_clients(ips)
        r = server.get('/client/setup', payload={'client': list(ips)})

        for part in r.json()['partitions'][1:]:
            form.os.choices.append(
                (f"{part.get('disk')} {part.get('partition')}",
                 f"Disco {part.get('disk')} | Partición {part.get('partition')} "
                 f"| {PART_TYPE_CODES[part.get('code')]} "
                 f"{FS_CODES[part.get('filesystem')]}")
            )
    return render_template('actions/software.html', form=form, scopes=scopes)

@app.route('/action/session', methods=['GET', 'POST'])
@login_required
def action_session():
    form = SessionForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        disk, partition = form.os.data.split(' ')

        server = get_server_from_clients(list(ips))
        r = server.post('/session', payload={'clients': ips,
                                             'disk': str(disk),
                                             'partition': str(partition)})
        if r.status_code == requests.codes.ok:
            return redirect(url_for('commands'))
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_elements(request.args.to_dict())
        if not validate_elements(ips, max_len=1):
            return redirect(url_for('commands'))

        server = get_server_from_clients(list(ips))
        form.ips.data = ' '.join(ips)
        r = server.get('/session', payload={'client': list(ips)})
        sessions = r.json()['sessions']
        for os in sessions:
            choice = (f"{os['disk']} {os['partition']}",
                      f"{os['name']} ({os['disk']},{os['partition']})")
            form.os.choices.append(choice)
        scopes, clients = get_scopes(set(ips))
        selected_clients = list(get_selected_clients(scopes['scope']).items())
        return render_template('actions/session.html', form=form,
                               selected_clients=selected_clients,
                               scopes=scopes)

@app.route('/action/client/info', methods=['GET'])
@login_required
def action_client_info():
    form = ClientDetailsForm()
    ips = parse_elements(request.args.to_dict())
    if not validate_elements(ips, max_len=1):
        return redirect(url_for('commands'))

    server = get_server_from_clients(list(ips))

    payload = {'client': list(ips)}
    r = server.get('/client/info', payload)
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

    r = server.get('/oglive/list')
    available_oglives = r.json()['oglive']
    for oglive in available_oglives:
        choice = (oglive.get('directory'), oglive.get('directory'))
        form.livedir.choices.append(choice)

    r = server.get('/mode')
    available_modes = [(mode, mode) for mode in r.json()['modes']]
    form.boot.choices = list(available_modes)

    r = server.get('/scopes')
    rooms = parse_scopes_from_tree(r.json(), 'room')
    rooms = [(room['id'], room['name']) for room in rooms]
    form.room.choices = list(rooms)

    form.create.render_kw = {"style": "visibility:hidden;"}

    r = server.get('/images')
    images = r.json()['images']

    ip = list(ips)[0]
    setup = get_client_setup(ip)
    if setup and setup[0].get('code') == 'MSDOS':
        setup[0]['code'] = 'MBR'

    for entry in setup:
        if images and entry['image'] != 0:
            image = next(img for img in images if img['id'] == entry['image'])
            entry['image'] = image['name']
        else:
            entry['image'] = ""

    scopes, clients = get_scopes(set(ips))

    return render_template('actions/client_details.html', form=form,
                           parent="commands.html", scopes=scopes, setup=setup)

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

        server = get_server_from_ip_port(form.server.data)
        r = server.post('/client/add', payload)
        if r.status_code != requests.codes.ok:
            flash(_('ogServer: error adding client'),
                  category='error')
        else:
            flash(_('Client added successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        params = request.args.to_dict()
        if not params.get('scope-room'):
            flash(_('Please, select one room'), category='error')
            return redirect(url_for('scopes'))
        form.server.data = params['scope-server']
        server = get_server_from_ip_port(params['scope-server'])
        r = server.get('/mode')
        available_modes = [(mode, mode) for mode in r.json()['modes']]
        form.boot.choices = list(available_modes)

        r = server.get('/scopes')
        room_id = params['scope-room']
        rooms = parse_scopes_from_tree(r.json(), 'room')
        rooms = [(room['id'], room['name']) for room in rooms
                 if room['id'] == int(room_id)]
        form.room.choices = list(rooms)
        form.room.render_kw = {'readonly': True}

        form.create.render_kw = {"formaction": url_for('action_client_add')}
        scopes, clients = get_scopes()
        return render_template('actions/client_details.html', form=form,
                               parent="scopes.html", scopes=scopes)

@app.route('/action/clients/import', methods=['GET'])
@login_required
def action_clients_import_get():
    params = request.args.to_dict()
    if not params.get('scope-room'):
        flash(_('Please, select one room'), category='error')
        return redirect(url_for('scopes'))

    form = ImportClientsForm()
    form.server.data = params['scope-server']
    server = get_server_from_ip_port(params['scope-server'])
    r = server.get('/scopes')
    rooms = parse_scopes_from_tree(r.json(), 'room')
    selected_room_id = params['scope-room']
    selected_room = [(room['id'], room['name'] + " (" + room['parent'] + ")")
                     for room in rooms if room['id'] == int(selected_room_id)]
    form.room.choices = selected_room
    form.room.render_kw = {'readonly': True}

    scopes, _clients = get_scopes()
    return render_template('actions/import_clients.html', form=form,
                           scopes=scopes)


OG_REGEX_DHCPD_CONF = (r'(?: *host *)'
                       r'([\w.-]*)'
                       r'(?: *{ *hardware *ethernet *)'
                       r'((?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2}))'
                       r'(?: *; *fixed-address *)'
                       r'(\d+\.\d+\.\d+\.\d+)'
                       r'(?: *; *})')
OG_CLIENT_DEFAULT_BOOT = "pxe"
OG_CLIENT_DEFAULT_LIVEDIR = "ogLive"
OG_CLIENT_DEFAULT_MAINTENANCE = False
OG_CLIENT_DEFAULT_NETDRIVER = "generic"
OG_CLIENT_DEFAULT_NETIFACE = "eth0"
OG_CLIENT_DEFAULT_NETMASK = "255.255.255.0"
OG_CLIENT_DEFAULT_REMOTE = False


@app.route('/action/clients/import', methods=['POST'])
@login_required
def action_clients_import_post():
    form = ImportClientsForm(request.form)
    server = get_server_from_ip_port(form.server.data)
    clients = re.findall(OG_REGEX_DHCPD_CONF, form.dhcpd_conf.data)
    if not clients:
        flash(_('No clients found. Check the dhcpd.conf file.'),
              category='error')
        return redirect(url_for('scopes'))
    payload = {'boot': OG_CLIENT_DEFAULT_BOOT,
               'livedir': OG_CLIENT_DEFAULT_LIVEDIR,
               'maintenance': OG_CLIENT_DEFAULT_MAINTENANCE,
               'netdriver': OG_CLIENT_DEFAULT_NETDRIVER,
               'netiface': OG_CLIENT_DEFAULT_NETIFACE,
               'netmask': OG_CLIENT_DEFAULT_NETMASK,
               'remote': OG_CLIENT_DEFAULT_REMOTE,
               'room': int(form.room.data)}
    for client in clients:
        payload['name'] = client[0]
        payload['mac'] = client[1].replace(':', '')
        payload['ip'] = client[2]
        resp = server.post('/client/add', payload)
        if resp.status_code != requests.codes.ok:
            flash(_('ogServer: error adding client {}').format(client[0]),
                  category='error')
            return redirect(url_for('scopes'))
    flash(_('Clients imported successfully'), category='info')
    return redirect(url_for('scopes'))


def get_selected_clients(scopes):
    selected_clients = dict()

    for scope in scopes:
        scope_type = scope.get('type')
        selected = scope.get('selected')
        if ((scope_type == 'computer') and selected):
            name_id = scope.get('name') + '_' + str(scope.get('id'))
            selected_clients[name_id] = scope.get('ip')[0]
        else:
            selected_clients.update(get_selected_clients(scope['scope']))

    return selected_clients

@app.route('/action/client/delete', methods=['GET', 'POST'])
@login_required
def action_client_delete():
    form = GenericForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        if not validate_elements(ips):
            return redirect(url_for('scopes'))

        payload = {'clients': ips}
        r = g.server.post('/client/delete', payload)
        if r.status_code != requests.codes.ok:
            flash(_('ogServer: error deleting client'),
                  category='error')
        else:
            flash(_('Client deleted successfully'),
                  category='info')
        return redirect(url_for('scopes'))
    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if validate_elements(ips):
            scopes, clients = get_scopes(set(ips))
            selected_clients = list(get_selected_clients(scopes['scope']).items())
            return render_template('actions/delete_client.html', form=form,
                                   selected_clients=selected_clients,
                                   scopes=scopes)
        else:
            return redirect(url_for('scopes'))

@app.route('/action/mode', methods=['GET', 'POST'])
@login_required
def action_mode():
    form = BootModeForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        payload = { 'clients': ips, 'mode': form.boot.data }
        print(payload)
        server = get_server_from_clients(ips)
        r = server.post('/mode', payload)
        if r.status_code == requests.codes.ok:
            flash(_('Client set boot mode request sent successfully'), category='info')
        else:
            flash(_('Ogserver replied with status code not ok'), category='error')
        return redirect(url_for('commands'))

    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if not validate_elements(ips):
            return redirect(url_for('commands'))

        server = get_server_from_clients(ips)
        r = server.get('/mode')
        available_modes = [(mode, mode) for mode in r.json()['modes']]
        form.boot.choices = list(available_modes)

        form.ok.render_kw = { 'formaction': url_for('action_mode') }
        scopes, clients = get_scopes(set(ips))
        selected_clients = list(get_selected_clients(scopes['scope']).items())
        return render_template('actions/mode.html', form=form, scopes=scopes,
                               selected_clients=selected_clients,
                               clients=clients)


@app.route('/action/oglive', methods=['GET', 'POST'])
@login_required
def action_oglive():
    form = OgliveForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        payload = {'clients': ips, 'name': form.oglive.data}
        server = get_server_from_clients(ips)
        r = server.post('/oglive/set', payload)
        if r.status_code == requests.codes.ok:
            flash(_('Client set ogLive request sent successfully'),
                  category='info')
        else:
            flash(_('Ogserver replied with status code not ok'),
                  category='error')
        return redirect(url_for('commands'))

    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if not validate_elements(ips):
            return redirect(url_for('commands'))

        server = get_server_from_clients(list(ips))
        r = server.get('/oglive/list')
        if r.status_code != requests.codes.ok:
            flash(_('Ogserver replied with status code not ok'),
                  category='error')
            return redirect(url_for('commands'))
        available_oglives = [(oglive.get('directory'), oglive.get('directory'))
                             for oglive in r.json()['oglive']]
        available_oglives.insert(0, ('default', 'default'))
        form.oglive.choices = list(available_oglives)

        form.ok.render_kw = {'formaction': url_for('action_oglive')}
        scopes, clients = get_scopes(set(ips))
        selected_clients = list(get_selected_clients(scopes['scope']).items())
        return render_template('actions/oglive.html', form=form, scopes=scopes,
                               selected_clients=selected_clients)


@app.route('/action/image/create', methods=['GET', 'POST'])
@login_required
def action_image_create():
    form = ImageCreateForm(request.form)
    if request.method == 'POST':
        ip = form.ip.data
        server = get_server_from_clients([ip])
        r = server.get('/client/info', payload={"client": [ip]})
        disk, partition, code = form.os.data.split(' ')
        payload = {"clients": [ip],
                   "disk": disk,
                   "partition": partition,
                   "code": code,
                   "name": form.name.data,
                   "repository_id": int(form.repository.data),
                   "id": "0", # This is ignored by the server.
                   "description": form.description.data,
                   "group_id": 0, # Default group.
                   "center_id": r.json()["center"]}
        r = server.post('/image/create', payload)
        if r.status_code == requests.codes.ok:
            return redirect(url_for('commands'))
        return make_response("400 Bad Request", 400)
    else:
        ips = parse_elements(request.args.to_dict())
        form.ip.data = " ".join(ips)
        if not validate_elements(ips, max_len=1):
            return redirect(url_for('commands'))

        server = get_server_from_clients(ips)
        r = server.get('/client/setup', payload={'client': list(ips)})
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

        repositories = get_repositories()
        for repo in repositories:
            form.repository.choices.append((repo['id'], repo['name']))

        scopes, clients = get_scopes(set(ips))
        return render_template('actions/image_create.html', form=form,
                               scopes=scopes)


@app.route('/action/image/update', methods=['GET', 'POST'])
@login_required
def action_image_update():
    form = ImageUpdateForm(request.form)
    if request.method == 'POST':
        ip = form.ip.data
        disk, partition, code = form.os.data.split(' ')
        image_id = form.image.data
        server = get_server_from_clients([ip])
        r = server.get('/images')
        images_list = r.json()['images']
        image = search_image(images_list, int(image_id))
        if not image:
            flash(_('Image to restore was not found'), category='error')
            return redirect(url_for('commands'))
        repository = get_repository(image['repo_id'])
        payload = {'clients': [ip],
                   'disk': disk,
                   'partition': partition,
                   'code': code,
                   'name': image['name'],
                   'repository': repository['ip'],
                   'id': str(image['id']),
                   # Dummy parameters, not used by ogServer on image update.
                   'group_id': 0,
                   'center_id': 0}
        r = server.post('/image/create', payload)
        if r.status_code == requests.codes.ok:
            flash(_('Image update command sent sucessfully'), category='info')
        else:
            flash(_('There was a problem sending the image update command'),
                  category='error')
        return redirect(url_for('commands'))

    ips = parse_elements(request.args.to_dict())
    if not validate_elements(ips, max_len=1):
        return redirect(url_for('commands'))
    form.ip.data = ' '.join(ips)

    r = server.get('/images')
    for image in r.json()['images']:
        form.image.choices.append((image['id'], image['name']))

    r = server.get('/client/setup', payload={'client': list(ips)})
    for partition in r.json()['partitions']:
        disk_id = partition['disk']
        part_id = partition['partition']
        fs_id = partition['filesystem']
        code = partition['code']

        if part_id == 0:
            # This is the disk data, not a partition.
            continue

        choice_value = f'{disk_id} {part_id} {code}'
        choice_name = (f"{_('Disk')} {disk_id} | "
                       f"{_('Partition')} {part_id} | "
                       f"{_('FS')} {FS_CODES[fs_id]}")
        form.os.choices.append((choice_value, choice_name))

    scopes, _clients = get_scopes(set(ips))
    selected_clients = list(get_selected_clients(scopes['scope']).items())

    return render_template('actions/image_update.html', form=form,
                           selected_clients=selected_clients,
                           scopes=scopes)


@app.route('/action/reboot', methods=['GET', 'POST'])
@login_required
def action_reboot():
    form = GenericForm(request.form)
    if request.method == 'POST':
        ips = form.ips.data.split(' ')
        if not validate_elements(ips):
            return redirect(url_for('commands'))

        payload = {'clients': ips}
        server = get_server_from_clients(ips)
        r = server.post('/reboot', payload)
        if r.status_code != requests.codes.ok:
            flash(_('ogServer: error rebooting client'),
                  category='error')
        else:
            flash(_('Client rebooted successfully'),
                  category='info')
        return redirect(url_for('commands'))
    else:
        ips = parse_elements(request.args.to_dict())
        form.ips.data = " ".join(ips)
        if validate_elements(ips):
            scopes, clients = get_scopes(set(ips))
            selected_clients = list(get_selected_clients(scopes['scope']).items())
            return render_template('actions/reboot.html', form=form,
                                   selected_clients=selected_clients,
                                   scopes=scopes)
        else:
            return redirect(url_for('commands'))


@app.route('/action/refresh', methods=['POST'])
@login_required
def action_refresh():
    ips = parse_elements(request.form.to_dict())
    if not validate_elements(ips):
        return redirect(url_for('commands'))

    server = get_server_from_clients(list(ips))
    payload = {'clients': list(ips)}
    r = server.post('/refresh', payload)
    if r.status_code != requests.codes.ok:
        flash(_('OgServer replied with a non ok status code'), category='error')
    else:
        flash(_('Refresh request processed successfully'), category='info')
    return redirect(url_for('commands'))

@app.route('/action/center/add', methods=['GET', 'POST'])
@login_required
def action_center_add():
    form = CenterForm(request.form)
    if request.method == 'POST':
        payload = {"name": form.name.data,
                   "comment": form.comment.data}
        r = g.server.post('/center/add', payload)
        if r.status_code != requests.codes.ok:
            flash(_('Server replied with error code when adding the center'),
                  category='error')
        else:
            flash(_('Center added successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        scopes, clients = get_scopes()
        return render_template('actions/add_center.html', form=form,
                               scopes=scopes)

@app.route('/action/center/delete', methods=['GET', 'POST'])
@login_required
def action_center_delete():
    form = DeleteCenterForm(request.form)
    if request.method == 'POST':
        payload = {"id": form.center.data}
        r = g.server.post('/center/delete', payload)
        if r.status_code != requests.codes.ok:
            flash(_('Server replied with error code when deleting the center'),
                  category='error')
        else:
            flash(_('Center deleted successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        r = g.server.get('/scopes')
        centers = parse_scopes_from_tree(r.json(), 'center')
        centers = [(center['id'], center['name']) for center in centers]
        form.center.choices = list(centers)
        scopes, clients = get_scopes()
        return render_template('actions/delete_center.html', form=form,
                               scopes=scopes)

@app.route('/action/room/add', methods=['GET', 'POST'])
@login_required
def action_room_add():
    form = RoomForm(request.form)
    if request.method == 'POST':
        server = get_server_from_ip_port(form.server.data)
        payload = {"center": int(form.center.data),
                   "name": form.name.data,
                   "netmask": form.netmask.data}
        r = server.post('/room/add', payload)
        if r.status_code != requests.codes.ok:
            flash(_('Server replied with error code when adding the room'), category='error')
        else:
            flash(_('Room added successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        params = request.args.to_dict()
        if not params.get('scope-center'):
            flash(_('Please, select one center'), category='error')
            return redirect(url_for('scopes'))
        server = get_server_from_ip_port(params['scope-server'])
        r = server.get('/scopes')
        selected_center_id = params['scope-center']
        centers = parse_scopes_from_tree(r.json(), 'center')
        selected_center = [(center['id'], center['name']) for center in centers
                           if center['id'] == int(selected_center_id)]
        form.center.choices = selected_center
        form.center.render_kw = {'readonly': True}
        form.server.data = params['scope-server']
        scopes, clients = get_scopes()
        return render_template('actions/add_room.html', form=form,
                               scopes=scopes)

@app.route('/action/room/delete', methods=['GET', 'POST'])
@login_required
def action_room_delete():
    form = DeleteRoomForm(request.form)
    if request.method == 'POST':
        payload = {"id": form.room.data}
        r = g.server.post('/room/delete', payload)
        if r.status_code != requests.codes.ok:
            flash(_('Server replied with error code when deleting the room'),
                  category='error')
        else:
            flash(_('Room deleted successfully'), category='info')
        return redirect(url_for("scopes"))
    else:
        params = request.args.to_dict()
        if not params.get('scope-room'):
            flash(_('Please, select one room'), category='error')
            return redirect(url_for('scopes'))
        r = g.server.get('/scopes')
        rooms = parse_scopes_from_tree(r.json(), 'room')
        selected_room_id = params['scope-room']
        selected_room = [(room['id'], room['name'] + " (" + room['parent'] + ")")
                         for room in rooms if room['id'] == int(selected_room_id)]
        form.room.choices = selected_room
        form.room.render_kw = {'readonly': True}
        scopes, clients = get_scopes()
        return render_template('actions/delete_room.html', form=form,
                               scopes=scopes)

@app.route('/commands/', methods=['GET'])
@login_required
def commands():
    scopes, clients = get_scopes()
    return render_template('commands.html', scopes=scopes, clients=clients)

@app.route('/images/', methods=['GET'])
@login_required
def images():
    r = g.server.get('/images')
    images = r.json()['images']
    return render_template('images.html', images=images)


@app.route('/repositories/', methods=['GET'])
@login_required
def repositories():
    r = g.server.get('/repositories')
    repositories = r.json()['repositories']
    return render_template('repositories.html', repositories=repositories)


@app.route('/repositories/add', methods=['GET'])
@login_required
def repository_add_get():
    form = RepositoryForm()
    r = g.server.get('/repositories')
    repositories = r.json()['repositories']
    return render_template('actions/add_repository.html', form=form,
                           repositories=repositories)


@app.route('/repositories/add', methods=['POST'])
@login_required
def repository_add_post():
    form = RepositoryForm(request.form)
    if not form.validate():
        flash(form.errors, category='error')
        return redirect(url_for('repositories'))

    payload = {"name": form.name.data,
               "ip": form.ip.data}
    r = g.server.post('/repository/add', payload)
    if r.status_code != requests.codes.ok:
        flash(_('ogServer: error adding the repository'), category='error')
    else:
        flash(_('Repository added successfully'), category='info')
    return redirect(url_for("repositories"))


@app.route('/repositories/delete', methods=['GET'])
@login_required
def repository_delete_get():
    form = GenericForm()
    repositories = get_repositories()
    selected_repo = [(name, repo_id) for name, repo_id in
                     request.args.to_dict().items() if name != "csrf_token"]
    if not validate_elements(selected_repo, max_len=1):
        flash(_('Please select one repository to delete'), category='error')
        return redirect(url_for('repositories'))
    repo_name, repo_id = selected_repo[0]
    form.ids.data = repo_id
    return render_template('actions/delete_repository.html', form=form,
                           repo_name=repo_name, repositories=repositories)


@app.route('/repositories/delete', methods=['POST'])
@login_required
def repository_delete_post():
    form = GenericForm(request.form)
    ids = form.ids.data.split(' ')
    if not validate_elements(ids, max_len=1):
        return redirect(url_for('repositories'))
    repo_id = ids.pop()
    payload = {'id': repo_id}
    r = g.server.post('/repository/delete', payload)
    if r.status_code != requests.codes.ok:
        flash(_('OgServer: error deleting repository'), category='error')
    else:
        flash(_('Repository deleted successfully'), category='info')
    return redirect(url_for('repositories'))


@app.route('/users/', methods=['GET'])
@login_required
def users():
    users = app.config['USERS']
    return render_template('users.html', users=users)


def get_available_scopes():
    resp = g.server.get('/scopes')
    centers = parse_scopes_from_tree(resp.json(), 'center')
    centers = [(center['name'], center['name']) for center in centers]
    rooms = parse_scopes_from_tree(resp.json(), 'room')
    rooms = [(room['name'], room['name']) for room in rooms]
    return centers + rooms


def save_user(form):
    username = form.username.data

    pwd_hash = hash_password(form.pwd.data)
    pwd_hash_confirm = hash_password(form.pwd_confirm.data)
    if not pwd_hash == pwd_hash_confirm:
        flash(_('Passwords do not match'), category='error')
        return redirect(url_for('users'))

    admin = form.admin.data
    scopes = form.scopes.data

    user = {
        'USER': username,
        'PASS': pwd_hash,
        'ADMIN': admin,
        'SCOPES': scopes,
    }

    filename = os.path.join(app.root_path, 'cfg', 'ogcp.json')
    with open(filename, 'r+') as file:
        config = json.load(file)

        config['USERS'].append(user)

        file.seek(0)
        json.dump(config, file, indent='\t')
        file.truncate()

    app.config['USERS'].append(user)

    return redirect(url_for('users'))


def delete_user(username):
    user = get_user(username)

    filename = os.path.join(app.root_path, 'cfg', 'ogcp.json')
    with open(filename, 'r+') as file:
        config = json.load(file)

        config['USERS'].remove(user)

        file.seek(0)
        json.dump(config, file, indent='\t')
        file.truncate()

    app.config['USERS'].remove(user)

    return redirect(url_for('users'))


@app.route('/user/add', methods=['GET'])
@login_required
def user_add_get():
    form = UserForm()
    form.scopes.choices = get_available_scopes()
    return render_template('auth/add_user.html', form=form)


@app.route('/user/add', methods=['POST'])
@login_required
def user_add_post():
    form = UserForm(request.form)
    form.scopes.choices = get_available_scopes()
    if not form.validate():
        flash(form.errors, category='error')
        return redirect(url_for('users'))

    if get_user(form.username.data):
        flash(_('This username already exists'), category='error')
        return redirect(url_for('users'))

    return save_user(form)


@app.route('/user/edit', methods=['GET'])
@login_required
def user_edit_get():
    username_set = parse_elements(request.args.to_dict())
    if not validate_elements(username_set, max_len=1):
        return redirect(url_for('users'))

    username = username_set.pop()
    user = get_user(username)
    if not user:
        flash(_('User {} do not exists').format(username), category='error')
        return redirect(url_for('users'))

    form = UserForm()
    form.username.data = user.get('USER')
    form.username.render_kw = {'readonly': True}
    form.admin.data = user.get('ADMIN')
    form.scopes.data = user.get('SCOPES')
    form.scopes.choices = get_available_scopes()

    return render_template('auth/edit_user.html', form=form)


@app.route('/user/edit', methods=['POST'])
@login_required
def user_edit_post():
    form = UserForm(request.form)
    form.scopes.choices = get_available_scopes()
    if not form.validate():
        flash(form.errors, category='error')
        return redirect(url_for('users'))

    username = form.username.data
    if not get_user(username):
        flash(_('User {} do not exists').format(username), category='error')
        return redirect(url_for('users'))

    delete_user(username)

    return save_user(form)


@app.route('/user/delete', methods=['GET'])
@login_required
def user_delete_get():
    username_set = parse_elements(request.args.to_dict())
    if not validate_elements(username_set, max_len=1):
        return redirect(url_for('users'))

    username = username_set.pop()
    user = get_user(username)
    if not user:
        flash(_('User {} do not exists').format(username), category='error')
        return redirect(url_for('users'))

    form = DeleteUserForm()
    form.username.data = user.get('USER')

    return render_template('auth/delete_user.html', form=form)


@app.route('/user/delete', methods=['POST'])
@login_required
def user_delete_post():
    form = DeleteUserForm(request.form)
    if not form.validate():
        flash(form.errors, category='error')
        return redirect(url_for('users'))

    username = form.username.data
    if not get_user(username):
        flash(_('User {} do not exists').format(username), category='error')
        return redirect(url_for('users'))

    delete_user(username)

    flash(_('User {} deleted').format(username), category='info')
    return redirect(url_for('users'))


@app.route('/action/image/info', methods=['GET'])
@login_required
def action_image_info():
    form = ImageDetailsForm()
    ids = parse_elements(request.args.to_dict())
    if not validate_elements(ids, max_len=1):
        return redirect(url_for('images'))

    id = ids.pop()
    r = g.server.get('/images')
    images = r.json()['images']
    image = next(img for img in images if img['id'] == int(id))

    form.id.data = image['id']
    form.name.data = image['name']
    # Bytes to Gibibytes
    form.size.data = image['size'] / 1024 ** 3
    form.datasize.data = image['datasize'] / 1024 ** 3
    form.modified.data = image['modified']
    form.permissions.data = image['permissions']
    form.software_id.data = image['software_id']

    images = g.server.get('/images').json()['images']

    return render_template('actions/image_details.html', form=form,
                           images=images)

@app.route('/action/image/delete', methods=['GET', 'POST'])
@login_required
def action_image_delete():
    form = GenericForm(request.form)
    if request.method == 'POST':
        ids = form.ids.data.split(' ')
        if not validate_elements(ids, max_len=1):
            return redirect(url_for('images'))
        id = ids.pop()
        payload = {'image': id}
        r = g.server.post('/image/delete', payload)
        if r.status_code != requests.codes.ok:
            flash(_('OgServer replied with a non ok status code'), category='error')
        else:
            flash(_('Image deletion request sent successfully'), category='info')
        return redirect(url_for('images'))
    else:
        images = [(name, imgid) for name, imgid in request.args.to_dict().items() if name != "csrf_token"]
        if not validate_elements(images, max_len=1):
            return redirect(url_for('images'))
        image_name, image_id = images[0]
        r = g.server.get('/images')
        form.ids.data = image_id
        if not validate_elements(images, max_len=1):
            flash(_('Please select one image to delete'), category='error')
            return redirect(url_for('images'))
        return render_template('actions/delete_image.html', form=form,
                               image_name=image_name.split('_', 1)[0], image_id=image_id,
                               images=r.json()['images'])

@app.route('/action/log', methods=['GET'])
@login_required
def action_legacy_log():
    ips = parse_elements(request.args.to_dict())
    if not validate_elements(ips, max_len=1):
        return redirect(url_for('commands'))
    ip = ips.pop()
    log_file = Path("/opt/opengnsys/log/clients/" + str(ip) + ".log")
    log = log_file.read_text()
    if log:
        scopes, clients = get_scopes(set(ips))
        return render_template('actions/legacy/log.html', log=log,
                               scopes=scopes)
    else:
        return redirect(url_for('commands'))

@app.route('/action/rt-log', methods=['GET'])
@login_required
def action_legacy_rt_log():
    ips = parse_elements(request.args.to_dict())
    if not validate_elements(ips, max_len=1):
        return redirect(url_for('commands'))
    ip = ips.pop()
    scheme = "http://"
    rt_log_path = "/cgi-bin/httpd-log.sh"
    rt_log_url = scheme + ip + rt_log_path
    return redirect(rt_log_url)

