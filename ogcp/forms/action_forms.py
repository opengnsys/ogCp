# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField,
    StringField, RadioField, FormField, FieldList
)
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from flask_babel import _

class WOLForm(FlaskForm):
    ips = HiddenField()
    wol_type = SelectField(label=_('Type'),
                           choices=[('broadcast', 'Broadcast'),
                                    ('unicast', 'Unicast')])
    submit = SubmitField(label=_('Submit'))

class PartitionForm(FlaskForm):
    partition = SelectField(label=_('Partition'),
                            choices=range(1,10))
    part_type = SelectField(label=_('Type'),
                            choices=[('LINUX', 'Linux'),
                                     ('NTFS', 'NTFS'),
                                     ('EMPTY', 'Empty')])
    fs = SelectField(label=_('Filesystem'),
                     choices=[('EXT4', 'EXT4'),
                              ('NTFS', 'NTFS'),
                              ('EMPTY', 'Empty')])
    size = IntegerField(label=_('Size (KB)'))
    format_partition = BooleanField(label=_('Format'))

class SetupForm(FlaskForm):
    ips = HiddenField()
    disk = HiddenField()
    disk_type = SelectField(label=_('Type'),
                            choices=[('MSDOS', 'MSDOS'),
                                     ('GPT', 'GPT')])
    partitions = FieldList(FormField(PartitionForm),
                           min_entries=1,
                           max_entries=10)

class HardwareForm(FlaskForm):
    ips = HiddenField()
    refresh = SubmitField(label=_('Refresh'))

class SoftwareForm(FlaskForm):
    ips = HiddenField()
    os = SelectField(label=_('Partition'), choices=[])
    view = SubmitField(label=_('View'))
    update = SubmitField(label=_('Update'))

class SessionForm(FlaskForm):
    ips = HiddenField()
    os = RadioField(label=_('Session'), choices=[])
    run = SubmitField(label=_('Run'))

class ImageRestoreForm(FlaskForm):
    ips = HiddenField()
    partition = SelectField(label=_('Partition'), choices=[])
    image = SelectField(label=_('Image'), choices=[])
    method = SelectField(label=_('Method'),
                         choices=[('UNICAST-CACHE', 'Unicast Cache'),
                                  ('UNICAST-DIRECT', 'Unicast Direct')])
    restore = SubmitField(label=_('Restore'))

class ClientDetailsForm(FlaskForm):
    name = StringField(label=_('Name'))
    ip = StringField(label=_('IP'))
    mac = StringField(label=_('MAC'))
    serial_number = StringField(label=_('Serial Number'))
    netmask = StringField(label=_('Netmask'))
    livedir = SelectField(label=_('ogLive'),
                          choices=[('ogLive', 'Default'),])
    remote = BooleanField(label=_('Remote'))
    maintenance = BooleanField(label=_('Maintenance'))
    netiface = SelectField(label=_('Interface'),
                           choices=[('eth0', 'eth0'),
                                    ('eth1', 'eth1'),
                                    ('eth2', 'eth2')])
    netdriver = SelectField(label=_('Driver'),
                            choices=[('generic', 'generic')])
    repo = SelectField(label=_('Repository'),
                       choices=[(1, 'Default')])
    room = SelectField(label=_('Room'))
    boot = SelectField(label=_('Boot Mode'))
    create = SubmitField(label=_('Create'))

class BootModeForm(FlaskForm):
    ips = HiddenField()
    boot = SelectField(label=_('Boot mode'))
    ok = SubmitField(label=_('Ok'))

class ImageCreateForm(FlaskForm):
    ip = HiddenField()
    os = SelectField(label=_('OS'), choices=[])
    name = StringField(label=_('Image name'),
                       validators=[InputRequired()])
    description = StringField(label=_('Description'))
    create = SubmitField(label=_('Create'))

class CenterForm(FlaskForm):
    name = StringField(label=_('Center name'),
                       validators=[InputRequired()])
    comment = StringField(label=_('Comment'))
    submit = SubmitField(label=_('Submit'))

class RoomForm(FlaskForm):
    center = SelectField(label=_('Center'),
                         validators=[InputRequired()])
    name = StringField(label=_('Room name'),
                       validators=[InputRequired()])
    netmask = StringField(label=_('Netmask'),
                          validators=[InputRequired()])
    submit = SubmitField(label=_('Submit'))

class DeleteRoomForm(FlaskForm):
    room = SelectField(label=_('Room'),
                       validators=[InputRequired()])
    submit = SubmitField(label=_('Submit'))
