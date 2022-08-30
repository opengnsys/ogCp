# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField,
    StringField, RadioField, FormField, FieldList, DecimalField, TextAreaField
)
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from flask_babel import _


class GenericForm(FlaskForm):
    ips = HiddenField()
    ids = HiddenField()
    server = HiddenField()
    submit = SubmitField(label=_l('Submit'))


class WOLForm(FlaskForm):
    ips = HiddenField()
    wol_type = SelectField(label=_l('Type'),
                           choices=[('broadcast', 'Broadcast'),
                                    ('unicast', 'Unicast')])
    submit = SubmitField(label=_l('Submit'))

class PartitionForm(FlaskForm):
    partition = SelectField(label=_l('Partition'),
                            choices=range(1,10))
    part_type = SelectField(label=_l('Type'),
                            choices=[('LINUX', 'Linux'),
                                     ('NTFS', 'NTFS'),
                                     ('CACHE', 'CACHE'),
                                     ('EFI', 'EFI'),
                                     ('DATA', 'DATA'),
                                     ('LINUX-SWAP', 'LINUX-SWAP'),
                                     ('EXTENDED', 'EXTENDED'),
                                     ('FAT32', 'FAT32'),
                                     ('LINUX-LVM', 'LINUX-LVM'),
                                     ('LINUX-RAID', 'LINUX-RAID'),
                                     ('WIN-RECOV', 'WIN-RECOV'),
                                     ('HNTFS', 'HNTFS'),
                                     ('HFAT32', 'HFAT32'),
                                     ('HNTFS-WINRE', 'HNTFS-WINRE'),
                                     ('EMPTY', 'Empty')])
    fs = SelectField(label=_l('Filesystem'),
                     choices=[('EXT4', 'EXT4'),
                              ('NTFS', 'NTFS'),
                              ('CACHE', 'CACHE'),
                              ('LINUX-SWAP', 'LINUX-SWAP'),
                              ('FAT32', 'FAT32'),
                              ('EXFAT', 'EXFAT'),
                              ('EMPTY', 'Empty')])
    size = IntegerField(label=_l('Size (KB)'))
    format_partition = BooleanField(label=_l('Format'))

class SelectClientForm(FlaskForm):
    ips = HiddenField()
    selected_client = SelectField(label=_l('Select one client as reference to '
                                           'define the partition scheme'))
    ok = SubmitField(label=_l('Ok'))

class SetupForm(FlaskForm):
    ips = HiddenField()
    disk = HiddenField()
    disk_type = SelectField(label=_l('Type'),
                            choices=[('MSDOS', 'MBR'),
                                     ('GPT', 'GPT')])
    partitions = FieldList(FormField(PartitionForm),
                           min_entries=1,
                           max_entries=10)

class HardwareForm(FlaskForm):
    ips = HiddenField()
    refresh = SubmitField(label=_l('Refresh'))

class SoftwareForm(FlaskForm):
    ips = HiddenField()
    os = SelectField(label=_l('Partition'), choices=[])
    view = SubmitField(label=_l('View'))
    update = SubmitField(label=_l('Update'))

class SessionForm(FlaskForm):
    ips = HiddenField()
    os = RadioField(label=_l('Session'), choices=[])
    run = SubmitField(label=_l('Run'))

class ImageRestoreForm(FlaskForm):
    ips = HiddenField()
    partition = SelectField(label=_l('Partition'), choices=[])
    image = SelectField(label=_l('Image'), choices=[])
    method = SelectField(label=_l('Method'),
                         choices=[('TIPTORRENT', 'TIPTORRENT')])
    restore = SubmitField(label=_l('Restore'))

class ClientDetailsForm(FlaskForm):
    server = HiddenField()
    name = StringField(label=_l('Name'))
    ip = StringField(label=_l('IP'))
    mac = StringField(label=_l('MAC'))
    serial_number = StringField(label=_l('Serial Number'))
    netmask = StringField(label=_l('Netmask'))
    livedir = SelectField(label=_l('ogLive'),
                          choices=[('ogLive', 'Default'),])
    remote = BooleanField(label=_l('Remote'))
    maintenance = BooleanField(label=_l('Maintenance'))
    netiface = SelectField(label=_l('Interface'),
                           choices=[('eth0', 'eth0'),
                                    ('eth1', 'eth1'),
                                    ('eth2', 'eth2')])
    netdriver = SelectField(label=_l('Driver'),
                            choices=[('generic', 'generic')])
    repo = SelectField(label=_l('Repository'),
                       choices=[(1, 'Default')])
    room = SelectField(label=_l('Room'))
    boot = SelectField(label=_l('Boot Mode'))
    create = SubmitField(label=_l('Create'))

class ImportClientsForm(FlaskForm):
    server = HiddenField()
    room = SelectField(label=_l('Room'))
    dhcpd_conf = TextAreaField(label=_l('dhcpd configuration'))
    import_btn = SubmitField(label=_l('Import'))

class BootModeForm(FlaskForm):
    ips = HiddenField()
    boot = SelectField(label=_l('Boot mode'))
    ok = SubmitField(label=_l('Ok'))

class OgliveForm(FlaskForm):
    ips = HiddenField()
    oglive = SelectField(label=_l('ogLive'))
    ok = SubmitField(label=_l('Ok'))

class ImageCreateForm(FlaskForm):
    ip = HiddenField()
    os = SelectField(label=_l('Partition'), choices=[])
    name = StringField(label=_l('Image name'),
                       validators=[InputRequired()])
    description = StringField(label=_l('Description'))
    repository = SelectField(label=_l('Repository'), choices=[],
                             validators=[InputRequired()])
    create = SubmitField(label=_l('Create'))


class ImageUpdateForm(FlaskForm):
    ip = HiddenField()
    os = SelectField(label=_l('Partition'), choices=[])
    image = SelectField(label=_l('Image'), choices=[])
    update = SubmitField(label=_l('Update'))


class CenterForm(FlaskForm):
    server = SelectField(label=_l('Server'),
                         validators=[InputRequired()])
    name = StringField(label=_l('Center name'),
                       validators=[InputRequired()])
    comment = StringField(label=_l('Comment'))
    submit = SubmitField(label=_l('Submit'))

class DeleteCenterForm(FlaskForm):
    server = HiddenField()
    center = SelectField(label=_l('Center'),
                         validators=[InputRequired()])
    submit = SubmitField(label=_l('Submit'))

class RoomForm(FlaskForm):
    server = HiddenField()
    center = SelectField(label=_l('Center'),
                         validators=[InputRequired()])
    name = StringField(label=_l('Room name'),
                       validators=[InputRequired()])
    netmask = StringField(label=_l('Netmask'),
                          validators=[InputRequired()])
    submit = SubmitField(label=_l('Submit'))

class DeleteRoomForm(FlaskForm):
    server = HiddenField()
    room = SelectField(label=_l('Room'),
                       validators=[InputRequired()])
    submit = SubmitField(label=_l('Submit'))

class ImageDetailsForm(FlaskForm):
    id = StringField(label=_l('Id'))
    name = StringField(label=_l('Name'))
    size = DecimalField(label=_l('Size (GiB)'))
    datasize = DecimalField(label=_l('Datasize (GiB)'))
    modified = StringField(label=_l('Modified'))
    permissions = StringField(label=_l('Permissions'))
    software_id = StringField(label=_l('Software id'))

class RepositoryForm(FlaskForm):
    name = StringField(label=_l('Name'),
                       validators=[InputRequired()])
    ip = StringField(label=_l('IP'),
                     validators=[InputRequired()])
    submit = SubmitField(label=_l('Submit'))

class DeleteRepositoryForm(FlaskForm):
    repository = SelectField(label=_l('Repository'),
                             validators=[InputRequired()])
    submit = SubmitField(label=_l('Submit'))
