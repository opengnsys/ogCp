from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField,
    StringField, RadioField
)
from flask_wtf import FlaskForm
from flask_babel import _

class WOLForm(FlaskForm):
    ips = HiddenField()
    wol_type = SelectField(label=_('Type'),
                           choices=[('broadcast', 'Broadcast'),
                                    ('unicast', 'Unicast')])
    submit = SubmitField(label=_('Submit'))

class PartitionForm(FlaskForm):
    ips = HiddenField()
    disk = HiddenField()
    partition = HiddenField()
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
    modify = SubmitField(label=_('Modify'))
    delete = SubmitField(label=_('Delete'))

class HardwareForm(FlaskForm):
    ips = HiddenField()
    refresh = SubmitField(label=_('Refresh'))

class SessionForm(FlaskForm):
    ips = HiddenField()
    os = RadioField(label=_('Session'), choices=[])
    run = SubmitField(label=_('Run'))

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
