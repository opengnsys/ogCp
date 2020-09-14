from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField
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
