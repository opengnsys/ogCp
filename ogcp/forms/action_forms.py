from wtforms import Form, SubmitField, HiddenField, SelectField
from flask_wtf import FlaskForm
from flask_babel import _

class WOLForm(FlaskForm):
    ips = HiddenField()
    wol_type = SelectField(label=_('Type'),
                           choices=[('broadcast', 'Broadcast'),
                                    ('unicast', 'Unicast')])
    submit = SubmitField(label=_('Submit'))
