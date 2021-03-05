from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField,
    StringField, RadioField, PasswordField
)
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from flask_babel import _

class LoginForm(FlaskForm):
    user = StringField(
        label=_('User'),
        validators=[InputRequired()]
    )
    pwd = PasswordField(
        label=_('Password'),
        validators=[InputRequired()]
    )
    submit = SubmitField(
        label=_('Login')
    )
