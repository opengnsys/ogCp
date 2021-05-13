# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

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
