# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from wtforms import (
    Form, SubmitField, HiddenField, SelectField, BooleanField, IntegerField,
    StringField, RadioField, PasswordField, SelectMultipleField
)
from wtforms.validators import InputRequired
from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from flask_babel import _

class LoginForm(FlaskForm):
    user = StringField(
        label=_l('User'),
        validators=[InputRequired()]
    )
    pwd = PasswordField(
        label=_l('Password'),
    )
    pwd_hash = HiddenField(
        validators=[InputRequired()]
    )
    submit_btn = SubmitField(
        label=_l('Login')
    )


class UserForm(FlaskForm):
    username = StringField(
        label=_l('Username'),
        validators=[InputRequired()]
    )
    pwd = PasswordField(
        label=_l('Password'),
    )
    pwd_hash = HiddenField(
        validators=[InputRequired()]
    )
    pwd_confirm = PasswordField(
        label=_l('Repeat password'),
    )
    pwd_hash_confirm = HiddenField(
        validators=[InputRequired()]
    )
    admin = BooleanField(
        label=_l('Administrator'),
    )
    scopes = SelectMultipleField(
        label=_l('Allowed scopes'),
        description=_l('Leave this empty to give full permissions'),
    )
    submit_btn = SubmitField(
        label=_l('Submit')
    )
