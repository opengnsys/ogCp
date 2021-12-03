# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, username, scopes):
        self.id = username
        self.scopes = scopes
