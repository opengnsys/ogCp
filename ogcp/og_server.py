# Copyright (C) 2020-2021 Soleta Networks <info@soleta.eu>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

from ogcp import app

import requests
import json

class OGServer:
    def __init__(self, ip=app.config['IP'],
                 port=app.config['PORT'],
                 api_token=app.config['API_TOKEN']):
        self.ip = ip
        self.port = port
        self.api_token = api_token
        self._prepare_requests()

    def _prepare_requests(self):
        self.URL = f'http://{self.ip}:{self.port}'
        self.HEADERS = {'Authorization' : self.api_token}

    def get(self, path, payload=None):
        r = requests.get(f'{self.URL}{path}',
                         headers=self.HEADERS,
                         json=payload)
        return r

    def post(self, path, payload):
        r = requests.post(f'{self.URL}{path}',
                          headers=self.HEADERS,
                          json=payload)
        return r
