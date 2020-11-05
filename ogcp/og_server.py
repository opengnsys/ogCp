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
