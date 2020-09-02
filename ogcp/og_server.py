import requests
import json

class OGServer:
    def __init__(self, ip='127.0.0.1', port=8888, api_token=""):
        self.ip = ip
        self.port = port
        self.api_token = api_token
        self._prepare_requests()

    def load_config(self, path):
        with open(path, 'r') as f:
            cfg = json.load(f)

        self.ip = cfg['ip']
        self.port = cfg['port']
        self.api_token = cfg['api_token']
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
