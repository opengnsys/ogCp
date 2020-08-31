import json

class OGServer:
    def __init__(self, ip='127.0.0.1', port=8888, api_token=""):
        self.ip = ip
        self.port = port
        self.api_token = api_token

    def load_config(self, path):
        with open(path, 'r') as f:
            cfg = json.load(f)

        self.ip = cfg['ip']
        self.port = cfg['port']
        self.api_token = cfg['api_token']
