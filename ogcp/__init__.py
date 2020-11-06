from flask_wtf.csrf import CSRFProtect
from flask_bootstrap import Bootstrap
from flask_babel import Babel
from flask import Flask
from os import urandom

app = Flask(__name__)
app.config.from_json('cfg/ogcp.json')
app.secret_key = urandom(16)

babel = Babel(app)
csrf = CSRFProtect(app)
bootstrap = Bootstrap(app)


import ogcp.views
