from flask_babel import Babel
from flask import Flask
app = Flask(__name__)
babel = Babel(app)

import ogcp.views
