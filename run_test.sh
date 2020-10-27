#! /bin/bash

pip3 install -r requirements.txt
export FLASK_APP=ogcp
export FLASK_ENV=development
flask run
