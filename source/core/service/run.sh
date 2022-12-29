#!/bin/bash

# Setup and start flask app
INSTALL_DIR=/usr/local/core
cd $INSTALL_DIR

python3 -m venv env
source env/bin/activate
pip install -r app/requirements.txt
gunicorn -w 4 -b 127.0.0.1:7000 'app.api:app'
