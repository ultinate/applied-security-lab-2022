#!/bin/bash

# Setup and start flask app
INSTALL_DIR=/usr/local/database
cd $INSTALL_DIR

python3 -m venv env
source env/bin/activate
pip install -r app/requirements.txt

# Setup key
export SECRET_KEY=$(python -c 'from Crypto import Random; print(Random.get_random_bytes(16).hex())')
gunicorn -w 4 -b 127.0.0.1:6000 'app.api:app'
