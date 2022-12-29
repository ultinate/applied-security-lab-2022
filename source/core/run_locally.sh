#!/bin/bash
echo "I am CoreCA"

CA_DIR=./work

# Create CA
# bash service/provision_ca.sh $CA_DIR securePassphrase1 securePassphrase2 securePassphrase3 
## CA's are created already in the repo. see /secret/bootstrap_once.sh for more details


# Create python environment
python3 -m venv env
source env/bin/activate
pip install -r app/requirements.txt

touch app.log

# Start application server
gunicorn -w 4 -b 127.0.0.1:7000 'app.api:app'