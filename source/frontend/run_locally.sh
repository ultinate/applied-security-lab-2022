#!/bin/bash
echo "I am Frontend"

# Create python environment
python3 -m venv env
source env/bin/activate
pip install -r app/requirements.txt

# Start application server
touch app.log
export SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex())')
export SECRET_CAPTCHA_KEY=$(python -c 'import secrets; print(secrets.token_hex())')
export IS_LOCAL_TESTING=1
gunicorn -w 4 -b 127.0.0.1:5000 'app.app:app'
