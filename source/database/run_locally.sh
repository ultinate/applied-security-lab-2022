#!/bin/bash
set -x
echo "I am Database"

# Set up the mysql server to run on startup
sudo update-rc.d mysql defaults
service mysql status

# start DB server
sudo systemctl start mysql.service

# ensure that the database does not exist
echo 'DROP DATABASE IF EXISTS imovies;' | sudo mysql -uroot -ppassword

# populate the database
echo 'CREATE DATABASE imovies;' | sudo mysql -uroot -ppassword
sudo mysql -uroot -ppassword imovies <data/imovies_users.dump

# run the additional setup
sudo mysql -uroot -ppassword imovies <data/db_additional_setup.sql

# Create python environment
python3 -m venv env
source env/bin/activate
pip install -r app/requirements.txt

touch app.log

# Start application server
export SECRET_KEY=$(python -c 'from Crypto import Random; print(b"\xfa\x86\n\x0e\x186\x1b\xc9\xa8\x14\xc41.\xc0#\xc0".hex())')
gunicorn -w 4 -b 127.0.0.1:6000 'app.api:app'
