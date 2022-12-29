#!/bin/bash
# Set up core machine
#
# Arguments:
#   $1: password for Root CA private key
#   $2: password for one Intermediate CA private key
#   $3: password for other Intermediate CA private key

# set -x
echo "I am CoreCA"

grep "cert" /etc/hosts || echo "192.168.56.101 imovies.ch cert.imovies.ch
192.168.56.102 database.imovies.ch
192.168.56.103 core.imovies.ch
192.168.56.104 backup.imovies.ch" | sudo tee -a /etc/hosts

INSTALL_DIR="/usr/local/core"
CA_DIR=$INSTALL_DIR/work
SYSADMIN=sysadmin
GUNICORN_USER=gunicorn
GUNICORN_GROUP=www-data

### Create users ###
# create the core user (non-privileged)
sudo adduser --disabled-login --gecos "" core
sudo chown -R core:core /home/core/
sudo chmod 700 /home/core/

# create the user SysAdmin
sudo adduser --disabled-login --gecos "" $SYSADMIN
sudo usermod -aG sudo $SYSADMIN
sudo chown -R $SYSADMIN:$SYSADMIN /home/$SYSADMIN/
sudo chmod 700 /home/$SYSADMIN/
sudo grep "$SYSADMIN" /etc/sudoers || echo "$SYSADMIN ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers

# create user gunicorn
sudo adduser --disabled-login $GUNICORN_USER --gecos "" --ingroup $GUNICORN_GROUP

# Move certs
sudo mkdir -p /mnt/hsm
sudo mv /tmp/core.imovies.ch.chained.cert.pem /mnt/hsm/
sudo mv /tmp/core.imovies.ch.key.pem /mnt/hsm/

# Set all files to 444 in /mnt/hsm/
sudo chown -R $SYSADMIN:$SYSADMIN /mnt/hsm/
sudo chmod -R 444 /mnt/hsm/
sudo chmod 555 /mnt/hsm/

# set the permission of the private key
sudo chown -R root:root /mnt/hsm/core.imovies.ch.key.pem
sudo chmod 600 /mnt/hsm/core.imovies.ch.key.pem

# set the ownership of the intermediate private key & passphrase
sudo chown $GUNICORN_USER:$GUNICORN_USER /mnt/hsm/intermediate_srv_passphrase.txt
sudo chown $GUNICORN_USER:$GUNICORN_USER /mnt/hsm/intermediate_usr_passphrase.txt
sudo chown $GUNICORN_USER:$GUNICORN_USER /mnt/hsm/ca_intermediate_serv.key.pem
sudo chown $GUNICORN_USER:$GUNICORN_USER /mnt/hsm/ca_intermediate_usr.key.pem

# set accessibility on private key & passphrase
sudo chmod 600 /mnt/hsm/intermediate_srv_passphrase.txt
sudo chmod 600 /mnt/hsm/intermediate_usr_passphrase.txt
sudo chmod 600 /mnt/hsm/ca_intermediate_serv.key.pem
sudo chmod 600 /mnt/hsm/ca_intermediate_usr.key.pem


# special configuration for ip tables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

# Install dependencies
sudo apt install -y openssl python3 python3.8-venv nginx

# add ssh access
echo "Setup SSH"
bash /tmp/ssh/setup_ssh.sh
rm -rf /tmp/ssh

# Move the provisioned /app folder by vagrant in /tmp/core to the proper place.
sudo rm -rf $INSTALL_DIR/
sudo mkdir -p $INSTALL_DIR/
sudo mv /tmp/app $INSTALL_DIR/
chown -R $GUNICORN_USER:$SYSADMIN $INSTALL_DIR/

# Move API key to right place
mv /tmp/core_api_key $INSTALL_DIR/api_keys
chown $GUNICORN_USER:$SYSADMIN $INSTALL_DIR/api_keys
chmod 400 $INSTALL_DIR/api_keys

# configure the log file
sudo rm -f $INSTALL_DIR/app.log
touch $INSTALL_DIR/app.log
chown $GUNICORN_USER:$SYSADMIN $INSTALL_DIR/app.log
chmod 640 $INSTALL_DIR/app.log
sudo chattr +a $INSTALL_DIR/app.log

# configure the application directory
chown $GUNICORN_USER:$SYSADMIN $INSTALL_DIR/app/
chmod 570 $INSTALL_DIR/app/

# Create CA
sudo /tmp/secret/remote_bootstrap_ca.sh # ATTENTI!! at end we remove the secret folder

# Set up the app service to run on startup
sudo mv /tmp/service/run.sh $INSTALL_DIR/
sudo mv /tmp/service/core-app.service /etc/systemd/system/
sudo chown -R $GUNICORN_USER:$GUNICORN_GROUP /usr/local/core
chmod 644 /etc/systemd/system/core-app.service
systemctl enable core-app.service
systemctl restart core-app

# set the permissions of the run script
sudo chown $GUNICORN_USER:$ADMIN_USER $INSTALL_DIR/run.sh
sudo chmod 700 $INSTALL_DIR/run.sh

# Set up NGINX
sudo mv /tmp/service/nginx-default /etc/nginx/sites-enabled/default
service nginx restart

# change log permission
sudo chmod 660 /var/log/nginx/ssl-error.log
sudo chmod 660 /var/log/nginx/ssl-access.log

# Logs
sudo apt install -y syslog-ng
sudo cp /tmp/syslog/syslog-$HOSTNAME.conf /etc/syslog-ng/syslog-ng.conf
sudo systemctl start syslog-ng
sudo systemctl enable syslog-ng
sudo syslog-ng-ctl reload

# copy firewall script
sudo mv /tmp/service/iptables.sh /tmp/iptables.sh

echo "START Show status"
systemctl status core-app
service nginx status
echo "DONE Show status"

# Clean up
rm -rf /tmp/app
rm -rf /tmp/service
rm -rf /tmp/secret
rm -rf /tmp/syslog

echo "Sleep 60 sec for the application to start in the background"
for i in {1..60}; do
  sleep 1
  echo "Now waiting for $i / 60"
done

# Set up firewall
echo "START Writing IP tables"
sudo bash /tmp/iptables.sh
rm -f /tmp/iptables.sh
echo "DONE Writing IP tables"
