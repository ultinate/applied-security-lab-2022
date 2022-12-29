echo "I am frontend"
# set -x

INSTALL_DIR="/usr/local/frontend"
SYSADMIN=sysadmin
ADMIN_USER=$SYSADMIN
### Create users ###
# create the frontend user (non-privileged)
sudo adduser --disabled-login --gecos "" frontend
sudo chown -R frontend:frontend /home/frontend/
sudo chmod 700 /home/frontend/

# create the user SysAdmin
sudo adduser --disabled-login --gecos "" $SYSADMIN
sudo usermod -aG sudo $SYSADMIN
sudo chown -R $SYSADMIN:$SYSADMIN /home/$SYSADMIN/
sudo chmod 700 /home/$SYSADMIN/
sudo grep "$SYSADMIN" /etc/sudoers || echo "$SYSADMIN ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers

# create the jumphost user
sudo adduser --disabled-login --gecos "" jumphost
sudo usermod -G nogroup jumphost
sudo chown -R jumphost:nogroup /home/jumphost/
sudo chmod 700 /home/jumphost/

# create the user admin
sudo adduser --disabled-password --gecos "" admin --ingroup nogroup
echo admin:admin | chpasswd
sudo chown -R admin:nogroup /home/admin/
sudo chmod 700 /home/admin/

# add ssh access
echo "Setup SSH"
bash /tmp/ssh/setup_ssh.sh
rm -rf /tmp/ssh

# Move certs and keys
sudo mkdir -p /mnt/hsm
sudo mv /tmp/imovies.ch.chained.cert.pem /mnt/hsm/
sudo mv /tmp/imovies.ch.key.pem /mnt/hsm/
sudo mv /tmp/cert.imovies.ch.chained.cert.pem /mnt/hsm/
sudo mv /tmp/cert.imovies.ch.key.pem /mnt/hsm/
sudo mv /tmp/ca_intermediate_usr.cert.pem /mnt/hsm/
sudo mv /tmp/ca-chain_usr.cert.pem /mnt/hsm/

# Set all files to 444 in /mnt/hsm/
sudo chown -R $SYSADMIN:$SYSADMIN /mnt/hsm/
sudo chmod -R 444 /mnt/hsm/
sudo chmod 555 /mnt/hsm/

# set the permission of the private key
sudo chown -R root:root /mnt/hsm/imovies.ch.key.pem
sudo chown -R root:root /mnt/hsm/cert.imovies.ch.key.pem
sudo chmod 600 /mnt/hsm/imovies.ch.key.pem
sudo chmod 600 /mnt/hsm/cert.imovies.ch.key.pem

# special configuration for ip tables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

# Install dependencies
sudo apt install -y python3 python3.8-venv nginx

grep "cert" /etc/hosts || echo "192.168.57.101 imovies.ch cert.imovies.ch
192.168.56.102 database.imovies.ch
192.168.56.103 core.imovies.ch
192.168.56.104 backup.imovies.ch" | sudo tee -a /etc/hosts

# Move the provisioned /app folder by vagrant to the proper place.
sudo rm -rf $INSTALL_DIR/
sudo mkdir -p $INSTALL_DIR/
sudo mv /tmp/app $INSTALL_DIR/

chown -R frontend:$ADMIN_USER $INSTALL_DIR/

# Move API keys to right place
mv /tmp/db_api_key $INSTALL_DIR/db_api_key
mv /tmp/core_api_key $INSTALL_DIR/core_api_key
chown frontend:frontend $INSTALL_DIR/db_api_key
chown frontend:frontend $INSTALL_DIR/core_api_key
chmod 400 $INSTALL_DIR/db_api_key
chmod 400 $INSTALL_DIR/core_api_key

# configure the log file
sudo rm -f $INSTALL_DIR/app.log
touch $INSTALL_DIR/app.log
chown frontend:$SYSADMIN $INSTALL_DIR/app.log
chmod 640 $INSTALL_DIR/app.log
sudo chattr +a $INSTALL_DIR/app.log

# configure the application directory
chown frontend:$SYSADMIN $INSTALL_DIR/app.log
chmod 570 $INSTALL_DIR/app/

# Set up the app service to run on startup
sudo mv /tmp/service/run.sh $INSTALL_DIR/
sudo mv /tmp/service/frontend-app.service /etc/systemd/system/
chown frontend:$ADMIN_USER /etc/systemd/system/frontend-app.service
chmod 644 /etc/systemd/system/frontend-app.service
systemctl enable frontend-app.service
systemctl restart frontend-app

# set the permissions of the run script
sudo chown frontend:$ADMIN_USER $INSTALL_DIR/run.sh
sudo chmod 700 $INSTALL_DIR/run.sh

## Setup crl
# create directory for the crl
mkdir -p /usr/local/frontend/crl
sudo chown -R $ADMIN_USER:$ADMIN_USER /usr/local/frontend/crl
# move the "empty" CRL to the directory
mv /tmp/ca_intermediate_usr_combined.crl.pem /usr/local/frontend/crl/ca_intermediate_usr_combined.crl.pem # Empty initial CRL. Must be updated later.
sudo chown -R $ADMIN_USER:$ADMIN_USER /usr/local/frontend/crl/ca_intermediate_usr_combined.crl.pem
chmod 664 /usr/local/frontend/crl/ca_intermediate_usr_combined.crl.pem

# Place files for psychic backdoor (must be executed manually)
sudo mv /tmp/psychic-signature/compile-nginx.sh /home/vagrant/
sudo mv /tmp/psychic-signature/openssl-psychic.patch /home/vagrant/

# Set up NGINX
sudo mv /tmp/service/error.html /var/www/html/error.html
sudo mv /tmp/service/nginx.conf /etc/nginx/nginx.conf
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
systemctl status frontend-app
service nginx status
echo "DONE Show status"

echo "Sleep 60 sec for the application to start in the background"
for i in {1..60}; do
  sleep 1
  echo "Now waiting for $i / 60"
done

## Setup CRL fetcher
# copy script
sudo mv /tmp/service/update_crl.sh $INSTALL_DIR/
sudo chown -R $ADMIN_USER:$ADMIN_USER $INSTALL_DIR/update_crl.sh
sudo chmod 740 $INSTALL_DIR/update_crl.sh

su -c "bash $INSTALL_DIR/update_crl.sh" $ADMIN_USER
# register job
su - $ADMIN_USER -c "(crontab -l ; echo '*/5 * * * * $INSTALL_DIR/update_crl.sh') | crontab -"

# Clean up
rm -rf /tmp/app
rm -rf /tmp/service
rm -rf /tmp/syslog
rm -rf /tmp/psychic-signature

# Set up firewall
echo "START Writing IP tables"
service iptables start
echo "Started service iptables"
sudo bash /tmp/iptables.sh
rm -f /tmp/iptables.sh
echo "DONE Writing IP tables"
