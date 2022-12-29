echo "I am db"

#users
SYSADMIN=sysadmin
SYSUSER=database
BACKUPMAKER=$SYSADMIN

# paths
INSTALL_DIR="/usr/local/$SYSUSER"
BACKUP_SCRIP_DIR="/usr/local/$BACKUPMAKER/scripts"
BACKUP_DATA_DIR="/usr/local/$BACKUPMAKER/backup"

### Create users ###
# create the database user (non-privileged)
sudo adduser --disabled-login --gecos "" $SYSUSER
sudo chown -R $SYSUSER:$SYSUSER /home/$SYSUSER/
sudo chmod 770 /home/$SYSUSER/

# create the user SysAdmin
sudo adduser --disabled-login --gecos "" $SYSADMIN
sudo usermod -aG sudo $SYSADMIN
sudo chown -R $SYSADMIN:$SYSADMIN /home/$SYSADMIN/
sudo chmod 700 /home/$SYSADMIN/
sudo grep "$SYSADMIN" /etc/sudoers || echo "$SYSADMIN ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers

# Move certs
mkdir -p /mnt/hsm
sudo mv /tmp/database.imovies.ch.chained.cert.pem /mnt/hsm/
sudo mv /tmp/database.imovies.ch.key.pem /mnt/hsm/

# Set all files to 444 in /mnt/hsm/
sudo chown -R $SYSADMIN:$SYSADMIN /mnt/hsm/
sudo chmod -R 444 /mnt/hsm/
sudo chmod 555 /mnt/hsm/

# set the permission of the private key
sudo chown -R root:root /mnt/hsm/database.imovies.ch.key.pem
sudo chmod 600 /mnt/hsm/database.imovies.ch.key.pem

# special configuration for ip tables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

# Install dependencies
sudo apt install -y openssl python3 python3.8-venv nginx mysql-server

# Move the provisioned /app folder by vagrant in /tmp/database to the proper place.
sudo rm -rf $INSTALL_DIR/
sudo mkdir -p $INSTALL_DIR/
sudo mv /tmp/app $INSTALL_DIR/

sudo chown -R $SYSUSER:$ADMIN_USER $INSTALL_DIR/

# Set up the mysql server to run on startup
sudo update-rc.d mysql defaults

# add ssh access
echo "Setup SSH"
bash /tmp/ssh/setup_ssh.sh
rm -rf /tmp/ssh

echo "Work on the MySQL Server"
# start the server
systemctl is-active --quiet mysql.service && sudo systemctl stop mysql.service
sudo systemctl start mysql.service
echo "##### Is mysql running ok? #######"
sudo systemctl status mysql.service

echo "Get credentials"
# get the credentials for the DB
ROOT_DB_PASSWORD=$(head -n 1 /tmp/db_root_key)
WEBAPP_DB_PASSWORD=$(head -n 1 /tmp/db_webapp_key)
BACKUP_DB_PASSWORD=$(head -n 1 /tmp/db_backup_key)

# Remove tailing newline
ROOT_DB_PASSWORD=$(echo "${ROOT_DB_PASSWORD}" | tr -d '\n')
WEBAPP_DB_PASSWORD=$(echo "${WEBAPP_DB_PASSWORD}" | tr -d '\n')
BACKUP_DB_PASSWORD=$(echo "${BACKUP_DB_PASSWORD}" | tr -d '\n')

echo "Import data"
# ensure that the database does not exist
echo 'DROP DATABASE IF EXISTS imovies;' | mysql -uroot -ppassword

# populate the database
echo 'CREATE DATABASE imovies;' | mysql -uroot -ppassword
mysql -uroot -ppassword imovies </tmp/data/imovies_users.dump

# run the additional setup
mysql -uroot -ppassword imovies </tmp/data/db_additional_setup.sql

# move the msysql cfg file
#sudo mv -f /tmp/service/my.cnf /etc/mysql/my.cnf
sudo mv -f /tmp/service/my.cnf /etc/my.cnf

# Change passwords of the DB
echo "ALTER USER  'backup'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${BACKUP_DB_PASSWORD}';" | mysql -uroot -ppassword
echo "ALTER USER  'webapp'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${WEBAPP_DB_PASSWORD}';" | mysql -uroot -ppassword
echo "rename user 'root'@'localhost' to 'sysadmin'@'localhost';ALTER USER  'sysadmin'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${ROOT_DB_PASSWORD}';flush privileges;" | mysql -uroot -ppassword

# create the config for the webapp
printf "[client]\nhost=localhost\nuser=webapp\npassword=${WEBAPP_DB_PASSWORD}\ndatabase=imovies" >"/home/$SYSUSER/.my.cnf"
sudo chown -R $SYSUSER:$SYSUSER "/home/$SYSUSER/.my.cnf"
sudo chmod 600 "/home/$SYSUSER/.my.cnf"

# Move API keys + db password to right place
mv /tmp/db_api_key $INSTALL_DIR/api_keys
sudo chown -R $SYSUSER:$SYSUSER $INSTALL_DIR/api_keys
sudo chmod 400 $INSTALL_DIR/api_keys

# configure the log file
sudo rm -f $INSTALL_DIR/app.log
touch $INSTALL_DIR/app.log
chown $SYSUSER:$SYSADMIN $INSTALL_DIR/app.log
chmod 640 $INSTALL_DIR/app.log
sudo chattr +a $INSTALL_DIR/app.log

# configure the application directory
chown $SYSUSER:$SYSADMIN $INSTALL_DIR/app/
chmod 570 $INSTALL_DIR/app/

# Set up the app service to run on startup
sudo mv /tmp/service/run.sh $INSTALL_DIR/
sudo mv /tmp/service/database-app.service /etc/systemd/system/
chown $SYSUSER:$SYSADMIN /etc/systemd/system/database-app.service
chmod 644 /etc/systemd/system/database-app.service
systemctl enable database-app.service
systemctl restart database-app

# set the permissions of the run script
sudo chown $SYSUSER:$SYSADMIN $INSTALL_DIR/run.sh
sudo chmod 700 $INSTALL_DIR/run.sh

# Set up NGINX
sudo mv /tmp/service/nginx-default /etc/nginx/sites-enabled/default
service nginx restart

# Setup backup
echo "Setup Backup scripts for $SYSADMIN"
# Clean-up
sudo rm -rf $BACKUP_SCRIP_DIR
sudo rm -rf $BACKUP_DATA_DIR
# create dir
mkdir -p $BACKUP_SCRIP_DIR
mkdir -p $BACKUP_DATA_DIR
# move files
mv /tmp/service/backup_db.sh $BACKUP_SCRIP_DIR/backup.sh

# set the db credentials for the backup
printf "[mysqldump]\nhost=localhost\nuser=backup\npassword=${BACKUP_DB_PASSWORD}" >"/home/$BACKUPMAKER/.my.cnf"
chown -R $BACKUPMAKER:$BACKUPMAKER "/home/$BACKUPMAKER/.my.cnf"
chmod 600 "/home/$BACKUPMAKER/.my.cnf"

# permissions
chown -R $BACKUPMAKER:$BACKUPMAKER $BACKUP_SCRIP_DIR
chown -R $BACKUPMAKER:$BACKUPMAKER $BACKUP_DATA_DIR

chmod 700 $BACKUP_SCRIP_DIR/backup.sh
chmod 750 $BACKUP_SCRIP_DIR/
chmod 750 $BACKUP_DATA_DIR/

grep "cert" /etc/hosts || echo "192.168.56.101 imovies.ch cert.imovies.ch
192.168.56.102 database.imovies.ch
192.168.56.103 core.imovies.ch
192.168.56.104 backup.imovies.ch" | sudo tee -a /etc/hosts

# import GPG key
gpg --import /tmp/backup.gpg
rm /tmp/backup.gpg

su - $BACKUPMAKER -c "(crontab -l ; echo '0 */6 * * * $BACKUP_SCRIP_DIR/backup.sh') | crontab -"

# Logs
sudo apt install -y syslog-ng
sudo cp /tmp/syslog/syslog-$HOSTNAME.conf /etc/syslog-ng/syslog-ng.conf
sudo systemctl start syslog-ng
sudo systemctl enable syslog-ng
sudo syslog-ng-ctl reload

# copy firewall script
sudo mv /tmp/service/iptables.sh /tmp/iptables.sh

# change log permission
sudo chmod 660 /var/log/nginx/ssl-error.log
sudo chmod 660 /var/log/nginx/ssl-access.log

echo "START Show status"
systemctl status database-app
service nginx status
echo "DONE Show status"

### Clean up ###
rm -rf /tmp/app
rm -rf /tmp/service
rm -rf /tmp/data
rm -rf /tmp/syslog

# Cleanup the credentials
rm -f /tmp/db_api_key
rm -f /tmp/db_webapp_key
rm -f /tmp/db_backup_key
rm -f /tmp/db_root_key

# remove ssh pub key
rm -f /tmp/id_sysadmin.pub

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
