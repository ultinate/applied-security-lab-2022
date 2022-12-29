echo "I am Backup"

INSTALL_DIR="/usr/local/backup"
BACKUP_DATA="/var/backups"
CRON_USER="vagrant"
LOGS_DIR=$BACKUP_DATA/logs
SYSADMIN=sysadmin
SYSUSER="backup_user"

grep "cert" /etc/hosts || echo "192.168.56.101 imovies.ch cert.imovies.ch
192.168.56.102 database.imovies.ch
192.168.56.103 core.imovies.ch
192.168.56.104 backup.imovies.ch" | sudo tee -a /etc/hosts

### Create users ###
# create the backup user (non-privileged)
sudo adduser --disabled-login --gecos "" $SYSUSER
sudo chown -R $SYSUSER:$SYSUSER /home/$SYSUSER/
sudo chmod 700 /home/$SYSUSER/

# create the user SysAdmin
sudo adduser --disabled-login --gecos "" $SYSADMIN
sudo usermod -aG sudo $SYSADMIN
sudo chown -R $SYSADMIN:$SYSADMIN /home/$SYSADMIN/
sudo chmod 700 /home/$SYSADMIN/
sudo grep "$SYSADMIN" /etc/sudoers || echo "$SYSADMIN ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers

# create the user admin
mkdir /home/admin
sudo adduser --disabled-password --gecos "" admin --ingroup nogroup
echo admin:admin | chpasswd
sudo chown admin:nogroup /home/admin
sudo chmod 500 /home/admin

# add ssh access
echo "Setup SSH"
bash /tmp/ssh/setup_ssh.sh
rm -rf /tmp/ssh

# Adding the data
sudo mkdir -f /home/admin/data
sudo chown -R admin:$SYSUSER /home/admin/data/
sudo chmod 500 /home/admin/data/

# setting the permissions of the data
sudo mv /tmp/database_backup_production.sql /home/admin/data/
sudo chown admin:$SYSUSER /home/admin/data/database_backup_production.sql
sudo chmod 400 /home/admin/data/database_backup_production.sql

# ensure that the private key in /home/vagrant is not accessible to admin
sudo chmod 700 /home/vagrant

#create logs directory
mkdir -p $LOGS_DIR

# Move certs.
sudo mv /tmp/backup.imovies.ch.cert.pem /mnt/hsm/
sudo mv /tmp/backup.imovies.ch.key.pem /mnt/hsm/

# Set all files to 444 in /mnt/hsm/
sudo chown -R $SYSADMIN:$SYSADMIN /mnt/hsm/
sudo chmod -R 444 /mnt/hsm/
sudo chmod 555 /mnt/hsm/

# set the permission of the private key
sudo chown -R root:root /mnt/hsm/backup.imovies.ch.key.pem
sudo chmod 600 /mnt/hsm/backup.imovies.ch.key.pem

sudo mkdir -p $INSTALL_DIR
sudo mkdir -p $BACKUP_DATA
gpg --import /tmp/backup.gpg
rm /tmp/backup.gpg
sudo rm -r $INSTALL_DIR/scripts
sudo mv -f /tmp/scripts $INSTALL_DIR
sudo chown vagrant:vagrant -R $INSTALL_DIR
sudo chown vagrant:vagrant -R $BACKUP_DATA

#prevent others to read scripts and backups.
sudo chmod -R 0740 $INSTALL_DIR
sudo chmod -R 0740 $BACKUP_DATA

# twice a day backup all
su - $CRON_USER -c "(crontab -l ; echo '* */12 * * * $INSTALL_DIR/scripts/backup.sh') | crontab -"
# once a week rotate logs
su - $CRON_USER -c "(crontab -l ; echo '0 4 * * * $INSTALL_DIR/scripts/rotatebackup.sh') | crontab -"
# make logs tamper proof.
su - $CRON_USER -c "(crontab -l ; echo '*/5 * * * * $INSTALL_DIR/scripts/tamper.sh') | crontab -"

# Logs
sudo apt install -y syslog-ng
sudo cp /tmp/syslog/syslog-$HOSTNAME.conf /etc/syslog-ng/syslog-ng.conf
sudo systemctl start syslog-ng
sudo systemctl enable syslog-ng
sudo syslog-ng-ctl reload

# configure firewall
# special configuration for ip tables
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get -y install iptables-persistent

#cleanup
rm -rf /tmp/syslog
rm -f /tmp/database_backup_production.sql

# Set up firewall
echo "START Writing IP tables"
service iptables start
sudo bash /tmp/iptables.sh
rm -f /tmp/iptables.sh
echo "DONE Writing IP tables"
