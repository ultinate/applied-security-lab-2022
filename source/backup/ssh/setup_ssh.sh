#!/bin/bash

### Configure SSH ##
mv /tmp/ssh/sshd_config /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# Test the config
echo "Testing the ssh config"
sshd -t

echo "Setup admin user"
mkdir -p /home/admin/.ssh
sudo chown -R admin:nogroup /home/admin/.ssh/

echo "Add some data for the admin user"
mkdir -p /home/admin/data
sudo chown -R admin:nogroup  /home/admin/data
sudo chmod 644 /home/admin/data

echo "Add ssh keys for sysadmin"
mkdir -p /home/sysadmin/.ssh
cat /tmp/id_sysadmin.pub >>/home/sysadmin/.ssh/authorized_keys
sudo chown -R sysadmin:sysadmin /home/sysadmin/.ssh
sudo chmod 700 /home/sysadmin/.ssh
sudo chmod 600 /home/sysadmin/.ssh/authorized_keys

echo "Restarting the ssh service"
sudo systemctl restart sshd
sudo systemctl status sshd

echo "Provisioning sysadmin credentials"
mv /tmp/ssh_credentials /home/vagrant/.ssh/
sudo chmod 600 /home/vagrant/.ssh/ssh_credentials/id_*_sysadmin
rm -r /tmp/ssh_credentials

# install ssh config
echo "Configuring ssh client"
mv /tmp/ssh/ssh_config /home/vagrant/.ssh/config

echo "Done with SSH"
