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
sudo chown -R sysadmin:sysadmin /home/admin/.ssh/
sudo chmod 700 /home/admin/.ssh

echo "Add ssh keys for sysadmin"
mkdir -p /home/sysadmin/.ssh
cat /tmp/id_sysadmin.pub >>/home/sysadmin/.ssh/authorized_keys
sudo chown -R sysadmin:sysadmin /home/sysadmin/.ssh
sudo chmod 700 /home/sysadmin/.ssh
sudo chmod 600 /home/sysadmin/.ssh/authorized_keys

echo "Add ssh keys for jumphost"
mkdir -p /home/jumphost/.ssh
cat /tmp/id_jumphost.pub >>/home/jumphost/.ssh/authorized_keys
sudo chown -R jumphost:jumphost /home/jumphost/.ssh
sudo chmod 700 /home/jumphost/.ssh
sudo chmod 600 /home/jumphost/.ssh/authorized_keys

echo "Restarting the ssh service"
sudo systemctl restart sshd
sudo systemctl status sshd
sudo systemctl restart ssh
sudo systemctl start ssh
echo "Done with the SSH setup"
