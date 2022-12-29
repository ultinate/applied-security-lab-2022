echo "I am client"
sudo apt install -y --no-install-recommends ubuntu-desktop
sudo apt install -y firefox
sudo touch /usr/lib/firefox/distribution/policies.json
sudo mv /tmp/policies.json /usr/lib/firefox/distribution/

grep "cert" /etc/hosts || echo "192.168.57.101 imovies.ch cert.imovies.ch
192.168.56.102 database.imovies.ch
192.168.56.103 core.imovies.ch
192.168.56.104 backup.imovies.ch" | sudo tee -a /etc/hosts

# copy SSH keys over
rm -rf /home/vagrant/.ssh/ssh_credentials >>/dev/null
mv /tmp/ssh_credentials /home/vagrant/.ssh/ssh_credentials
sudo chmod 600 /home/vagrant/.ssh/ssh_credentials/id_*_sysadmin
sudo chmod 600 /home/vagrant/.ssh/ssh_credentials/id_jumphost
echo "Copied all SSH Keys over"

# copy user certificate for CA admin
mv /tmp/admin_user.pkcs12 /home/vagrant/admin_user.p12
mv /tmp/admin_user.pkcs12.password /home/vagrant/admin_user.p12.password

# install ssh config
mv /tmp/config /home/vagrant/.ssh/config
echo "Added the SSH config"

echo "Restart the machine now"
sudo shutdown -r now
