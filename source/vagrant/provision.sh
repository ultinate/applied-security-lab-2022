sudo apt update -y
sudo apt upgrade -y
sudo apt install -y --no-install-recommends virtualbox-guest-dkms virtualbox-guest-utils virtualbox-guest-x11 ca-certificates
sudo mkdir -p /mnt/hsm
sudo mv /tmp/ca_root.cert.pem /mnt/hsm/
sudo cp /mnt/hsm/ca_root.cert.pem /usr/local/share/ca-certificates/imovies_root_ca.crt  # must have .crt extension
sudo update-ca-certificates


echo "IPtables Accept all during provisioning"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F

# Fix multipath key error for VBOX hdd.
grep "VBOX" /etc/multipath.conf || cat <<EOF | sudo tee -a /etc/multipath.conf
blacklist {
  device {
    vendor "VBOX"
    product "HARDDISK"
  }
}
EOF
sudo systemctl restart multipathd
