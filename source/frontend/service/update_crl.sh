#!/bin/bash
CRL_DIR=/usr/local/frontend/crl
EXEC_USER=vagrant

# get the CRL of the user CA
echo "Get user CRL"
CRL_USER="$(wget -qO- wget https://imovies.ch/intermediate_usr.crl.pem)"
if [[ $CRL_USER != *"-----BEGIN X509 CRL-----"* ]]; then
  echo "Unable to get user CRL"
  echo "ERR: $CRL_USER"
  exit
fi

# get the CRL of the root CA
echo "Get root CRL"
CRL_ROOT="$(wget -qO- wget https://imovies.ch/root.crl.pem)"
if [[ $CRL_ROOT != *"-----BEGIN X509 CRL-----"* ]]; then
  echo "Unable to get root CRL"
  echo "ERR: $CRL_ROOT"
  exit
fi

# create file (combination)
sudo printf "$CRL_ROOT\n$CRL_USER" > $CRL_DIR/tmp_intermediate_usr_combined.crl.pem

# mark as read-only
sudo chown -R $EXEC_USER:$EXEC_USER $CRL_DIR/tmp_intermediate_usr_combined.crl.pem
sudo chmod 664 $CRL_DIR/tmp_intermediate_usr_combined.crl.pem

echo "Move files"
# move the file over
sudo mv -f $CRL_DIR/tmp_intermediate_usr_combined.crl.pem $CRL_DIR/ca_intermediate_usr_combined.crl.pem

# remove tmp file
sudo rm -f $CRL_DIR/tmp_intermediate_usr_combined.crl.pem

echo "Reload config"
# reload ngnix
sudo /etc/init.d/nginx reload
