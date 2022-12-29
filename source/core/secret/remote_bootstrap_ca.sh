#!/bin/bash
# set -x
echo "###########################"
echo "#### Bootstraping CA  #####"
echo "###########################"

# hay que ver que hacia el viejo script y como esta la vm ahora. y replicar los archivos
# donde van con los mismos permisos que tienen ahora.
INSTALL_DIR="/usr/local/core"
CA_DIR=$INSTALL_DIR/work

# mv from tmp vagrant provisioned to the actual CA_DIR
mkdir -p $CA_DIR
mv /tmp/secret/work $INSTALL_DIR/

#root cert permissions
chmod 400 $CA_DIR/private/ca_root.key.pem
chmod 444 $CA_DIR/ca_root.cert.pem
rm -f $CA_DIR/private/ca_root.key.pem
rm -f $CA_KEY_PASSPHRASE_FILE

#intermediate user directory
INTERMEDIATE_USR_DIR=$CA_DIR/intermediate_usr
chmod 700 $INTERMEDIATE_USR_DIR/private
chmod 400 $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem
chmod 444 $INTERMEDIATE_USR_DIR/ca_intermediate_usr.cert.pem
chmod 444 $INTERMEDIATE_USR_DIR/ca-chain_usr.cert.pem
mkdir -p $INTERMEDIATE_USR_DIR/newcerts

#intermediate server certificate
INTERMEDIATE_SERV_DIR=$CA_DIR/intermediate_serv
chmod 700 $INTERMEDIATE_SERV_DIR/private
chmod 400 $INTERMEDIATE_SERV_DIR/private/ca_intermediate_serv.key.pem
chmod 444 $INTERMEDIATE_SERV_DIR/ca_intermediate_serv.cert.pem
chmod 444 $INTERMEDIATE_SERV_DIR/ca-chain_serv.cert.pem

# Move Intermediate CA private keys to simulated HSM
# Populate passphrases too.
HSM_DIR=/mnt/hsm
mv /tmp/secret/intermediate_srv_passphrase.txt $HSM_DIR
mv /tmp/secret/intermediate_usr_passphrase.txt $HSM_DIR
sudo mv $INTERMEDIATE_SERV_DIR/private/ca_intermediate_serv.key.pem $HSM_DIR
sudo mv $INTERMEDIATE_USR_DIR/private/ca_intermediate_usr.key.pem $HSM_DIR

sudo chown -R gunicorn:www-data  /mnt/hsm/

# Static CRLs
# TODO

# Server certs
for DOMAIN in core.imovies.ch database.imovies.ch imovies.ch backup.imovies.ch
do
  chmod 400 $INTERMEDIATE_SERV_DIR/private/$DOMAIN.key.pem
  chmod 444 $INTERMEDIATE_SERV_DIR/certs/$DOMAIN.cert.pem
done
