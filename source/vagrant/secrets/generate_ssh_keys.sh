#!/bin/bash

echo "Working in: $(pwd)"
CREDENTIALS_DIR=./ssh_credentials

# remove the ssh dir
if [ -d "$CREDENTIALS_DIR" ]; then rm -Rf $CREDENTIALS_DIR; fi
mkdir $CREDENTIALS_DIR

for MACHINE in core database backup frontend
do
    echo "Creating credentials for $MACHINE"
    ssh-keygen -t ed25519 -f ${CREDENTIALS_DIR}/id_${MACHINE}_sysadmin -q -P "" -b 521 -C ssh_key
done

echo "Creating credentials for the jumphost"
ssh-keygen -t ed25519 -f ${CREDENTIALS_DIR}/id_jumphost -q -P "" -b 521 -C ssh_key