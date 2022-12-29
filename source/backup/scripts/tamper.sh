#!/usr/bin/bash
set -x
DATE=$(date +"%d-%m-%Y--%H-%M-%S")
BASE_DIR="/var/backups/tamper"
TAMPER_DIR="$BASE_DIR/$DATE"
mkdir -p $TAMPER_DIR
sudo rsync -a /var/backups/logs/ $TAMPER_DIR
sudo tar -czf $BASE_DIR/$DATE.tar.gz $TAMPER_DIR --remove-files
sha512sum $BASE_DIR/$DATE.tar.gz > $BASE_DIR/$DATE.hash
sudo gpg --trust-model always --yes --output $BASE_DIR/$DATE.hash.gpg --encrypt --recipient 6C4B8D812D04F99CEAE28D2DBE6E7C7EDBBAD045 $BASE_DIR/$DATE.hash
