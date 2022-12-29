#!/usr/bin/bash

BACKUP_DATA="/var/backups"
DATE=$(date +"%d-%m-%Y")
DAILY_DIR=$BACKUP_DATA/$DATE

DB_BACKUPMAKER=sysadmin

echo "Start CFG"
# Backup configs and create target dirs for core frontend and db.
for HOST in core frontend db
do
  echo "Working on $HOST"
  mkdir -p "$DAILY_DIR/$HOST/configs"
  rsync -a --log-file=$DAILY_DIR/$HOST/log-$HOST.log $HOST.imovies.ch:/etc/nginx/sites-enabled/default $DAILY_DIR/$HOST/configs/nginx
done

echo "Frontend"
# FRONTEND
rsync -a --log-file=$DAILY_DIR/frontend/log-frontend.log frontend.imovies.ch:/usr/local/frontend/run.sh $DAILY_DIR/frontend/

echo "Database"
# DATABASE
rsync -a --log-file=$DAILY_DIR/db/log-db.log database.imovies.ch:/usr/local/database/run.sh $DAILY_DIR/db/
rsync -a --log-file=$DAILY_DIR/db/log-db.log database.imovies.ch:/usr/local/$DB_BACKUPMAKER/backup/ $DAILY_DIR/db/data/

echo "Core"
# CORE
mkdir -p $DAILY_DIR/core/sensitive
rsync -a --rsync-path="sudo rsync" --log-file=$DAILY_DIR/core/log-core.log core.imovies.ch:/usr/local/core/work $DAILY_DIR/core/sensitive/
rsync -a --rsync-path="sudo rsync" --log-file=$DAILY_DIR/core/log-core.log core.imovies.ch:/mnt/hsm $DAILY_DIR/core/sensitive/
rsync -a --log-file=$DAILY_DIR/core/log-core.log core.imovies.ch:/usr/local/core/run.sh $DAILY_DIR/core/

echo "Packing data"
## CORE - Sensitive - convert dir into a directory and deltes the originals
tar -czf $DAILY_DIR/core/private.tar.gz $DAILY_DIR/core/sensitive/ --remove-files
## Ensure secrecy and integrity
sudo gpg --trust-model always --yes --output $DAILY_DIR/core/private.gpg --encrypt --recipient 6C4B8D812D04F99CEAE28D2DBE6E7C7EDBBAD045 $DAILY_DIR/core/private.tar.gz
rm $DAILY_DIR/core/private.tar.gz

echo "Done with the backup"
