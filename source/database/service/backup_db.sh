#!/bin/bash
SYSADMIN=sysadmin
BACKUP_SCRIP_DIR=/usr/local/$SYSADMIN/scripts
BACKUP_FILE_LOCATION=/usr/local/$SYSADMIN/backup
FILENAME=$(date +"%Y%m%dT%H%M")

# dump the data
mysqldump -u backup imovies --no-tablespaces  > $BACKUP_SCRIP_DIR/${FILENAME}_backup.sql

# tar the file
tar -czf $BACKUP_SCRIP_DIR/${FILENAME}_data.tar.gz $BACKUP_SCRIP_DIR/${FILENAME}_backup.sql --remove-files

# encrypt
sudo gpg --trust-model always --yes --output $BACKUP_SCRIP_DIR/${FILENAME}_data.gpg --encrypt --recipient 6C4B8D812D04F99CEAE28D2DBE6E7C7EDBBAD045 $BACKUP_SCRIP_DIR/${FILENAME}_data.tar.gz

# change the file permissions
sudo chown -R backup:$SYSADMIN $BACKUP_SCRIP_DIR/${FILENAME}_data.tar.gz
sudo chmod 444 $BACKUP_SCRIP_DIR/${FILENAME}_data.tar.gz

# move the file over
mv -f $BACKUP_SCRIP_DIR/${FILENAME}_data.tar.gz $BACKUP_FILE_LOCATION/${FILENAME}_data.tar.gz

