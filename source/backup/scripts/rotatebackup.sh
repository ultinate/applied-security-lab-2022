#!/usr/bin/bash
BACKUP_RDAYS=45
TAMPER_RDAYS=15
BACKUP_DATA="/var/backups"
TAMPER_DATA="/var/backups/tamper"
sudo find $BACKUP_DATA -type f -atime +$BACKUP_RDAYS -delete
sudo find $TAMPER_DATA -type f -atime +$TAMPER_RDAYS -delete >> /var/backups/tamper/rotated.log
