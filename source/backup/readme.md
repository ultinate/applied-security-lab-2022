
# assignment.


A copy of all keys and certificates issued must be stored in an archive. The archive is intended to ensure that encrypted data is still accessible even in the case of loss of an employee’s certificate or private key, or even the employee himself.

- Backup of keys and certificates from the Core CA, databases, and configuration and logging information.
- Secrecy and integrity with respect to the private keys in the key backup. Note that the protection of the private keys on users’ computers is the responsibility of the individual users;


## Backup frequency

A cronjob is running every 12hs (twice a day) backup up all.

## Secrecy and integrity 

For now:
keys are copied using ssh, so it is encrypted on transit.
Once they arrive at the backup server they are immediately encrypted with a gpg key ensuring secrecy and integrity.

to-do: For CA certs, we have a cronjob at core node that gpg encrypts and rsync (push) to backup. 
Pushing is safer than pulling (backup does not have access to core, but the other way round). and the keys only leave core once they are gpg encrypted.
 

## Backups rotation.

To avoid filling up the disk. Files older than 45 days are being deleted every week (weekly cronjob) 



# Logs

Clients send their logs to backup.imovies.ch:2100 where a syslog-ng is listening and storing the backups on directory /var/backups/logs/{HOST}/{MONTH-YEAR}-logs file.
as this file is also inside /var/backup files older than 45 days will be removed by the backup rotation script to avoid filling up the disk.

Documentation on syslog-ng:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.37/administration-guide/11#TOPIC-1828944

to-do: implement tls:
https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.17/administration-guide/55#TOPIC-989756


```
vagrant@backup:~$ sudo find /var/backups/logs/
/var/backups/logs/backup/11-2022-logs
/var/backups/logs/core/11-2022-logs
/var/backups/logs/database/11-2022-logs
/var/backups/logs/frontend/11-2022-logs
```


# GPG


The private key stays on our repo. we don't update it.
It's meant to be stored in a secure flash device.
It is protected with the following passphrase:

"foobar123"

Yes, very secure!



# to-do:
CA push to backup instead.

## Backup
 ca
   backup all in /work except /private
   Logs
   config ()
 database
   Data
   Config
   logs
 Frontend
  logs
  Configs


### gpg cheat sheet

https://www.gnupg.org/gph/en/manual.html#AEN84
