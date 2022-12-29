# Leftover SSH acccess
A 'configuration error' left the user `admin` with the password `admin`in the frontend and the backup.

Difficulty to find:
  * Blackbox approach: medium
  * Whitebox approach: easy

## How to exploit
1. The `admin` account has to be found and the password `admin` has to be guessed. Altough this involves some guessing work, this combination is often used in testing and therefore reasonable to guess.
2. Connect to the frontend / jumphost with `ssh admin@imovies.ch` and use the password `admin`.
3. Using the account, the frontend can be inspected and the IP or domain of the backup can be found in `/etc/hosts`
4. Connect to the backup using the frontend as a jumphost: `ssh -J admin@imovies.ch admin@backup.imovies.ch`
   1. Alternatively, a session from the frontend can be directly established with `ssh admin@backup.imovies.ch`
5. Conveniently, a dump of the data is placed in the `data` directory that resides in the admin's home directory.



