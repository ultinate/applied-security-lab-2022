# Certificate Authority Project (Applied Security Lab)

Date: Autumn Semester 2022

Group name: #2

Group members: Clemens Klopfstein, Nicolas Kowenski, Jasmin Stadler, Nathanael Wettstein


## Documentation
The source code of the primary group work is located in  `/source`. Each VM has its own sub-folder (`core`, `frontend`, etc.) with a `README.md` file.

For a comprehensive system description, find the system description and the corresponding presentation in the `/docs` folder. 

## Security Note
Some secrets were left in the repository (such as API keys) to facilitate local testing. DO NOT use these in any production envorinment.

## Hints for implementation
Python:
  * Official documentation, https://docs.python.org/3
  * Virtual environment, https://docs.python.org/3/library/venv.html
  * Black style guide, https://github.com/psf/black
  * Flask, https://flask.palletsprojects.com/
  * Flask Guide, https://dev.to/pratap2210/beginners-guide-to-setting-up-and-running-flask-web-server-1710
  * Django, https://www.djangoproject.com/
  * Crypto Library, https://www.pycryptodome.org/ (Alternative: https://pypi.org/project/cryptography/)
  * Requests Library for HTTP(s) requests, https://pypi.org/project/requests/

CSS: 
  * https://getbootstrap.com/docs/3.4/css/
  * https://milligram.io/

Crypto:
  * Guide on how to use OpenSSL, https://openssl-ca.readthedocs.io/en/latest/index.html
  * Book, chapter _7.5 Running a Certificate Authority_ to implement CA
  * For configuring to client-side TLS (mTLS), see Book, chapter _7.6 Certificate-Based Client Authentication_
 
Hardening guides and configs:
  * OWASP Top 10, https://owasp.org/Top10/
  * CIS Benchmarks, https://www.cisecurity.org/benchmark
  * CIS Benchmark scripts, https://github.com/konstruktoid/hardening/tree/master/scripts
  * CIS Benchmark image, https://github.com/alivx/CIS-Ubuntu-20.04-Ansible
  * TLS configs for Apache, nginx, MySQL, etc. https://ssl-config.mozilla.org
  * Rsync config, https://docs.rockylinux.org/books/learning_rsync/05_rsync_authentication-free_login/
  
  
