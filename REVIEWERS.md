# Notes to reviewers

## Setup
The system has been tested on VirtualBox running on Ubuntu and MacOS hosts.

To get started, power up all VMs, log into client machine ("asl-core") GUI using user `vagrant` (password: `vagrant`).

You will find application source code on each "service" machine (frontend, database, core, backup) at `/usr/local/{core|frontend|database|backup}/`. For more details, see System Description.

## CA users and CA administrators
The URL to access the web-interface is [https://imovies.ch]. It is also pre configured as the home page in firefox.

The default usernames and passwords for CA users can be found in the assignment.

A certificate and private key of the CA administrator is located in the `/home/vagrant` folder on the client machine.

## System Maintenance (remote access)
A sysadmin key (user `sysadmin`) is available and configured on the client host.
Use `ssh {frontend|database|ca_backup|core}` to access the machines.


## Credentials for 'on-site' access via console. Emulated here by starting the UI with VirtualBox.

### Frontend
Administrator: `vagrant:p1Ayk6hatK2tlMIRsY3XNWw9ioBGk8Ym`

### Core
Administrator: `vagrant:uN1umyHu1bnH90URp70HkDsO2oNMdm4N`

### Database
Administrator: `vagrant:vcs4W8Z066hcIMAUUknF4DdeQBeqc32f`

### Backup
Administrator: `vagrant:Fqh5bXDz8g1p0kdJNmejx66btiw0k6hi`


## Files stored in a bank vault:
MySQL server root user: `sysadmin:eepFmvJTmpBxCKNIxBWrwxC42MbfZSX3sYKv2WHMqrnyKmsFZ3XCmcsIAzzWMKme`

GPG private key: 

file Available on polybox: "backup-gpg.key"

CA Root private key: 
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIJnDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIuN6HQUbdDEcCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECN4D8pUoVLviBIIJSCcFL+sppN4k
z1alX5E4EXHu1LnhiRkbsj4yamWRfTpOCtJ76cLW+7MGGg6rwaahUCLU0iKbE/q9
E+9G5TXonvIylqwD4TcGdThTEU4nOzxQWi0GuCMnGIyD+OGe6DMQTy4FH0Dj71HQ
3kkG4MWOwI/6967f9R84aNVsDJHhSgO3KhtNGqheCx+DoWlwmtm6R7PzWAXoZuPE
DmFP1aVXTEHy+8muSic7p3xtGv+fa0NCuK9vfYL0V4vB7pposiTQdnLaR4htwYrF
M+tYmpvdyG59JxApQBhq0hh0e/d/3m+wVm9oU3USXATMmum1+ZwTI8N5RrQHUZfj
r+Of16+SjejvKAlgWTOXejwXm4/h+BThdd3iLaQJPYXejEIWzEhWgsKVBSnOj4p9
QGNbKSaEMFN1RRw2Ko32AE3qxkbyjo4Scs88IQ5ppGXUX5tAUGgbIkgT4lp5HWUQ
A8cuhFcHeLgUUCDXksjLO2nBAojft9Nlg0LOwAH+60fgGOsvG7JSmdElPiuKAC6W
RwkEjtnBtabOWp9M0/NW1qucNf9p6SvS+XKI1ZAISy8kqBxeqVo4xnUnTPJw3VYU
oYC5UDqvtfNgi7T+lAbTmsfhU/rvFMH5OsJOXKiXKKLJSVnDdS8EuhEcVDhWX0SX
pw0k2RUq0BbVEGxs8JO6xirBW3lEiytXZCPJxQ3737UBh8l1RRcCdxJyOu7ulm49
2eUD4+0JL41TEHSGc71nOy8BFTxlCpeojpydEAIQFlwUcdFQ0Rj+6VgzwiMlvKoo
DopoLNX2+aWl9sYSVJe80IqHKzWuifzOWvoRAxdns793tcIkbhNWjDTiL+7FnRGw
mHZ8G9Axpxd9HZdw/rzxzwFxLorNb+YGqhQSPWn/1hsKQ5yueLYhSPAkbBVt6X0q
g1jMcpB4j+lmPxInhRj76cIrYZ8QTe4DZgx8LXGt4r41dxdLKViiilOyFuHO2Anz
B8cEYLNaEj7GMW0n7s2kXOdbO7XDqKs0opPGbQlyDjeexF10K+K7NVgyF9verBwZ
bCgwsIcHYMMR0ufbpjc44d0m0AjCOLsXyb8EFX6YyibliYXGbV+jQfvq7jJo8Lvt
B46UNWnj5MQ7eSPinp+ruQ1CiR2Q8EJ9TMrVVmpQF5QIglxaZPBQ64ZU6HuKvjmi
SsfHDAjer3K9yHOYIIB4mwyZRFDH1ZCltigZxP6ZdAjZf4fgRWpKDiiGnh1g3YN4
vFk1FzXjeNDN0CyFgfnVXwdhzkyPWk3G3hrFFTTs/KF38tI57L2apoBfnWzfGcY2
R0WjfDxSfBKx2mLIBaecv8XeC06LMH7LHzBpsVpl8hT1wtCNHmW1SOiZQcElrWyq
tenzTjDyb+BjHwlCOsUbZzK/ANNmrfQMZ6Kp6UpuJfhSHfpo8eC45RljDpqs45NO
NW8fgK96HoANHOrS/CKSVcPmktcgVGkKH5YVDbcWz/Q4q0m86vsksv8g2NkppB4m
YUV4v2OusdKpqSsXGgshazZWuHO8VghBYr1Oy3pPVYEHpN6GfZzZMZQzZ4T+3MDO
GAyKsa3vaCVuSjgzrylzo27FHxdY3rAzWuXf9jNobQfymN+ZGI4bxm9NS+ULEJD2
MzSuHd+in8jCCQa6beb/KU2FpR+sSWD/VySV9L/RqIurQnBmj8UOHIE+sSo4ojuC
eTFEHlpiFHi8VI2DsGnkm2xlmI7VRQhyVeMeulUju+C+/3z3qvOOd1j1ub1Njjgh
0djZVvZmfOJ+k8eT2/l5MqnwCKmuU3wlRBllVvkSIi3ylqeIyM3QlyFgreScs4ym
xJ8XyCTxfk+V/0dC1p3Jc/EwP3/lmLpbm+i/KRyJX5RVAUbs13eOFR92XWxi2SZN
CEmt+915yoePscKjnNT7LiieXA7s1oUR7ZkRfxYPdZ//ZDWqjjVOvGhgu5aK9x80
i90BxmzjjXboCOs07NLEuTr/3i6KRZXP0NQlMsIwUywczBvLdTk7BTTzSCk7zXoZ
0AkP8Y9BrHfZzDWkRep4GiV8nMV4PwARQKe4a4FL5+x+yDeu8WmUrooeOz2KQAPf
LIB3cgK/zHjZs094p0d40uIhEFu1g5vy4mNtP8s1voPNJJh/MPe6wDnqVg4jgdgm
siBj5O8gNKv3wp6vokmNXOuooUDbwY8ik4c2Oc2/AmsxhbN2ZVb1z5Z5FVRuvc21
AZzhxxVAAkMQ0fodX/GnDUEV2Oi/+xPt0ifWJTQgNixTY+pFiaOYNMi8EM3wuM/V
+Cje8cqlCTVDsKUOMsdYBdmBoiqMbyiLdMF//06mHDjFx17zAy6PVDh1Bp1c+rys
YPxAl5ks64Thm0RVsv+VmUlrYhA9gUvufbwkmqj9TeCC9h8u4JQHcIQAwTo55y9c
rE2af8qNfvE9vZaTJA+QvJgx6SFtUWhrR8cpPDT62Nw13epzzooMVXQ7b/u/A4XN
YktixciOMMnMDYIWTqzakQjPJKOLyFMdpK9z5g6KjSBQrQIQPk3CiLdsxkwXrU3w
WnFFHVSVg6Y3l2VkcG+4sO8MyJBQOOh+AkYwWWS/wsCKRYYF/FTogF+4uZrpeVyf
eSWjnsdBV7d6zMxTVGWWpvzBQbbTleKRb+x8/enXUYjvFV8P5VyFWxI3WBXHUfTI
cb5RnsEcgmLx/7TedHFxaGQxPa9027orad2sYMoAaxe7tICDzf5jt+WmgNsULYBA
d3xGO7jFYwEm6qXnEZB4zY+SwKVT+zlZmKZRuWIUHCTrgOfq2VrRYYSHwpj6DhSv
W53mfYu46QrftS/awcwTD9vQftoTCfA48+Xd/Q9Dv5hUwkdEwXA67/xiAWD+q5Yj
tAXLCWcfi8TR15YyMFt0k5GrkFiXq9AmOGxCz1Fb7eEn8KWuiRcXISwwvwyJw91u
ij1Tm1y2BQhAu2JCU4qeGdFSAmzek4LC+N4QQGRjeOedJihZMUy0gbsqATa/TbKj
IN3YevDBuvUtbhUA3Eh1v0RiT68WsE+aZUVNcitn50Ein6SIIj7lzORDw0v3efK5
MrVDkRg4S6D8fvqeCghn8VN0WFC2tKMzaE+V608chSeWXKQAvwGslTU7WFkPykTT
UNbeCIiVa4xE856JvHo2HU/Um2v4YrItz06+Kppt+h9NQQMHnAa+PkNCESoqIR4/
olTDlokkLqjs2IbvrtdU8w==
-----END ENCRYPTED PRIVATE KEY-----
```
