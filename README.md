# django-bruteforce
Django Control Panel Bruteforce tool.


```
usage: django-bf.py [-h] -u URL [-f FILE] [-p PROXY] [-au AURL]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Django Admin URL
  -f FILE, --file FILE  Combo file
  -p PROXY, --proxy PROXY
                        Proxy for debugging
  -au AURL, --aurl AURL
                        Default /admin/login/
```

Example usage
---

```
python3 django-bf.py -u http://192.168.1.130:8081 -f test.txt -au /admin/login/
[*] Token:MRLQSL6PDQveXw1k3L9BSZfCAYO2vEpONxnuv3cd3LeOy3C2TlIUB9utppi1G298 [*]
[-] Failed to login with user: admin [-]
[*] Token:YPkI8Zj2q6txyBCFbI4Tan5fMaa6NcAYZvWmLhpqQ1c798dn1iDcTxk6BBE5YAki [*]
[-] Failed to login with user: asdadsadssa [-]
[*] Token:tA9R0Taw1efBAkaitHwjD5POR7Qq9BxfugLvDbgUr9YbbRL0jh5Cmf4FGykpkZhz [*]
[-] Failed to login with user: 132123 [-]
[*] Token:GVCXFxa5bgCH9FlNvBUNaBsFmqgN149nHBeBiPgtBblhKcWvlbt6TLHwbRKMcsTH [*]


********** Login Found **********
Django URL: http://192.168.1.130:8081/admin/login/
Django Username: test
Django Password: test
*********************************
```


Combo File
---

Example combo file comes with this as test.txt

it must be formatted like so.

```
admin:admin
test:test
django:django
```
