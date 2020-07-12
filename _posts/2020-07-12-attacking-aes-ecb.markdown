---
layout: post
title: "Attacking AES ECB"
date: 2020-07-12
categories: crypto
description: Attacking AES ECB
---

## Explanation

in this post, i will explain how we can attacking AES ECB, according to this diagram: <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png" style="background:white"/>

if we use the same key to encrypt a plaintext, we can actual get the same cipher.
in aes, there's 16 byte each block. for example:

    plaintext = AAAAAAAAAAAAAAAA <------- represent 1 blockcipher (16 byte length)

so if we use the same plaintext as our input and will encrypted with the same key. the return 
value will be the same value. for example:

    key= .....
    plaintext = AAAAAAAAAAAAAAAA
    will be:
    cipher    = BBBBBBBBBBBBBBBB

at this time, our goals to get the secret encrypted string by bruteforcing the last byte. for example:
we encrypted our known plaintext 15 byte :
   
    plaintext = AAAAAAAAAAAAAAA

so the last byte of our plaintext is the secret string that will fit on the first blockcipher

    plaintext = AAAAAAAAAAAAAAAS

at this time, we have to encrypt another `plaintext` and brute our last byte with a char and 
comparing with the first one.

    plaintext = AAAAAAAAAAAAAAA<brute here>

if we have the same encrypted string as the first one. it mean that was the correct string.

## Attacking example

for example i will use my latest CTF problem `ECB GAME` from my university. we are given a source 
code , and a listen server: `nc core.ccug.my.id 39002`,

Source : `chall.py`
{% highlight python %}

from __future__ import print_function
from Crypto.Cipher import AES
from Crypto import Random
from secret import *
import sys
import base64
import string
KEY = Random.new().read(16)

class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def writelines(self, datas):
        self.stream.writelines(datas)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

def pad(s):
    length = 16 - (len(s) % 16)
    return s + chr(length) * length

def encrypt(data):
    plain = pad(data + flag)
    aes_obj = AES.new(KEY,AES.MODE_ECB)
    cipher = aes_obj.encrypt(plain)
    return base64.b64encode(cipher)

def check_attack(data):
    for char in data:
        if char not in string.printable:
            return True
    return False

def main():
    while True:
        try:
            print("""
        ---[ HackFest ECB Game ]---
        """)
            print("[?] Plaintext : ",end='')
            plain = raw_input()
            cipher = encrypt(plain)
            print("[+] Ciphertext : {}".format(cipher))
        except:
            break

if __name__ == "__main__":
    main()

{% endhighlight %}

our goal to get the flag string, as you can see the key is randomly choosen with 16 byte length. so every time we connect to the server, the key will change. but we can always doing encrypt because the `while True`

{% highlight python %}
KEY = Random.new().read(16)
{% endhighlight %}

now,in the encrypt function, our flag will appended with our input plaintext

{% highlight python %}
def encrypt(data):
    plain = pad(data + flag)
    aes_obj = AES.new(KEY,AES.MODE_ECB)
    cipher = aes_obj.encrypt(plain)
    return base64.b64encode(cipher)
{% endhighlight %}

so the flag will be located on our last plaintext.

    plaintext = AAAAAAAAAAAAAAAH

note: H is the first byte of the flag String.
now we have to check the first encrypted text with our brute encrypted text, if
we found the same encrypted text, that means we found the correct string of flag. 
after we found the correct string, we have to substract the padding in this case 
`AAAAAAAAAAAAAAA` with length of the that we found `'A' * (len(flag_found))`. so it will looks
like this:

    AAAAAAAAAAAAAAAH
    AAAAAAAAAAAAAAHA
    AAAAAAAAAAAAAHAC
    AAAAAAAAAAAAHACK
    AAAAAAAAAAAHACKF
    AAAAAAAAAAHACKFE
    AAAAAAAAAHACKFES
    AAAAAAAAHACKFEST

here is my solver to get the full flag:

{% highlight python %}
from pwn import *
import base64
# r = remote("core.ccug.my.id",39002)

def kirim(r,p):
    r.sendlineafter('[?] Plaintext : ',p)
    r.recvuntil("[+] Ciphertext : ")
    return base64.b64decode(r.recv())

tmp = ""

enc = lambda x: x.encode('hex')

for x in range(80, 1 , -1):
    if "}" in tmp:
        print("done!")
        print("FLAG : " + tmp)
        break
    r = remote("core.ccug.my.id",39002)
    p1 = ("A"*(x - len(tmp) - 1 ))
    pembanding = kirim(r,p1)
    print "pembanding : " + enc(pembanding)
    for i in range(128):
        p = "A" * (x - len(tmp) - 1) + tmp + chr(i)
        brute_res = kirim(r,p)
        print("+------------------------------------+")
        print("current flag    : " + tmp)
        print("current payload : " + p)
        print("current brute   : " + chr(i) + " , " +  str(i))
        print("pembanding      : " + enc(pembanding[:80]))
        print("brute res       : " + enc(brute_res[:80]))
        if brute_res[:80] == pembanding[:80]:
            print("we found {}".format(chr(i)))
            print("CONGRATSSSS")
            tmp += chr(i)
            break 
    # r.close()


    r.close()
    
{% endhighlight %}

FLAG : `HackFest{penguin_hates_ECB_squidward_hates_spongebob_and_patrick}`
