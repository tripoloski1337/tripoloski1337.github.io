---           
layout: post
title:  "Hacktoday IPB 2020 CTF quals "
date:   2020-09-06
categories: ctf
description: Hacktoday IPB 2020 CTF quals 
tags: ctf-writeup              
---

After compete with many university team on indonesia 
me and my university team (glut0r) got 10th place at hacktoday CTF 2020

<img src="/images/hacktoday2020-quals/scoreboard.png" />

## tebak tebakan
#### Description:
Seberapa hebat tebakan anda?
.
nc chall.codepwnda.id 14011


#### Solve:

<img src="/images/hacktoday2020-quals/output.png" />

as you can see, we have to guess the correct input according to 
these output, so i manually collect all the data, and create a
script to solve automatically

{% highlight python %}
from pwn import *
x = {
   "I":'Ikarius',
   "L":"Limos",
   "S":'Skilla',
   "C":"Cleopatra",
   "Q":"Qurea",
   "G":"Gordon",
   "U":"Uranus",
   "A":"Athena",
   "X":"Xuthus",
   "K":"Kaerus",
   "N":"Nemesis",
   "O":"Oizys",
   "W":"Wu-kong",
   "B":"BryanFurran",
   "Y":"Yellena",
   "Z":"Zagreus",
   "H":"Hades",
   "P":"Palioxis",
   "V":"Venus",
   "M":"Moirae",
   "F":"Fuhrer",
   "T":"Triteia",
   "D":"Dionisos",
   "E":"EDYRAHMAYADI",
   "R":"Rhea",
   "J":"Jokasta"
}
r = remote("chall.codepwnda.id",14011)
 
 
def getflag():
   r.sendlineafter(":",'2')
 
def guess():
   r.sendlineafter(":","1")
   r.recvuntil('am ')
   nm = r.recv().split()[0]
   r.sendline(x.get(nm[:1]))
   print "pk"
   print nm[:1]
   print x.get(nm[:1])
   r.send("\n")
 
 
def main():
   for i in range(1115):
       guess()
   r.interactive()
 
 
if __name__ == "__main__":
   main()


{% endhighlight %}

run the script, and we got our flag

<img src="/images/hacktoday2020-quals/11.png" />

#### Flag:
hacktoday{tebak_tebak_berhadiah_flag_1kEb44t}

## Hard Rock casino

#### Description:
play smart and win
nc chall.codepwnda.id 14021

#### Solve:
Service Source code

{% highlight python %}

#!/usr/bin/python
import random, signal, sys
 
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
 
def handler(signum, frame):
 print '\nmaaf casino sudah mau tutup, silakan coba lagi...'
 exit()
 
class Player:
 def __init__(self, nama):
   self.nama = nama
   self.saldo = 1000
 def taruhan(self):
   try:
     bet = int(raw_input('\nhalo %s, ayo pasang taruhan: ' % (self.nama)).strip())
     if self.saldo >= bet:
       if bet > 0:
         if random.random() >= 0.44: # 56% winning chance?
           self.saldo += bet
           print 'kamu menang! saldo kamu %d' % (self.saldo)
         else:
           self.saldo -= bet
           print 'kamu kalah, saldo kamu %d' % (self.saldo)
       else:
         print '%s, dilarang bermain curang!!1!1' % (self.nama)
     else:
       print 'maaf %s, saldo kamu tidak cukup' % (self.nama)
     if self.saldo == 0:
       print '\nkamu bangkrut, bye %s' % (self.nama)
       exit()
     elif self.saldo >= 100000:
       print open('flag.txt').read().strip()
       exit()
   except:
     exit()
 
n = raw_input('nama kamu: ').strip()
p = Player(n)
signal.signal(signal.SIGALRM, handler)
signal.alarm(10)
while True:
 p.taruhan()

{% endhighlight %}

according to the source code, our chance to win is depends on `random()`
so i create a simple script to solve it:

{% highlight python %}

from pwn import *
import random
 
r = remote("chall.codepwnda.id",14021)
def main():
   uang = 1000
   r.sendlineafter(":","arsalan")
  
   for i in range(10):
       r.sendline(str(uang))
       uang += (uang-1)
   r.interactive()
 
if __name__ == "__main__":
   main()


{% endhighlight %}

<img src="/images/hacktoday2020-quals/flago.png">

#### Flag:
hacktoday{when_this_house_is_rocking__dont_bother_knocking__come_on_in}

## Babyvol

#### Description: 

I command you to find the flag

#### Solve:

you can use `volatility` to find the right profile, so we can digging more into it

<img src="/images/hacktoday2020-quals/vol-dump.png">

according to the description, i assume our flag is stored inside recent command,then i use `cmdscan` to get the flag

<img src="/images/hacktoday2020-quals/vol-flag.png">

#### Flag: 
hacktoday{yOUv3__folll0wed_My_c0mm4ND_f3ry_w3LL__}

## Stegosaurus

#### Description: 

omething creepy is hiding here.
format flag: "hacktoday{flag}", tiap kata dipisahkan oleh "_"

#### Solve:

use `stegsnow` to extract the hidden data

<img src="/images/hacktoday2020-quals/stegsnow.png">

download the image, and use `stegsolve.jar` to get the flag

<img src="/images/hacktoday2020-quals/stegoflag-1.png">
<img src="/images/hacktoday2020-quals/stegoflag-2.png">

#### Flag:
hacktoday{ez_point_yow}

## Nothosaurus

#### Description:

#007

#### Solve:

there is a zip header inside `okay` file, so i assume this is the 
zip file, so i create a simple script to join the file

{% highlight python %}
okay = open("okay",'rb').read() # header
ill = open("ill",'rb').read()
be = open("be",'rb').read()
again = open("again",'rb').read()
today = open("today",'rb').read()
 
# broken fix
x = okay
x += today
x += ill
x += be
x += again
 
print x
{% endhighlight %}

after the file extracted, there is 2 file inside it `broken.jpg` and `cute.jpg`
so we have to compare each file and dump the difference between two file

{% highlight python %}

def main():
   broken = open("./broken.jpg",'rb').read()
   cute = open("./cute.jpg",'rb').read()
 
   tmp = ''
   for i in range(len(cute)):
       if broken[i] == cute[i]:
           continue
       else:
           tmp += broken[i]
   print tmp
      
 
if __name__ == "__main__":
   main()

{% endhighlight %}

#### FLAG:
hacktoday{broken_image}

## Harta Karun
#### Description:
Seorang penggemar harta akhirnya insaf setelah menonton drama pengingat dosa, ia pun mengadakan sebuah sayembara untuk menemukan harta yang telah ia simpan di suatu tempat. Para peserta hanya diberikan gambar peta untuk menemukan Location dari harta tersebut. Apakah kamu yang menjadi juara?

#### Solve:

extract with foremost, and join the file 
{% highlight python %}

def do(x):
   return x.replace(' ','').decode('hex')
 
def main():
   satu = '''89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52 00 00 01 68 00 00 00 64 08 00 00 00 00 8E 3B F5 C6 00 00 00 04 67 41 4D 41 00 00 B1 8F 0B FC 61 05 00 00 00 20 63 48 52 4D 00 00 7A 26 00 00 80 84 00 00 FA 00 00 00 80 E8 00 00 75 30 00 00 EA 60 00 00 3A 98 00 00 17 70 9C BA 51 3C 00 00 00 02 62 4B 47 44 00 FF 87 8F CC BF 00 00 00 07 74 49 4D 45 07 E4 08 07 01 28 12 43 80 35 99 00 00 03 41 49 44 41 54 78 DA ED D5 5D 48 D5 77 1C C7 F1 F7 F1 3C 29 CC 69 D2 90 6D 8D A8 C4 46 45 28 9B 6D 94 27 57 9D 8B 8A 3C 25 63 2E C8 81 7B C2 E6 8C BA 08 3C 45 C8 A9 CC B9 B9'''
   dua = '''65 DE 92 47 96 17 C3 99 D9 87 7D A7 B3 FC 35 E7 C0 02 84 63 D9 C5 B3 8B A3 67 5A D6 A4 DA FE 3C 6C 16 2C 2D AF B8 95 52 7F B3 DA 6C C4 EA B4 F4 A6 98 69 67 05 FC 0D E1 4B BC FE F9 ED DE F4 0D B9 75 6E 2A DE 2C A5 A8 AC CA 13 6A 6E 85 C1 44 CF EE D9 6C F2 7A BD FB 00 70 6C 84 6A 1B 2C CA C0 BD E2 CB 0C C0 9D 0F C0 76 A0 F2 E5 D4 2D 60 FD 39 39 9C B9 32 0F 67 25 40 15 10 8D F9 62 8E 6E 9A 04 EF CD 0D 17 6C 60 AF 73 6D 7A F8 6B CB B4 D8 5C B3 9F 19 FB 6C 3E CC 32 C2 3E 60 73 99 11 AA 74 24 7A 56 63 31 FC 45 D7 C2 26 70 15 F4 74 D9 A1 BB 1F CE 00 45 B7 EE 46 12 32 AF 03 67 73 3B 5A 61 E0 A7 48 66 63 ED 2F 1F 1C 81 A4 43 8D 40 B6 19 1B EA 5A 1B FC F0 51 8B 59 C0 B4 DE A5 69 F7 C3 E5 A1 1B D0 1F 4D 35 FA 99 B1 86 85 AB 1D 57 AF 44 62 7D 7B 8D F5 78 E0 E3 DB 89 1E DF 93 4B 1A 79 3B CD 5D 5D 77 30 04 69 36 78 69 2A F8 03 3E A0 CF 01 D0 91 6D 81 05 C1 6B 73 C0 EA 8E 64 0E B6 2C 9C D0 0E A1 D2 B7 00 33 16 67 E6 6B B0 F8 62 B8 E0 7E 69 55 CE 60 A4 3C 8E 3F E0 8B 5E 62 D1 99 86 9D CB A0 DF 8E 33 23 26 A7 F8 DD E7 68 CE C3 5E F4 14 57 F9 1E 8F AB E0 82 6D 73 F7 A3 79 39 C1 FA 9A 87 F6 81 ED 13 DF 3F 78 B9 F0 58 6D B0 75 EB 5C 6B D7 D7 EC FB A2 33 F9 5C 3B A7 6A 7A 5E F8 B5 7C 87 99 C9 77 CD 9F 00 C6 BB EC 34 62 DF 7C 98 99 EF ED DF 61 BE 54 CF DF 65 03 5C 6F 4D 32 0B 2E 6D BC D7 F9 90 7F 8C AF AE FC 92 A3 0B 5C 05 E6 7F AB D9 EF B2 99 59 F8 86 DD 7E 11 8E D7 DD B5 4E'''
   tiga = '''46 AB EC D8 F3 45 5D 24 74 2E 96 D2 D6 A2 5A C4 2C 1C 8C 43 C4 28 A8 16 9B 13 8C D6 D3 34 E7 D3 71 17 FF FF 79 F0 A8 2D 0B 3C 04 9F D7 CD 8F FF EF FB FD FE BE BF F3 E5 07 07 44 44 44 44 44 44 44 44 44 44 44 44 44 44 64 DC 39 4E 96 E3 39 35 65 E8 E6 C4 FD 6F 03 30 3F 2F 2E 7B C6 F7 C9 C3 4E 28 5A 1B 1B 6B 8E 06 3C 07 46 6F 9B F3 E3 48 FD 1E AB 70 5D A2 67 35 26 49 71 DF BD 2D 7B 38 71 E1 F7 A1 9B 77 1A 8D D5 E1 8C CB FE ED FC F0 13 67 7C 1B 1B 8B 99 C6 89 B6 D1 AF 11 6C 19 A9 DF 63 35 A5 26 66 62 4F C9 36 CA FE 9C C2 7F 33 EA 6F F2 CA A7 DD 96 59 DE BF 20 2B E0 6F C8 5D D5 F7 4E A8 FE 01 D3 4B BA 52 CE 9F'''
   empat = '''CE 09 56 B8 BC 34 5F 01 AC BD 89 1E 5E 62 A4 AC 37 D6 AD 96 71 6A B8 2D D1 BF 78 4C 6C CF 7E 04 00 AF 96 CC 6E 77 F6 00 04 2A 76 C5 C5 76 1B CB 57 7F FC EF 29 4F 9E 09 CB 2F 8D CF 84 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 9E DA 7F 95 3C 15 CC 47 61 B5 66 00 00 00 25 74 45 58 74 64 61 74 65 3A 63 72 65 61 74 65 00 32 30 32 30 2D 30 38 2D 30 37 54 30 31 3A 34 30 3A 31 38 2B 30 37 3A 30 30 F7 19 5F 45 00 00 00 25 74 45 58 74 64 61 74 65 3A 6D 6F 64 69 66 79 00 32 30 32 30 2D 30 38 2D 30 37 54 30 31 3A 34 30 3A 31 38 2B 30 37 3A 30 30 86 44 E7 F9 00 00 00 00 49 45 4E 44 AE 42 60 82'''
  
   o = do(satu)
   o += do(tiga)
   o += do(dua)
   o += do(empat)
   print o
 
 
 
 
if __name__ == "__main__":
   main()

{% endhighlight %}

<img src="/images/hacktoday2020-quals/flaga.png">

#### Flag:
hacktoday{di_bawah_kasur}

## Daun Singkong
#### Description:
tanam-tanam ubi tak perlu dibajak.

#### Solve:
Extract `daunsinkong.zip` i found `.DS_Store` inside the archive
i use `https://labs.internetwache.org/ds_store/`. to extract all the information

<img src="/images/hacktoday2020-quals/aa.png">



brute the `flag.7z` using `.DS_Store` information, password: `pertanianindonesiakanlebihbaikjikapetaninyatidakmainctf`



<img src="/images/hacktoday2020-quals/flagoo.png">

#### FLAG:
hacktoday{DS_Store_h4ve_ur_f0lder_nam3___}