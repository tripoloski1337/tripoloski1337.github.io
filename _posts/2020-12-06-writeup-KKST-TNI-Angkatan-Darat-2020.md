---
layout: post
title:  "Writeup KKST TNI Angkatan Darat 2020"
date:   2020-12-06
categories: ctf
description: Writeup KKST TNI Angkatan Darat 2020
tags: ctf-writeup
---

<iframe width="700" height="400" src="https://www.youtube.com/embed/enasZk977YI" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

on 23 - 24 November 2020 my team "TnT" participated in KKST TNI Angkata Darat 2020 CTF, a CTF organized by Pusat Sandi Dan Siber TNI-AD, and we had a lot of fun during the competition. in this post, I will cover some challenges that I solved 

<ul>
    <li><h3>Reverse Engineering</h3></li>
    <li><a href="#license">License</a></li>
    <li><a href="#crackme">Simple Crackme</a></li>
    <li><a href="#gemoi">Gemoi</a></li>
</ul>

<h1 id="license">License</h1>

we were given a binary called lin, and it's 64bit elf binary. and this is the main function of the binary

<img src="/images/KKST2020/license-1.png" />

and it will pass our input to address `0x400B6D`

<img src="/images/KKST2020/license-2.png" />

now our mission is to satisfy our input with the constraint so that we can jump to another function to solve after doing dynamic analysis
I found that we can bypass the `strlen` and the calculation can still sum our input more than 19 bytes
here is the string that can satisfy the constraint
`"\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\xd3" + "\x00" `

after we solve the first function we jump to the next function `0x400CEC`

<img src="/images/KKST2020/lincese-3.png" />

after doing dynamic analysis with gdb I found the right input `AB\x23D\x3f\x41GHIJ`, the last function is `0x400E7C`

<img src="/images/KKST2020/license-4.png" />

as you can see, the input is already there. this is my exploit to solve this challenge

{% highlight python %}
#!/usr/bin/env python2
'''
    author : tripoloski 
    visit  : https://tripoloski1337.github.io/
    mail   : arsalan.dp@gmail.com
'''
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 92"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/KKSI2020/rev/license/lin")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        # bkps = ["* 0x400bd7","* 0x400b7d", "* 0x00400c22"]
        # bkps = ["* 0x400d01","* 0x400d5f","* 0x400d6f"]
        bkps = ['* 0x400e05']
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    attach(r)
    satu = "\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\x7f-\x7f\x7f\x7f\xd3" + "\x00" 
    r.sendlineafter(":",satu)
    dua = "AB\x23D\x3f\x41GHIJ"
    r.sendlineafter(":",dua)
    tiga = "YHXZ/G!FGHXZ/G!FGXP\\_6ah3XP\\_6ah3"[::-1]
    r.sendline(tiga)
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("140.82.48.126", 30003)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

FLAG: KKST2020{reverse_binary_like_a_B0000s}

<h1 id="crackme">Simple Crackme</h1>

there is a format string bug on the main function

<img src="/images/KKST2020/crackme-1.png" />

so we can easily write to `dword_804A030` using format string bug, this is my exploit to solve it

{% highlight python %} 
#!/usr/bin/env python2
'''
    author : tripoloski 
    visit  : https://tripoloski1337.github.io/
    mail   : arsalan.dp@gmail.com
'''
import sys
from pwn import *
context.update(arch="i386", endian="little", os="linux", log_level="debug",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/KKSI2020/rev/simple-crackme/simple_crackme")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = ['* 0x080485EC']
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    # attach(r)
    p = fmtstr_payload(7, {0x0804A030:0xde4db33f})
    r.sendline(p)
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("140.82.48.126", 30001)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

FLAG: KKST2020{bad_person_?}

<h1 id="gemoi">gemoi </h1>

so basically this is an obfuscated PHP code, 
in order to solve it we have to use <a href="https://github.com/unreturned/evalhook">evalhook</a>
dump the php code after that, dump it again manually till we found the source code, here is the source code

{% highlight php %}
<?php
if (strpos($i1i, "Obfuscation provided by Unknowndevice64 - Free Online PHP Obfuscator") == false)
{
   header("Location: http://ud64.com/"); die();
}
$key="SemogaSemuaKebaikanBersamaKitaSemuaDanBersamaDirimuYangBelakuJujur!";
function dd($data){
   die(var_dump($data));
}
function p($data){
   if(is_array($data)){
       print_r($data);
   }else{
       echo $data;
   }
}
function writefile($file,$data){
   $open=fopen($file,"a+");
   fwrite($open,$data);
   fclose($open);
}
function check_file_exist($file){
   if(!file_exists($file)){
       dd('File tidak ada!');
   }else{
       return file_get_contents($file);
   }
}
 
function rotting13($data){
   $md5_now=md5($data);
   $string=str_split($data);
   array_pop($string);
   $string=implode("",$string);
   return[str_rot13($md5_now),str_rot13(base64_encode(str_rot13($string)))];
}
 
function xoring($data,$file){
   $oldhash=$data[0];
   writefile($file.".GEMAS",$oldhash."#");
   $string=$data[1];
   $ret="";
   $luck=[];
   for($i=0;$i<strlen($string);$i++){
       $num=rand(10,100);
       $bytes=ord($string[$i]);
       $do=$bytes^$num;
       $ret.=chr($do);
       $luck[]=sha1($num);
   }
   writefile($file.".GEMAS",json_encode([implode("|",$luck),base64_encode($ret)]));
}
 
function checkfile(){
   $test='test.txt';
   if(is_writable($test)){
       for($i=0;$i<100000;$i++){
           writefile('HAHA'.$i,$i);
       }
   }else{
       for($i=0;$i<100000;$i++){
           writefile('HAHA'.$i,$i);
           echo "PUT ME IN WRITABLE DIR HACKERS!!!!".PHP_EOL;
       }
   }
}
 
if(isset($argv[1])){
   $string=check_file_exist($argv[1]);
   $h1=rotting13($string);
   $h2=xoring($h1,$argv[1]);
   echo 'Done!';
}else{
   checkfile();
}

{% endhighlight %}

now we can decrypt the encrypted file using the same algorithm from the ransom code, and this is my solver to solve this challenge.
pardon my code :'(

{% highlight python %}
import hashlib 
import string
import codecs
import base64
import string

# enc = open("./flag.gemas").read()
# enc = enc.replace("o68526sp68580rsspn7196q27p946401##","").replace('["',"").replace('"]',"").replace('","',"|")
enc = '''9e6a55b6b4563e652a23be9d623ca5055c356940
b37f6ddcefad7e8657837d3177f9ef2462f98acf
761f22b2c1593d0bb87e0b606f990ba4974706de
972a67c48192728a34979d9a35164c1295401b71
667be543b02294b7624119adc3a725473df39885
f6e1126cedebf23e1463aee73f9df08783640400
761f22b2c1593d0bb87e0b606f990ba4974706de
0716d9708d321ffb6a00818614779e779925365c
22d200f8670dbdb3e253a90eee5098477c95c23d
812ed4562d3211363a7b813aa9cd2cf042b63bb2
d02560dd9d7db4467627745bd6701e809ffca6e3
4d134bc072212ace2df385dae143139da74ec0ef
80e28a51cbc26fa4bd34938c5e593b36146f5e0c
0716d9708d321ffb6a00818614779e779925365c
9e6a55b6b4563e652a23be9d623ca5055c356940
af3e133428b9e25c55bc59fe534248e6a0c0f17b
b37f6ddcefad7e8657837d3177f9ef2462f98acf
98fbc42faedc02492397cb5962ea3a3ffc0a9243
7b52009b64fd0a2a49e6d8a939753077792b0554
92cfceb39d57d914ed8b14d0e37643de0797ae56
98fbc42faedc02492397cb5962ea3a3ffc0a9243
12c6fc06c99a462375eeb3f43dfd832b08ca9e17
511a418e72591eb7e33f703f04c3fa16df6c90bd
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
b6692ea5df920cad691c20319a6fffd7a4a766b8
08a35293e09f508494096c1c1b3819edb9df50db
fb644351560d8296fe6da332236b1f8d61b2828a
1574bddb75c78a6fd2251d61e2993b5146201319
761f22b2c1593d0bb87e0b606f990ba4974706de
4d134bc072212ace2df385dae143139da74ec0ef
9109c85a45b703f87f1413a405549a2cea9ab556
c097638f92de80ba8d6c696b26e6e601a5f61eb7
0716d9708d321ffb6a00818614779e779925365c
e1822db470e60d090affd0956d743cb0e7cdf113
6fb84aed32facd1299ee1e77c8fd2b1a6352669e
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
bc33ea4e26e5e1af1408321416956113a4658763
76546f9a641ede2beab506b96df1688d889e629a
7d7116e23efef7292cad5e6f033d9a962708228c
d321d6f7ccf98b51540ec9d933f20898af3bd71e
b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
c097638f92de80ba8d6c696b26e6e601a5f61eb7
fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
c097638f92de80ba8d6c696b26e6e601a5f61eb7
59129aacfb6cebbe2c52f30ef3424209f7252e82
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
92cfceb39d57d914ed8b14d0e37643de0797ae56
fb644351560d8296fe6da332236b1f8d61b2828a
7719a1c782a1ba91c031a682a0a2f8658209adbf
d54ad009d179ae346683cfc3603979bc99339ef7
7719a1c782a1ba91c031a682a0a2f8658209adbf
667be543b02294b7624119adc3a725473df39885
9109c85a45b703f87f1413a405549a2cea9ab556
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
1352246e33277e9d3c9090a434fa72cfa6536ae2
812ed4562d3211363a7b813aa9cd2cf042b63bb2
761f22b2c1593d0bb87e0b606f990ba4974706de
08a35293e09f508494096c1c1b3819edb9df50db
b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f
2e01e17467891f7c933dbaa00e1459d23db3fe4f
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
8e63fd3e77796b102589b1ba1e4441c7982e4132
c66c65175fecc3103b3b587be9b5b230889c8628
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
16b06bd9b738835e2d134fe8d596e9ab0086a985
215bb47da8fac3342b858ac3db09b033c6c46e0b
6c1e671f9af5b46d9c1a52067bdf0e53685674f7
4d89d294cd4ca9f2ca57dc24a53ffb3ef5303122
2e01e17467891f7c933dbaa00e1459d23db3fe4f
0286dd552c9bea9a69ecb3759e7b94777635514b
f1abd670358e036c31296e66b3b66c382ac00812
22d200f8670dbdb3e253a90eee5098477c95c23d
f1f836cb4ea6efb2a0b1b99f41ad8b103eff4b59
fb644351560d8296fe6da332236b1f8d61b2828a
16b06bd9b738835e2d134fe8d596e9ab0086a985
7b52009b64fd0a2a49e6d8a939753077792b0554
667be543b02294b7624119adc3a725473df39885
76546f9a641ede2beab506b96df1688d889e629a
9a79be611e0267e1d943da0737c6c51be67865a0
0716d9708d321ffb6a00818614779e779925365c
91032ad7bbcb6cf72875e8e8207dcfba80173f7c
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
22d200f8670dbdb3e253a90eee5098477c95c23d
64e095fe763fc62418378753f9402623bea9e227
59129aacfb6cebbe2c52f30ef3424209f7252e82
fc074d501302eb2b93e2554793fcaf50b3bf7291
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
b888b29826bb53dc531437e723738383d8339b56
59129aacfb6cebbe2c52f30ef3424209f7252e82
eb4ac3033e8ab3591e0fcefa8c26ce3fd36d5a0f
2e01e17467891f7c933dbaa00e1459d23db3fe4f
972a67c48192728a34979d9a35164c1295401b71
1574bddb75c78a6fd2251d61e2993b5146201319
f6e1126cedebf23e1463aee73f9df08783640400
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
4d89d294cd4ca9f2ca57dc24a53ffb3ef5303122
b37f6ddcefad7e8657837d3177f9ef2462f98acf
c097638f92de80ba8d6c696b26e6e601a5f61eb7
f6e1126cedebf23e1463aee73f9df08783640400
8effee409c625e1a2d8f5033631840e6ce1dcb64
80e28a51cbc26fa4bd34938c5e593b36146f5e0c
d321d6f7ccf98b51540ec9d933f20898af3bd71e
64e095fe763fc62418378753f9402623bea9e227
7719a1c782a1ba91c031a682a0a2f8658209adbf
16b06bd9b738835e2d134fe8d596e9ab0086a985
2e01e17467891f7c933dbaa00e1459d23db3fe4f
d321d6f7ccf98b51540ec9d933f20898af3bd71e
e6c3dd630428fd54834172b8fd2735fed9416da4
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
2e01e17467891f7c933dbaa00e1459d23db3fe4f
bc33ea4e26e5e1af1408321416956113a4658763
eb4ac3033e8ab3591e0fcefa8c26ce3fd36d5a0f
8e63fd3e77796b102589b1ba1e4441c7982e4132
9a79be611e0267e1d943da0737c6c51be67865a0
9e6a55b6b4563e652a23be9d623ca5055c356940
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
761f22b2c1593d0bb87e0b606f990ba4974706de
d435a6cdd786300dff204ee7c2ef942d3e9034e2
be461a0cd1fda052a69c3fd94f8cf5f6f86afa34
8e63fd3e77796b102589b1ba1e4441c7982e4132
0a57cb53ba59c46fc4b692527a38a87c78d84028
f1f836cb4ea6efb2a0b1b99f41ad8b103eff4b59
bc33ea4e26e5e1af1408321416956113a4658763
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
91032ad7bbcb6cf72875e8e8207dcfba80173f7c
bc33ea4e26e5e1af1408321416956113a4658763
fc074d501302eb2b93e2554793fcaf50b3bf7291
76546f9a641ede2beab506b96df1688d889e629a
d435a6cdd786300dff204ee7c2ef942d3e9034e2
0716d9708d321ffb6a00818614779e779925365c
1574bddb75c78a6fd2251d61e2993b5146201319
12c6fc06c99a462375eeb3f43dfd832b08ca9e17
887309d048beef83ad3eabf2a79a64a389ab1c9f
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
af3e133428b9e25c55bc59fe534248e6a0c0f17b
c66c65175fecc3103b3b587be9b5b230889c8628
80e28a51cbc26fa4bd34938c5e593b36146f5e0c
2e01e17467891f7c933dbaa00e1459d23db3fe4f
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
f1f836cb4ea6efb2a0b1b99f41ad8b103eff4b59
450ddec8dd206c2e2ab1aeeaa90e85e51753b8b7
4d134bc072212ace2df385dae143139da74ec0ef
b4c96d80854dd27e76d8cc9e21960eebda52e962
5a5b0f9b7d3f8fc84c3cef8fd8efaaa6c70d75ab
98fbc42faedc02492397cb5962ea3a3ffc0a9243
761f22b2c1593d0bb87e0b606f990ba4974706de
fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b
b6692ea5df920cad691c20319a6fffd7a4a766b8
b37f6ddcefad7e8657837d3177f9ef2462f98acf
7719a1c782a1ba91c031a682a0a2f8658209adbf
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
2a459380709e2fe4ac2dae5733c73225ff6cfee1
98fbc42faedc02492397cb5962ea3a3ffc0a9243
2d0c8af807ef45ac17cafb2973d866ba8f38caa9
76546f9a641ede2beab506b96df1688d889e629a
fb644351560d8296fe6da332236b1f8d61b2828a
761f22b2c1593d0bb87e0b606f990ba4974706de
bd307a3ec329e10a2cff8fb87480823da114f8f4
c5b76da3e608d34edb07244cd9b875ee86906328
16b06bd9b738835e2d134fe8d596e9ab0086a985
6fb84aed32facd1299ee1e77c8fd2b1a6352669e
c5b76da3e608d34edb07244cd9b875ee86906328
c097638f92de80ba8d6c696b26e6e601a5f61eb7
b37f6ddcefad7e8657837d3177f9ef2462f98acf
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
9a79be611e0267e1d943da0737c6c51be67865a0
761f22b2c1593d0bb87e0b606f990ba4974706de
c097638f92de80ba8d6c696b26e6e601a5f61eb7
d321d6f7ccf98b51540ec9d933f20898af3bd71e
16b06bd9b738835e2d134fe8d596e9ab0086a985
972a67c48192728a34979d9a35164c1295401b71
16b06bd9b738835e2d134fe8d596e9ab0086a985
761f22b2c1593d0bb87e0b606f990ba4974706de
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
2a459380709e2fe4ac2dae5733c73225ff6cfee1
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
f6e1126cedebf23e1463aee73f9df08783640400
eb4ac3033e8ab3591e0fcefa8c26ce3fd36d5a0f
1352246e33277e9d3c9090a434fa72cfa6536ae2
887309d048beef83ad3eabf2a79a64a389ab1c9f
e6c3dd630428fd54834172b8fd2735fed9416da4
b1d5781111d84f7b3fe45a0852e59758cd7a87e5
bd307a3ec329e10a2cff8fb87480823da114f8f4
310b86e0b62b828562fc91c7be5380a992b2786a
08a35293e09f508494096c1c1b3819edb9df50db
0a57cb53ba59c46fc4b692527a38a87c78d84028
fb644351560d8296fe6da332236b1f8d61b2828a
b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f
9e6a55b6b4563e652a23be9d623ca5055c356940
fc074d501302eb2b93e2554793fcaf50b3bf7291
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
7b52009b64fd0a2a49e6d8a939753077792b0554
80e28a51cbc26fa4bd34938c5e593b36146f5e0c
bc33ea4e26e5e1af1408321416956113a4658763
bd307a3ec329e10a2cff8fb87480823da114f8f4
e1822db470e60d090affd0956d743cb0e7cdf113
b7103ca278a75cad8f7d065acda0c2e80da0b7dc
632667547e7cd3e0466547863e1207a8c0c0c549
16b06bd9b738835e2d134fe8d596e9ab0086a985
887309d048beef83ad3eabf2a79a64a389ab1c9f
54ceb91256e8190e474aa752a6e0650a2df5ba37
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
31bd9b9f5f7b338e41b56183a2f3008b541d7c84
f6e1126cedebf23e1463aee73f9df08783640400
8effee409c625e1a2d8f5033631840e6ce1dcb64
887309d048beef83ad3eabf2a79a64a389ab1c9f
2e01e17467891f7c933dbaa00e1459d23db3fe4f
bd307a3ec329e10a2cff8fb87480823da114f8f4
b7eb6c689c037217079766fdb77c3bac3e51cb4c
c097638f92de80ba8d6c696b26e6e601a5f61eb7
972a67c48192728a34979d9a35164c1295401b71
91032ad7bbcb6cf72875e8e8207dcfba80173f7c
b37f6ddcefad7e8657837d3177f9ef2462f98acf
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
5b384ce32d8cdef02bc3a139d4cac0a22bb029e8
1352246e33277e9d3c9090a434fa72cfa6536ae2
1f1362ea41d1bc65be321c0a378a20159f9a26d0
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
511a418e72591eb7e33f703f04c3fa16df6c90bd
c097638f92de80ba8d6c696b26e6e601a5f61eb7
d321d6f7ccf98b51540ec9d933f20898af3bd71e
2d0c8af807ef45ac17cafb2973d866ba8f38caa9
7719a1c782a1ba91c031a682a0a2f8658209adbf
a17554a0d2b15a664c0e73900184544f19e70227
f1abd670358e036c31296e66b3b66c382ac00812
310b86e0b62b828562fc91c7be5380a992b2786a
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
b7103ca278a75cad8f7d065acda0c2e80da0b7dc
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
d435a6cdd786300dff204ee7c2ef942d3e9034e2
e1822db470e60d090affd0956d743cb0e7cdf113
54ceb91256e8190e474aa752a6e0650a2df5ba37
887309d048beef83ad3eabf2a79a64a389ab1c9f
4d134bc072212ace2df385dae143139da74ec0ef
0716d9708d321ffb6a00818614779e779925365c
2e01e17467891f7c933dbaa00e1459d23db3fe4f
22d200f8670dbdb3e253a90eee5098477c95c23d
e6c3dd630428fd54834172b8fd2735fed9416da4
2d0c8af807ef45ac17cafb2973d866ba8f38caa9
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
310b86e0b62b828562fc91c7be5380a992b2786a
eb4ac3033e8ab3591e0fcefa8c26ce3fd36d5a0f
fe2ef495a1152561572949784c16bf23abb28057
b37f6ddcefad7e8657837d3177f9ef2462f98acf
511a418e72591eb7e33f703f04c3fa16df6c90bd
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
1352246e33277e9d3c9090a434fa72cfa6536ae2
91032ad7bbcb6cf72875e8e8207dcfba80173f7c
8ee51caaa2c2f4ee2e5b4b7ef5a89db7df1068d7
a17554a0d2b15a664c0e73900184544f19e70227
812ed4562d3211363a7b813aa9cd2cf042b63bb2
9e6a55b6b4563e652a23be9d623ca5055c356940
b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f
450ddec8dd206c2e2ab1aeeaa90e85e51753b8b7
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
31bd9b9f5f7b338e41b56183a2f3008b541d7c84
b74f5ee9461495ba5ca4c72a7108a23904c27a05
b7103ca278a75cad8f7d065acda0c2e80da0b7dc
0a57cb53ba59c46fc4b692527a38a87c78d84028
972a67c48192728a34979d9a35164c1295401b71
8e63fd3e77796b102589b1ba1e4441c7982e4132
16b06bd9b738835e2d134fe8d596e9ab0086a985
0a57cb53ba59c46fc4b692527a38a87c78d84028
f1abd670358e036c31296e66b3b66c382ac00812
632667547e7cd3e0466547863e1207a8c0c0c549
b7eb6c689c037217079766fdb77c3bac3e51cb4c
b3f0c7f6bb763af1be91d9e74eabfeb199dc1f1f
6fb84aed32facd1299ee1e77c8fd2b1a6352669e
7b52009b64fd0a2a49e6d8a939753077792b0554
1574bddb75c78a6fd2251d61e2993b5146201319
59129aacfb6cebbe2c52f30ef3424209f7252e82
a9334987ece78b6fe8bf130ef00b74847c1d3da6
bd307a3ec329e10a2cff8fb87480823da114f8f4
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
2e01e17467891f7c933dbaa00e1459d23db3fe4f
d321d6f7ccf98b51540ec9d933f20898af3bd71e
d54ad009d179ae346683cfc3603979bc99339ef7
fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b
310b86e0b62b828562fc91c7be5380a992b2786a
80e28a51cbc26fa4bd34938c5e593b36146f5e0c
22d200f8670dbdb3e253a90eee5098477c95c23d
0716d9708d321ffb6a00818614779e779925365c
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
f1f836cb4ea6efb2a0b1b99f41ad8b103eff4b59
b1d5781111d84f7b3fe45a0852e59758cd7a87e5
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
2d0c8af807ef45ac17cafb2973d866ba8f38caa9
be461a0cd1fda052a69c3fd94f8cf5f6f86afa34
1574bddb75c78a6fd2251d61e2993b5146201319
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
d02560dd9d7db4467627745bd6701e809ffca6e3
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
92cfceb39d57d914ed8b14d0e37643de0797ae56
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
a17554a0d2b15a664c0e73900184544f19e70227
7b52009b64fd0a2a49e6d8a939753077792b0554
c5b76da3e608d34edb07244cd9b875ee86906328
92cfceb39d57d914ed8b14d0e37643de0797ae56
98fbc42faedc02492397cb5962ea3a3ffc0a9243
972a67c48192728a34979d9a35164c1295401b71
d02560dd9d7db4467627745bd6701e809ffca6e3
f1abd670358e036c31296e66b3b66c382ac00812
be461a0cd1fda052a69c3fd94f8cf5f6f86afa34
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
12c6fc06c99a462375eeb3f43dfd832b08ca9e17
92cfceb39d57d914ed8b14d0e37643de0797ae56
887309d048beef83ad3eabf2a79a64a389ab1c9f
b4c96d80854dd27e76d8cc9e21960eebda52e962
17ba0791499db908433b80f37c5fbc89b870084b
1352246e33277e9d3c9090a434fa72cfa6536ae2
af3e133428b9e25c55bc59fe534248e6a0c0f17b
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
3c26dffc8a2e8804dfe2c8a1195cfaa5ef6d0014
e62d7f1eb43d87c202d2f164ba61297e71be80f4
fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b
450ddec8dd206c2e2ab1aeeaa90e85e51753b8b7
cb7a1d775e800fd1ee4049f7dca9e041eb9ba083
827bfc458708f0b442009c9c9836f7e4b65557fb
fe2ef495a1152561572949784c16bf23abb28057
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
4d89d294cd4ca9f2ca57dc24a53ffb3ef5303122
16b06bd9b738835e2d134fe8d596e9ab0086a985
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
7b52009b64fd0a2a49e6d8a939753077792b0554
4cd66dfabbd964f8c6c4414b07cdb45dae692e19
22d200f8670dbdb3e253a90eee5098477c95c23d
a72b20062ec2c47ab2ceb97ac1bee818f8b6c6cb
9e6a55b6b4563e652a23be9d623ca5055c356940
08a35293e09f508494096c1c1b3819edb9df50db
ca3512f4dfa95a03169c5a670a4c91a19b3077b4
8e63fd3e77796b102589b1ba1e4441c7982e4132
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
310b86e0b62b828562fc91c7be5380a992b2786a
8effee409c625e1a2d8f5033631840e6ce1dcb64
5a5b0f9b7d3f8fc84c3cef8fd8efaaa6c70d75ab
1f1362ea41d1bc65be321c0a378a20159f9a26d0
b4c96d80854dd27e76d8cc9e21960eebda52e962
632667547e7cd3e0466547863e1207a8c0c0c549
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
35e995c107a71caeb833bb3b79f9f54781b33fa1
9e6a55b6b4563e652a23be9d623ca5055c356940
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
b1d5781111d84f7b3fe45a0852e59758cd7a87e5
22d200f8670dbdb3e253a90eee5098477c95c23d
6fb84aed32facd1299ee1e77c8fd2b1a6352669e
472b07b9fcf2c2451e8781e944bf5f77cd8457c8
0a57cb53ba59c46fc4b692527a38a87c78d84028
fe2ef495a1152561572949784c16bf23abb28057
9109c85a45b703f87f1413a405549a2cea9ab556
b6692ea5df920cad691c20319a6fffd7a4a766b8
632667547e7cd3e0466547863e1207a8c0c0c549
761f22b2c1593d0bb87e0b606f990ba4974706de
5b384ce32d8cdef02bc3a139d4cac0a22bb029e8
cb4e5208b4cd87268b208e49452ed6e89a68e0b8
215bb47da8fac3342b858ac3db09b033c6c46e0b
5a5b0f9b7d3f8fc84c3cef8fd8efaaa6c70d75ab
2a459380709e2fe4ac2dae5733c73225ff6cfee1
6c1e671f9af5b46d9c1a52067bdf0e53685674f7
e62d7f1eb43d87c202d2f164ba61297e71be80f4
e6c3dd630428fd54834172b8fd2735fed9416da4
22d200f8670dbdb3e253a90eee5098477c95c23d
4d89d294cd4ca9f2ca57dc24a53ffb3ef5303122
4d134bc072212ace2df385dae143139da74ec0ef
667be543b02294b7624119adc3a725473df39885
f1f836cb4ea6efb2a0b1b99f41ad8b103eff4b59
17ba0791499db908433b80f37c5fbc89b870084b
b74f5ee9461495ba5ca4c72a7108a23904c27a05
a9334987ece78b6fe8bf130ef00b74847c1d3da6
08a35293e09f508494096c1c1b3819edb9df50db
1f1362ea41d1bc65be321c0a378a20159f9a26d0
a9334987ece78b6fe8bf130ef00b74847c1d3da6
64e095fe763fc62418378753f9402623bea9e227
eb4ac3033e8ab3591e0fcefa8c26ce3fd36d5a0f
c66c65175fecc3103b3b587be9b5b230889c8628
17ba0791499db908433b80f37c5fbc89b870084b
e62d7f1eb43d87c202d2f164ba61297e71be80f4
7719a1c782a1ba91c031a682a0a2f8658209adbf
b7eb6c689c037217079766fdb77c3bac3e51cb4c
0716d9708d321ffb6a00818614779e779925365c
e1822db470e60d090affd0956d743cb0e7cdf113
6c1e671f9af5b46d9c1a52067bdf0e53685674f7
b37f6ddcefad7e8657837d3177f9ef2462f98acf
b1d5781111d84f7b3fe45a0852e59758cd7a87e5
310b86e0b62b828562fc91c7be5380a992b2786a
1d513c0bcbe33b2e7440e5e14d0b22ef95c9d673
d321d6f7ccf98b51540ec9d933f20898af3bd71e
7719a1c782a1ba91c031a682a0a2f8658209adbf
64e095fe763fc62418378753f9402623bea9e227
761f22b2c1593d0bb87e0b606f990ba4974706de
c5b76da3e608d34edb07244cd9b875ee86906328
450ddec8dd206c2e2ab1aeeaa90e85e51753b8b7
'''
enc = enc.split("\n")
key =  "SemogaSemuaKebaikanBersamaKitaSemuaDanBersamaDirimuYangBelakuJujur!"


oldhash = "o68526sp68580rsspn7196q27p946401"

def rotting13(data):
    # x = hashlib.md5(data)
    # str_split = [i for i in data]
    x = ''
    for i in data:
        x += chr((ord(i) + 13) % 0xff)
    return x

def rott(s):
    return codecs.encode(s, 'rot13')

def xoring(data):
    oldhash = oldhash
    strin = data 
    ret = ''
    luck = []
    for i in range(len(strin)):
        num = random.randint(10, 100)
        byte = ord(strin[i])
        do = byte ^ num 
        ret += chr(do)
        m = hashlib.sha1()
        m.update(num)
        m = m.hexdigest()
        luck.append(m)


aneh = '''UQkQVEtTc2VPJSVvbFUicA5BWmt8YGQ2FBJDKmxeGUBvJVlzMCdBYAIJcVAEL3hWcyU2ZHpbR3lMflsrDyZnHENQZikNYy0mTDQBQU1yZx8aXWg4IX1RJ0ZcJEcpOnIWQRFHYHhwBmoLXnkBGmVRYWsKcnJmTgI6O35cHkYQPUtzX0QtaxYFbklAUygGbw4BZgluc0IDdRt+W209RUs4GwsWT35ccTpZRXoPWTt5DX8aZBceCxQaIRQSVAtdWCg4REFqJXUfNFtnX24LNi0OY2ALAFBacFQGWmYEG04fHxECHx1bECEjKm5LBncXGHQLSChPaGlOeWgfIwAZD2sabU4bcVZFRgdCOiM\/K3IbO0teW1AqED5HO2xdHgMOC0BTYUtdLXhNGG0DRVkiCUYoCF1xSHtyA2xtVSR9YxxbEBoSERk5HHBjFh8EFxdbDlIgSjFeaAAgVWwbAHwsGVYlUm0kJUR\/fUJzWXNpKG0Raj1TZAJ0SHEyKVskc1pxHA9mHC8KeX52HGcpYHR7Zl0Idg=='''

def solve():
    # oldhash = oldhash
    data = enc.split("|")
    itera = 0
    luck = []
    tmp = ""
    for x in range(len(data)):
        # brute 
        for i in range(10, 100):
            m = hashlib.sha1()
            m.update(str(i))
            m = m.hexdigest()
            if m == data[0+itera]:
                luck.append(i)
                break 
        if itera == 399:
            flag = ""
            for o in aneh:
                for k in luck:
                    flag += chr((ord(o) ^ (k)))
                if "KKST" in flag:
                    print flag 
                    raw_input("!!!!!!")
            # print flag
        if itera == 399:
            o = "".join(([chr(i) for i in luck]))
            print o.encode("hex")
            print "lastly: " + data[400]
            break
        flag_g = rott(base64.b64decode(data[1+itera]))
        for x in flag_g:
            tmp += chr(((ord(x) ^ i)))
        if "KKST" in tmp:
            print tmp
            print 'FOOOOUNDDD'
        itera += 1
            
            
def solo():
    data = enc.split("|")
    lucky = []
    error = []
    for o in range(len(data)):
        for i in range(10, 100):
            m = hashlib.sha1()
            m.update(str(i))
            m = m.hexdigest()
            if m == data[o]:
                lucky.append(i)
                break
            else:
                error.append(data[o])
                continue
    print "length data : " + str(len(data))
    print "length lucky: " + str(len(lucky))
    # print lucky

    flag = ''
    for i in range(len(lucky)):
        flag += chr((ord(aneh[i]) ^ lucky[i]) % 128)
    # print base64.b64decode(rott((flag)))
    print flag

def bismillah():
    g = base64.b64decode(aneh)
    data = enc
    lucky = []
    for x in range(len(data)):
        for i in range(10, 200):
            m = hashlib.sha1()
            m.update(str(i))
            m = m.hexdigest()
            if m == data[x]:
                lucky.append(i)
                continue
    flag = ''
    for u in range(len(g)):
            flag += chr(ord(g[u]) ^ lucky[u])
    print rott(base64.b64decode(rott(flag)))
    print len(g)
    print len(lucky)


def dd():
    a = base64.b64decode("b37f6ddcefad7e8657837d3177f9ef2462f98acf")
    tmp = ""
    for i in a:
        tmp += chr(ord(i) ^ 18)
    print tmp
    print 


def main():
    # print rotting13(key)
    dd()

if __name__ == "__main__":
    bismillah()
{% endhighlight %}

FLAG: KKST2020{capek_ya_M4@f_bang3t_y}