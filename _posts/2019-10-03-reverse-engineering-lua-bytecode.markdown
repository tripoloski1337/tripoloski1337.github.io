---
layout: post
title:  "Reverse engineering lua bytecode inside an elf binary"
date:   2019-09-09 03:59:00
categories: ctf
description: this article explains about ctf writeup.
tags: reversing lua ctf-writeup
---

# writeup Gemastik12 CTF [decode-me]

this is a ctf competition challenge. in this blog post, i will explain how i solve this challenge. actually, i got this challenge when competing in gemastik 12 ctf telkom, in this challenge we was given a binary called mooncode you can download the ELF binary [here](https://google.com)

# digging into it

this is the information of this binary

```
mooncode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0,
BuildID[sha1]=c0e15ca22b562c60f5d4535eea61d26157ecdde7,
not stripped
```

it's a 64bit elf binary and 'not stripped' binary. that can make our work easier.
let's open it on Ghidra, if you are not familiar with Ghidra you can check theier repository [here](https://github.com/NationalSecurityAgency/ghidra)

# Ghidra section

let's focus on main function , here's the decompiled main function from Ghidra
{% highlight c %}


int main(int param_1)

{
  uint8_t local_AL_15;
  uint8_t local_SIL;
  char *local_28;

  _local_AL_15 = luaL_newstate();
  luaL_openlibs(_local_AL_15);
  local_28 = &code; // <--- this is the lua bytecode was stored
  lua_load(_local_AL_15,readMemFile,&local_28,&DAT_00102004,0);
  lua_pcallk(_local_AL_15,0,0,0,0,0);
  return 0;
}
{% endhighlight %}

as you can see there's the lua_load(). since the binary linked with liblua5.3.so.0, so i assume this binary will run the lua bytecode from a memory. in this case the bytecode stored in a global variable called 'code'.

here's the value of code variable

<img src="/images/2019-10-03-170254_320x418_scrot.png" class="center" />

as you can see there's "Luas" string inside this memory , so we can just dump or export this code variable using Ghidra. and here's the lua bytecode we successfully dump

```
┌─[tripoloski]──[~/code/ctf/gemastik2019/reversing/decode-me]──[pwn-box]: $
└────╼ >> file .data_\[00104060\,001046d5\]_1217343673003918772.tmp.bin
.data_[00104060,001046d5]_1217343673003918772.tmp.bin: Lua bytecode,
```

since this is a Lua bytecode file, so we can get the original source code by decompile it using [unluac](https://sourceforge.net/projects/unluac/) , and here's the source code

{% highlight lua %}
io.write("Flag: ")
user_input = io.read()
key = {
  159,
  82,
  149,
  103,
  179,
  62,
  111,
  84,
  236,
  251,
  222,
  213,
  195,
  125,
  163,
  144,
  118,
  199,
  224,
  170,
  120,
  129,
  153,
  253,
  193,
  32,
  239,
  148,
  197,
  7
}
data = {
  248,
  55,
  248,
  6,
  192,
  74,
  6,
  63,
  221,
  201,
  165,
  167,
  166,
  11,
  198,
  226,
  5,
  174,
  142,
  205,
  39,
  245,
  241,
  152,
  158,
  77,
  128,
  251,
  171,
  122
}
r = ""
for i = 1, #key do
  r = r .. string.char(key[i] ~ data[i])
end
if user_input == r then
  io.write("correct flag: " .. r .. "\n")
else
  io.write("Invalid flag\n")
end
{% endhighlight %}

this is a simple xor between two value , here's my solver to get the flag:

{% highlight python %}

key = [159,82,149,103,179,62,111,84,236,251,222,213,195,125,163,144,118,199,224,170,120,129,153,253,193,32,239,148,197,7]

data = [248,55,248,6,192,74,6,63,221,201,165,167,166,11,198,226,5,174,142,205,39,245,241,152,158,77,128,251,171,122]

flag = ''
for i in range(len(data)):
  flag += chr(key[i] ^ data[i])

print flag
{% endhighlight %}


and we got our flag

```
$ python mooncode.py
gemastik12{reversing_the_moon}
```
