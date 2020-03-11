---
layout: post
title:  "Reverse engineering MIPS elf , babymips UTCTF 2020"
date:   2020-03-11 #13:52:01
categories: ctf
description: this article explains about my writeup.
tags: ctf writeup
---

Challenge Description:

    what's the flag?

    by Dan

Solution:

i use ghidra to doing static analysis, this is the main function

{% highlight C %}

undefined4 main(void)

{
  basic_ostream *this;
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack152 [24];
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack128 [24];
  undefined auStack104 [84];
  int iStack20;

  iStack20 = __stack_chk_guard;
  basic_string();
                    /* try { // try from 00400e44 to 00400edb has its CatchHandler @ 00400f80 */
  this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"enter the flag");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  operator>><char,std--char_traits<char>,std--allocator<char>>
            ((basic_istream *)&cin,(basic_string *)abStack152);
  memcpy(auStack104,&UNK_004015f4,0x54);
  basic_string((basic_string *)abStack128);
                    /* try { // try from 00400ef0 to 00400ef7 has its CatchHandler @ 00400f54 */
  FUN_00401164((int)auStack104,abStack128);
  ~basic_string(abStack128);
  ~basic_string(abStack152);
  if (iStack20 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

{% endhighlight %}

and i found a ``check_flag`` function on ```FUN_00401164``` , it takes 2 argument

{% highlight c %}
  FUN_00401164((int)auStack104,abStack128);
{% endhighlight %}

this is the check_flag function :

{% highlight c %}

void FUN_00401164(int param_1, basic_string<char,std--char_traits<char>,std--allocator<char>> *param_2)
{
  int iVar1;
  basic_ostream *this;
  uint uVar2;
  char *pcVar3;
  uint uStack20;

  iVar1 = size();
  if (iVar1 == 0x4e) {
    uStack20 = 0;
    while (uVar2 = size(), uStack20 < uVar2) {
      pcVar3 = (char *)operator[](param_2,uStack20);
      if (((int)*pcVar3 ^ uStack20 + 0x17) != (int)*(char *)(param_1 + uStack20)) {
        this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
        return;
      }
      uStack20 = uStack20 + 1;
    }
    this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"correct!");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
  }
  else {
    this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
  }
  return;
}


{% endhighlight %}

let's focus on this part

{% highlight c %}
    while (uVar2 = size(), uStack20 < uVar2) {
      pcVar3 = (char *)operator[](param_2,uStack20);
      if (((int)*pcVar3 ^ uStack20 + 0x17) != (int)*(char *)(param_1 + uStack20)) {
        this = operator<<<std--char_traits<char>>((basic_ostream *)&cout,"incorrect");
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
        return;
      }
      uStack20 = uStack20 + 1;
    }
{% endhighlight %}

it looks like our input will xor with `uStack20` and add 0x17

lets use encrypted flag on addres `0x004015f4` to get our flag

{% highlight python %}
def main():
    encrypted = [
    0x62,0x6c,0x7f,0x76,0x7a,0x7b,0x66,0x73,0x76,0x50,0x52,0x7d,0x40,0x54,0x55,0x79,0x40,0x49,0x47,0x4d,0x74,0x19,0x7b,0x6a,0x42,0x0a,0x4f,
    0x52,0x7d,0x69,0x4f,0x53,0x0c,0x64,0x10,0x0f,0x1e,0x4a,0x67,0x03,0x7c,0x67,0x02,0x6a,0x31,0x67,0x61,0x37,0x7a,0x62,0x2c,0x2c,0x0f,0x6e,
    0x17,0x00,0x16,0x0f,0x16,0x0a,0x6d,0x62,0x73,0x25,0x39,0x76,0x2e,0x1c,0x63,0x78,0x2b,0x74,0x32,0x16,0x20,0x22,0x44,0x19,0x00,0x00,0x00,
    0x00,0x00,0x4e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    ]

    flag  = ''
    for i in range(len(encrypted)):
        flag += chr((encrypted[i] ^ i + 0x17) % 0xff)
    print flag

if __name__ == '__main__':
    main()

{% endhighlight %}

FLAG:

```utflag{mips_cpp_gang_5VDm:~`N]ze;\)5%vZ=C'C(r#$q=*efD"ZNY_GX>6&sn.wF8$v*mvA@'}```
