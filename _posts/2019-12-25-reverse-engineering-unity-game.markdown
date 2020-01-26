---
layout: post
title:  "Reverse engineering unity game"
date:   2019-09-09 03:59:00
categories: ctf
tags: ctf-writeup reversing
description: this article explains about ctf writeup.
---

# writeup xmas-ctf 2019 lapland mission

in this challenge we are given an archive that contains a game ,
the game it self looks like an fps game , it's using unity (looks like)
, to solve this challenge i use dnspy to patch some code. , let's play
the game first

<img src="/images/x-mas-lapland/ezgif.com-video-to-gif.gif"/>

the bot is very fast , and there's alot of bot outside , our mission is
to kill all the bot , to kill the bot we have to shot on the head , hmm it's sounds
impossible right ? since they will kill us when we go outside.

let's open Assembly-CSharp.dll file inside 'X-MAS_Data/managed/' and take a look at
shoot() from bot class

<img src="/images/x-mas-lapland/before-shoot.PNG"/>

this is looks like , if the bot see us , we will die. so we can change
```this.weapon.Shoot()``` to this

<img src="/images/x-mas-lapland/after-shoot.PNG"/>

so the bot will never see us , at least we are not dead lol. this changes will
affect like this

<img src="/images/x-mas-lapland/immortal.gif" />

we are immortal now lol. so now we have to kill them , but i was lazy to do that.
so i try to find another way to get the flag without kill all the bot , and i found
checkbots function

<img src="/images/x-mas-lapland/checkbots-class.PNG" />

well , it's looks like this function can help us to get our flag. actually this
function will check all the bot and if there is no bot the flag will not set to
false and the flag will appear. so i change the code

<img src="/images/x-mas-lapland/checkbots-class-after.PNG" />

if we can trigger this function , the flag will appear, in order to do that
we have to kill 1 bot so this function will trigger  and give us our shinny Flag

<img src="/images/x-mas-lapland/flaggg.gif" />
