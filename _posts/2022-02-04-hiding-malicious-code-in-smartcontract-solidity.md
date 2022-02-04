---           
layout: post
title:  "Hiding Malicious Code in Smartcontract Solidity"
date:   2022-02-04
categories: smartcontract
description: smartcontract, blockchain, ether, go go go!!
tags: smartcontract
---

# Intro

What is solidity? Solidity is an object-oriented, high-level language for implementing smart contracts. Smartcontracts are programs which govern the behaviour of accounts within the Ethereum state.

Why did we need to hide our malicious code? this is because anyone can see your smartcontract source code by using etherscan including your malicious code, Since everyone can see your code, so you have to hide your malicious code to prevent someone read your malicious code.

<img src="/images/hidingmalcodesol/etherscan.png">

# Demo

for this demonstration, I will make a simple smartcontract script below

Token.sol
{% highlight javascript %}
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;

contract LOG{
    event Log(string msg);
    function print() public{
        emit Log("Good code");
    }
}
contract Token{
    LOG log;
    constructor(address _log) public{
        log = LOG(_log); 
    }
    function infoVersion() external{
        log.print();
    }
}
{% endhighlight %}

Now our goal is to change `info.print()` function to do evil stuff, then I create another smartcontract file

Mal.sol
{% highlight javascript %}
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;

contract Mal{
    event Log(string msg);

    function print() external {
        // malicious code will be here
        emit Log("evil code");
    }
}
{% endhighlight %}

in this Post I will just log the `evil code` string which will be executed by `Token` smartcontract. now we can compile
our smartcontract and passing our `Mal` smartcontract address to `Token` smartcontract.

<img src="/images/hidingmalcodesol/remix.png">

now we can just click `infoVersion()` function and these function will execute `log.print()` function from `Mal` smartcontract

<img src="/images/hidingmalcodesol/debug.png">