---
title: "Shellcode Snippets: From Bytes to Bash"
date: 2025-11-02 15:10:00 +0000
categories: [Writeups, Binex]
tags: [binex, shellcode]
description: "Learning to craft effective shellcode through creativity."
---
## Introduction
While learning to craft Shellcode, I have found that I sometimes find myself relating to some of the most famous artists.





## Null-Bytes
Shellcode is not as simple as programming in raw assembly due to how many C-programming language fucntions handles null-bytes.
Often times, we will need to use string manipulation functions as a means for getting our shellcode into our running processes. 
```

```

To remove the null-byte in our Shellcode, we must put on our smock and get creative in our x86 instruction usage.
There are several methods to avoiding null bytes. You can xor, shl/shr, push/pop values withinn registers so that instructions
that have null bytes, like mov, are no longer necessary. <br>


In the example I am providing, I am using xor, shr, and push/pop to avoid null bytes. 

for a second and think about how we can utilize the stack, we find that pushing and popping registers onto the 
stack will remove the null-bytes created by the mov instruction.

```
mov rdi, 0x68732f6e69622f6a
shr rdi, 8
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
push 0x3b
pop rax
syscall
```

[Shellcode/NullFree](https://nets.ec/Shellcode/Null-free) <br>
[pwn.college Shellcode Module](https://pwn.college/dojo/program-security)
