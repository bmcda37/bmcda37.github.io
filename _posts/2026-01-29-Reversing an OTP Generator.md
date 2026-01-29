---
title: "Reversing an OTP Generator"
date: 2026-1-26 00:11:00 +0000
categories: [Reversing]
tags: [reversing]
description: "Reversing | Cracking OTP Generator which utilizes the current timestamp and bitwise operations."
---

# Introduction

# Assembly Code Review
```
Function generate_OTP ; 1 xref
0x400f28:  push    rbp
0x400f29:  mov     rbp, rsp
0x400f2c:  mov     qword [rbp-0x18], rdi
0x400f30:  mov     rax, qword [rel current_session]
0x400f37:  mov     rax, qword [rax+0x30]
0x400f3b:  mov     dword [rbp-0x8], eax
0x400f3e:  mov     dword [rbp-0x4], 0x0
0x400f45:  jmp     0x400f96
0x400f47:  mov     eax, dword [rbp-0x4]
0x400f4a:  add     eax, eax
0x400f4c:  mov     edx, 0x3059b9c1
0x400f51:  mov     ecx, eax
0x400f53:  sar     edx, cl
0x400f55:  mov     eax, edx
0x400f57:  movzx   eax, al
0x400f5a:  xor     eax, dword [rbp-0x8]
0x400f5d:  mov     ecx, eax
0x400f5f:  mov     edx, 0x38e38e39
0x400f64:  mov     eax, ecx
0x400f66:  imul    edx
0x400f68:  sar     edx, 0x1
0x400f6a:  mov     eax, ecx
0x400f6c:  sar     eax, 0x1f
0x400f6f:  sub     edx, eax
0x400f71:  mov     eax, edx
0x400f73:  shl     eax, 0x3
0x400f76:  add     eax, edx
0x400f78:  sub     ecx, eax
0x400f7a:  mov     edx, ecx
0x400f7c:  mov     eax, edx
0x400f7e:  lea     ecx, [rax+0x31]
0x400f81:  mov     eax, dword [rbp-0x4]
0x400f84:  movsxd  rdx, eax
0x400f87:  mov     rax, qword [rbp-0x18]
0x400f8b:  add     rax, rdx
0x400f8e:  mov     edx, ecx
0x400f90:  mov     byte [rax], dl
0x400f92:  add     dword [rbp-0x4], 0x1
0x400f96:  cmp     dword [rbp-0x4], 0x7
0x400f9a:  jle     0x400f47
0x400f9c:  nop     
0x400f9d:  pop     rbp
0x400f9e:  retn    
```



# Using Python to obtain the OTP
## My Python code
```
import datetime

"""
Through manual reverse engineering and dumping values in gdb, I was able to determine the following values for when
the Unix timestamp was: 1769693733

Also, I was able to determine that the generate_OTP function had 2 constants: 
Constant 1: 0x3059b9c1
Constant 2: 0x38e38e39

Lastly, after the function completed, there was a comparison done between the PIN provided by the user and the OTP that was generated and stored
in rax. This value is listed below.
Final PIN Value: 34553314

Helpful Python Notes:
a ^ b XOR
a & b AND
a | b OR
x >> n shift right by n
x << n shift left by n
"""

def greeting():
    valid = True
    time = 0
    pin = 0
    
    if(valid):
        userinput = input("Are you wanting to run the script using demo data or use the current time to see the OTP?\nEnter the following choices:\ndemo\ncurrent\n")
        if userinput == "demo":
            time =  1769693733
            pin =  34553314
        elif userinput == "current":
            dt = datetime.datetime(2026, 1, 29, 16, 5, 15, tzinfo=datetime.timezone.utc)
            time = int(dt.timestamp())
            pin = None
        else:
            print("Only enter 'demo' or 'current'")
            valid = False
            
    return time, pin, valid

def sar32(x, n):
    x &= 0xffffffff
    if x & 0x80000000:
        x -= 0x100000000
    return (x >> n) & 0xffffffff

def reversing(time, pin):
    const1 = 0x3059b9c1
    const2 = 0x38e38e39
    i = 0
    otp_string = ""

    for i in range(8):
        shift_c = i + i
        temp = sar32(const1, shift_c)
        al_const1 = temp & 0xff #get the al value
        xor = time ^ al_const1  #XOR with the al value

        xor_signed = xor if xor < 0x80000000 else xor - 0x100000000
        imul = (const2 * xor_signed) & 0xffffffffffffffff
        edx_imul = imul >> 32 & 0xffffffff   #get the upper 32 bits

        shift_result = sar32(edx_imul, 1)
        s_xor = sar32(xor, 31)


        quotient = (shift_result - s_xor) & 0xffffffff
        tmp_cal = ((quotient << 3) + quotient) & 0xffffffff

        remainder = (xor - tmp_cal) & 0xffffffff

        otp = (remainder + 0x31) & 0xff
        otp_string += chr(otp)
    
    otp = int(otp_string)
    print(f"OTP PIN is {otp}")
    result = pin == otp
    print(f"PIN and OTP match: {result}")
    
if __name__ == "__main__":
    time, pin, valid = greeting()
    if valid:
        reversing(time, pin)
    else:
        print("Run script again with valid input")

```
