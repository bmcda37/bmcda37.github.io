---
title: "CVE-2017-14980 Proof of Concept"
date: 2026-1-10 15:10:00 +0000
categories: [OSED_Prep, Binex]
tags: [binex, osed]
description: "CVE-2017-14980 | Sync Breeze Application"
---

## Introduction
Buffer overflows are arguably one of the most well-known types of vulnerabilities. At their simplest form, they seem so basic that you would think they could easily be mitigated. However, these seemingly simplistic vulnerabilities can be tricky when paired with other exploit techniques. For this walkthrough, we will be examining the Sync Breeze Enterprise application. Sync Breeze Server 10.0.28 was found to have an unauthenticated buffer overflow vulnerability within the HTTP GET method and was assigned CVE-2017-14980.

## What Needs to Happen?
In short, our goal for this exploit will be to gain a remote shell by causing a buffer overflow (Access Violation) to occur.
Tools Needed for Walkthrough: Win10 VM running the Sync Breeze Application along with the Windbg application installed, Kali Linux VM, which we will use to launch the exploit. Additionally, we will utilize Python and Metasploit for developing and delivering our payload. 

### Controlling EIP

### Placing our Shellcode

### Controlling the Flow

### Completing the Reverse Shell
