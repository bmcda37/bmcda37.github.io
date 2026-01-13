
---
title: "Buffer Overflows: OSED Exam Practice"
date: 2026-1-10 15:10:00 +0000
categories: [OSED Prep, Binex]
tags: [binex, shellcode, osed]
description: "CVE-2017-14980 | Sync Breeze Application"
---

## Introduction
Buffer overflows are arguably one of the most common types of exploits. At their simplest form, they seem so basic that you would think they could easily be mitigated. However, these seemingly simplistic vulnerabilities can be tricky when paired with other exploit techniques. For this walkthrough, we will be examining the Sync Breeze Enterprise application. Sync Breeze Server 10.0.28 was found to have an unauthenticated buffer overflow vulnerability within the HTTP GET method and was assigned CVE-2017-14980.

