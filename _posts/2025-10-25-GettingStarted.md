---
title: "PAMdemic: How Plague Infects Linux Logins"
date: 2025-10-25 07:48:00
categories: [Writeups, Malware]
tags: [malware]
---

###Backgroud
‘Plague’ represents a newly identified Linux backdoor that has quietly evaded detection by traditional antivirus solutions for over a year. Its primary mechanism involves operating as a malicious PAM, allowing attackers to silently bypass system authentication and establish persistent SSH access to compromised Linux systems.


- Plague’s initial infection vector remains unknown. However, during deployment, the malware drops a binary that is configured to run as a PAM module for sshd.
- This module provides an SSH backdoor, enabling threat actors to log in to the infected machine while bypassing standard authentication mechanisms.
- Because it operates within the core of Linux authentication, the malware can persist through application updates and security patches.

