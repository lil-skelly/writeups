# Secure IRC (Internet Relay Chat) Chatting

For this writeup we will be using **TOR** and **irssi** to chat anonymously online.

# TOR and Proxy Chains
**ProxyChains** is a tool that forces any **TCP** connection made by any given application to go through proxies like **TOR**. 
[Tor](https://www.torproject.org/) is an overlay network for anonymous communication.

## Setup

Firstly let's install proxychains and tor using a package manager (`ex. apt`)

```bash
$ sudo apt install tor proxychains-ng
[ . . . ]
```

We can now enable the **TOR** service using `systemctl`

```bash
$ sudo systemctl enable tor
[sudo] password for skeleton: 
Synchronizing state of tor.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable tor
```

Check that **TOR** is succesfully enabled:

```bash
$ sudo systemctl status tor
[sudo] password for skeleton: 
● tor.service - Anonymizing overlay network for TCP (multi-instance-master)
     Loaded: loaded (/lib/systemd/system/tor.service; enabled; preset: disabled)
     Active: active (exited) since Mon 2023-01-23 17:33:30 EET; 1h 30min ago
   Main PID: 516 (code=exited, status=0/SUCCESS)
        CPU: 2ms

Jan 23 17:33:30 kali systemd[1]: Starting Anonymizing overlay network for TCP (multi-instance-master)...
Jan 23 17:33:30 kali systemd[1]: Finished Anonymizing overlay network for TCP (multi-instance-master).
```

Before using proxychains it is advised you change the default chaining protocol.
To do that edit the `/etc/proxychains4.conf` file. We comment out line 17 (by adding the # symbol) and uncomment line 9. This enables dynamic chains.

# IRSSI
For this writeup I will show you how to connect to the `Libera.Chat` network. 
To access `Libera.Chat` via **TOR** we will need to use their **onion service**. 
To make our lives easier we will map the onion service to a more readable address.
Add this to your `/etc/tor/torrc` file: `MapAddress palladium.libera.chat libera75jm6of4wxpxt4aynol3xjmbtxgfyjpu34ss4d7r7q2v5zrpyd.onion

> **Note**
> Make sure to restart **TOR** after any changes to the `torrc` file
> `sudo systemctl restart tor`


## CertFP

The onion service requires public-key (not plain) SASL authentication.
We generate a certificate:

> **Note**
> This certificate will last about 3 years (1096 days).

```bash
$ openssl req -x509 -new -newkey rsa:4096 -sha256 -days 1096 -nodes -out libera.pem -keyout libera.pem
[ . . . ]
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:.
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:.
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

We can now store our certificate somewhere safe:

```bash
$ mkdir ~/.irssi/certs && mv libera.pem ~/.irssi/certs
```

We now configure our `/server` entry for `Libera.Chat` to use this certificate and connect to the network in order to register our account.

```irc
/server add -tls_cert ~/.irssi/certs/libera.pem -network LiberaChat irc.libera.chat 6697
```

```irc
/connect LiberaChat
```

## Register

To create an account firstly we need to pick a username/nickname.

```irc
/nick YourNick
```

Now we **register** the nickname. 

```irc
/msg NickServ REGISTER YourPassword youremail@example.com
```

Replace “YourPassword” with a secure and unique password.
Upon registering, you will receive an email with a verification command that you will need to run to complete the registration process.

> **Warning**
> Do not share your NickServ password with anyone else as this could compromise account security.

## Adding the fingerprint

Firstly we get certificates fingerprint by running 

```bash
$ openssl x509 -in libera.pem -noout -fingerprint -sha512 | awk -F= '{gsub(":",""); print tolower ($2)}'
<fingerprint>
```

Afterwards we authorise our current certificate fingerprint:

```irc
/msg NickServ CERT ADD <fingerprint>
```

## Configuring SASL

Now we can disconnect from the network

```irc
/disconnect LiberaChat
```

Switch the authentication to certificates:

```irc
/network add -sasl_password '' -sasl_mechanism EXTERNAL LiberaChat
/save
/quit
```

Great! Now we can finally use the **onion service**.

## Connecting

```bash
$ proxychains4 irssi
[ . . . ]
```

And connect to the mapped onion service:

```irc
/connect palladium.libera.chat
```

# Goodbye
I hope you enjoyed this writeup. Now you can anonymously chat like Ollie.
Remember to star the repository for more or open an issue to discuss the things you disliked with me :D
- sk3let0n