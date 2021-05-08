About
-----
This program tunnels Socks-5 traffic using AES-encryption between two devices.

Example usage:
--------------
Generate AES-256 key for both Desktop and VPS:
```
dd if=/dev/random bs=32 count=1 of=aeskey
```
Launch plain Socks-5 proxy on VPS,
for example with axproxy, another project here:
```
axproxy 127.0.0.1:8080
```
Then launch SocksCrypt on VPS (server-side):
```
./bin/sockscrypt -s aeskey 0.0.0.0:12345 127.0.0.1:8080
```
Finally launch SocksCrypt on Desktop (client-side):
```
./bin/sockscrypt -c aeskey 0.0.0.0:8082 <vps-ipv4>:8080
```
Test connection with curl on Desktop:
```
curl -x socks5h://localhost:8082 https://ipinfo.io/json -o -
```
Ports summary:
* 8080 - Plain Socks-5 server port on VPS
* 12345 - Encrypted Socks-5 traffic between devices
* 8082 - Gateway on Desktop for connections to be tunneled

How to build
------------
install dependency: mbedtls, then run:
```
make
```

Usage message:
--------------
```
[socr] SocksCrypt - ver. 1.04.2a
[socr] usage: sockscrypt [-cs] aeskey-file listen-addr:listen-port endp-addr:endp-port

options:
       -c                Client-side mode
       -b                Bridge-side mode
       -s                Server-side mode

values:
       aeskey-file       Plain AES-256 key file
       listen-addr       Gateway address
       listen-port       Gateway port
       endp-addr         Endpoint address
       endp-port         Endpoint port

```

