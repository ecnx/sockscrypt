About
-----
Tunnel AES-encrypted Socks-5 traffic with IPv6 supported

Example usage
-------------
Generate AES-256 key for both Desktop and VPS:
```
dd if=/dev/random bs=32 count=1 of=aeskey
```
Launch plain Socks-5 proxy on VPS,
for example with axproxy, another project here:
```
axproxy -v [::1]:8080
```
Start SocksCrypt on VPS, server-side:
```
./bin/sockscrypt -vs aeskey 0.0.0.0:8081 [::1]:8080
```
Then launch SocksCrypt on Desktop, client-side:
```
./bin/sockscrypt -vc aeskey [::1]:8082 <vps-ipv4>:8080
```
Finally check the connection with curl, client-side:
```
curl -x socks5h://[::1]:8082 https://ipinfo.io/json -o -
```
Purpose of ports used in example:
* 8080 - Incoming plaintext Socks-5 data on VPS
* 8081 - Incoming ciphertext Socks-5 data on VPS
* 8082 - Gateway on Desktop for connections to be tunneled

How to build
------------
Install mbedtls, then
```
make
```

Help message
------------
```
[skcr] SocksCrypt - ver. 1.05.1a
[skcr] usage: sockscrypt [-vdcs] aeskey-file listen-addr:listen-port endp-addr:endp-port

       option -v         Enable verbose logging
       option -d         Run in background
       option -c         Client-side mode
       option -s         Server-side mode
       aeskey-file       Plain AES-256 key file
       listen-addr       Gateway address
       listen-port       Gateway port
       endp-addr         Endpoint address
       endp-port         Endpoint port

Note: Both IPv4 and IPv6 can be used

```
