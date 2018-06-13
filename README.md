# FunTunnel.py
### Tunnel layer 2 traffic over TCP with a single Python script

<br>

### Features:
* **NIC bridging over the internet**
* Single script acts as client or server
* No virtual interface is created client-side
* 100% vanilla Python (no external dependencies)

<br>

### Please be aware:
1. Traffic is obfuscated using an SSL self-signed cert, so it's possible for the data to be decrypted.
2. Requires root access on both server and client
3. Doesn't work on Windows. Tested on Linux.
4. Future developments may include:
	* Tunnelling over well-formed HTTP / WebSockets

<br>

### Help:
~~~
usage: FunTunnel.py [-h] [-i] [-p] [-v] [host]

im in ur network sniffin ur packetz

positional arguments:
  host               connect to host (client mode)

optional arguments:
  -h, --help         show this help message and exit
  -i , --interface   interface to bridge (default: enp5s0)
  -p , --port        port number on which to listen/connect (default: 8080)
  -v, --verbose      print detailed information
~~~

<br>

### Simple example:
**Server:**
~~~
$ ./FunTunnel.py
~~~

**Client:**
~~~
$ ./FunTunnel.py <server_ip>
~~~
