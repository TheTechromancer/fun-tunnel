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
1. **This is a work in progress.** The current implementation tunnels traffic over a simple unencrypted TCP socket.
2. Requires promiscuous mode (and therefore root access) on both server and client
3. Untested on Windows - use Linux for best results (feel free to report issues)
4. Future developments may include:
	* Tunnelling over well-formed HTTP / WebSockets
	* Option to create virtual interface on the server side
	* End-to-end encryption
	* Multiple client support

### Current bugs:
* The client endpoint is unable to communicate over the tunnel, although its network is fully reachable.

<br>

### Help:
~~~
usage: FunTunnel.py [-h] [-c] [-i] [-p] [-v] [host]

FunTunnel.py

positional arguments:
	host               connect to IP (client mode) or bind to IP (server mode)

optional arguments:
	-h, --help         show this help message and exit
	-c, --client       client mode (default: server)
	-i , --interface   interface to bridge
	-p , --port        port on which to listen/connect (default: 8080)
	-v, --verbose      print what's happening
~~~

<br>

### Simple example:
**Server:**
~~~
$ ./FunTunnel.py
~~~

**Client:**
~~~
$ ./FunTunnel.py -c <server_ip>
~~~
