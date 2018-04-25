# FunTunnel.py
### Tunnel layer 2 traffic over TCP with a single Python script
#### "im in ur network sniffin ur packetz"

<br>

#### Features:
* **NIC bridging over the internet** without a TUN/TAP interface
* Use tools like Responder, etc. from the safety of your AWS instance as if you had physical network access
* Single script acts as client or server
* 100% vanilla Python (no external dependencies)

#### Please be aware:
1. **This is a work in progress.** The current implementation tunnels traffic over a simple unencrypted TCP socket.
2. Requires promiscuous mode (and therefore root access) on both server and client
3. Untested on Windows - use Linux for best results (feel free to report issues)
4. Future developments may include:
	* Tunnelling over well-formed HTTP similar to TrevorC2
	* End-to-end encryption
	* Multiple client support
	* Simple shell for C2


#### Help:
~~~~
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
~~~~

#### Simple usage: