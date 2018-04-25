#!/usr/bin/env python3

'''
TODO:
1. Fix listener on server/client to process packets sent on bridged interface
2. Add HTTP/WebSockets support
3. Add encryption support
4. Add multiple client support
'''

import sys
import queue
import ctypes
import pickle
import socket
import argparse
import threading
from time import sleep
from os import name as os_name
from subprocess import run, PIPE


### MAIN CLASS ###

class FunTunnel():

    def __init__(self, interface=None, host=None, port=80, client_mode=False, verbose=False, buf_size=65536):

        self.interface      = interface
        self.sniffer        = Sniffer(interface, send=True)
        self.socket         = self.sniffer.socket # promiscuous socket for listening on network
        self.sender         = self.sniffer.sender # bound socket for sending on network
        self.tunnel         = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # tunnel connection
        self.tunnel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # enable socket reuse
        self.peer           = None # tunnel connection (or client )

        self.host           = host
        self.port           = port
       
        self.client_mode    = client_mode # true or false depending on mode
        self.net_listener   = threading.Thread(target=self._net_listener, daemon=True)
        self.tun_listener   = threading.Thread(target=self._tun_listener, daemon=True)
        self.tun_sender     = threading.Thread(target=self._tun_sender, daemon=True)
        self.incoming_queue = queue.Queue()

        self.mac_table      = []
        self.verbose        = verbose
        self.buf_size       = buf_size
        self._stop          = False


    def start(self):

        self.verbose_print('[+] Starting sniffer on {}'.format(self.interface))
        self.sniffer.start()

        #try:
        if not (self.client_mode and self.host):
            self.verbose_print('[+] Starting tunnel in server mode\n[+] Listening on port {}'.format(self.port))
            self.tunnel.bind((self.host, self.port))
            self.tunnel.listen(0)

        self.tun_sender.start()
        self.tun_listener.start()
        self.net_listener.start()

        #except OSError as e:
        #    stderr.write('[!] {}\n'.format(str(e)))
        #    self.stop()

        while not self._stop:
            sleep(1)


    def stop(self):

        self._stop = True
        self.peer.shutdown()
        self.peer.close()
        if not self.client_mode:
            self.tunnel.shutdown(socket.SHUT_RDWR)
        self.sniffer.stop()


    def _net_listener(self):

        while not self._stop:
            packet = self.socket.recv(self.buf_size)
            self.proc_net_incoming(packet)


    def _tun_listener(self):

        self.verbose_print('[+] Starting tunnel listener')

        while not self._stop:
            try:
                if self.peer is not None:
                    #self.verbose_print('[+] Reading from tunnel')
                    #packet = self.peer.recv(self.buf_size)
                    with self.peer.makefile(mode='rb') as p:
                        packet = pickle.load(p)
                    self.proc_tun_incoming(packet)
                else:
                    self.verbose_print('[!] No tunnel yet')
                    self._reset_tunnel()
                    sleep(.1)

            except:
                if not self._stop:
                    self._reset_tunnel()
                else:
                    break


    def _tun_sender(self):

        while not self._stop:
            #try:
            packet = self.incoming_queue.get()
            self.proc_tun_outgoing(packet)
            #except queue.Empty:
            #    sleep(.1)
            


    def proc_net_incoming(self, packet):
        '''
        process packets sniffed off the wire
        '''

        # src and dest MACs
        src,dst = packet[6:12],packet[:6]

        if self.verbose:
            s = ':'.join('{:02X}'.format(i) for i in src)
            d = ':'.join('{:02X}'.format(i) for i in dst)
            print('{} -> {}'.format(s, d), end='', flush=True)

        is_multicast = (dst[0] & 1) == 1 # least significant bit in most significant byte

        # if destination is on the other side of the tunnel
        # or if it's multicast/broadcast
        if (dst in self.mac_table) or (src not in self.mac_table and is_multicast):
            # send it across the tunnel
            self.incoming_queue.put(packet)
            self.verbose_print(' SENT')
        else:
            self.verbose_print('')

        #self.verbose_print('is multicast/broadcast: {}'.format(is_multicast))
        #self.verbose_print(self.mac_table)


    def proc_tun_incoming(self, packet):
        '''
        process incoming packets from tunnel
        '''

        #self.verbose_print('[+] Received packet (size {})'.format(len(packet)))

        src_mac = packet[6:12]

        # add source MAC to table
        if not src_mac in self.mac_table:
            self.verbose_print('[+] Adding new MAC {}'.format(':'.join('{:02X}'.format(i) for i in src_mac)))
            self.mac_table.append(src_mac)

        #print(packet, flush=True)
        #self.verbose_print('[+] Sending {} bytes'.format(len(packet)))
        self.sender.send(packet)



    def proc_tun_outgoing(self, packet):
        '''
        sends a packet out the tunnel
        '''

        try:
            if self.peer is not None:
                #self.peer.send(packet)
                with self.peer.makefile(mode='wb') as p:
                    pickle.dump(packet, p)
                #self.verbose_print('[+] Packet (size {}) sent'.format(len(packet)))
        except BrokenPipeError:
            self._reset_tunnel()
            

        '''
        while not done:
            with self.llock:
                for c in range(len(self.clients)):
                    try:
                        c.send(packet)
                    except OSError:
                        self.client.remove(c)
                        break
                done = True
        '''


    def verbose_print(self, *args, **kwargs):

        if self.verbose:
            print(*args, **kwargs, flush=True)


    def err_print(self, *args):

        sys.stderr.write('[!] {}\n'.format(' '.join([*args])))
        sys.stderr.flush()


    def _reset_tunnel(self):

        self.peer           = None
        self.mac_table      = []

        try:

            if self.client_mode:
                self.verbose_print('[+] Starting tunnel in client mode')
                self.tunnel.connect((self.host, self.port))
                self.peer = self.tunnel
            else:
                self.peer,address = self.tunnel.accept()
                print('\n\n[+] Connection from {}'.format(address[0]))

        except:
            self._stop = True
            self.err_print('Error setting up tunnel')




### SNIFFER CLASS ###

# most of this code is shamelessly borrowed from zeigotaro's "python-sniffer"
# https://github.com/zeigotaro/python-sniffer/blob/master/snifferCore.py

# ifreq struct
class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


# various flags
class FLAGS():
    # linux/if_ether.h
    ETH_P_ALL     = 0x0003 # all protocols
    ETH_P_IP      = 0x0800 # IP only
    # linux/if.h
    IFF_PROMISC   = 0x100
    # linux/sockios.h
    SIOCGIFFLAGS  = 0x8913 # get the active flags
    SIOCSIFFLAGS  = 0x8914 # set the active flags


class Sniffer(): 
    '''
    Basic sniffer class

        with Sniffer(interface) as stream:
            for packet in stream:
                do_stuff(packet)

    or

        s = Sniffer(interface)
        s.start()
        s.socket.recv(65536)
        s.stop()
    '''

    def __init__(self, interface=None, send=False):

        self.interface  = interface
        self.send       = send # whether or not sending is enabled
        self.sender     = None # separate socket for sending
        self.started    = False

        if os_name == 'posix':
            assert interface, "Please specify interface"

            # htons: converts 16-bit positive integers from host to network byte order
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))
            # 25 = IN.SO_BINDTODEVICE (from /usr/include/netinet/in.h)
            self.socket.setsockopt(socket.SOL_SOCKET, 25, interface[:15].encode('utf-8') + b'\x00')

            if self.send:
                # create additional socket for sending
                #self.sender = self.socket.dup()
                self.sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))
                self.sender.setsockopt(socket.SOL_SOCKET, 25, interface[:15].encode('utf-8') + b'\x00')

        else:
            # create a raw socket and bind it to the public interface
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

            if self.send:
                # create additional socket for sending
                #self.sender = self.socket.dup()
                self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)


    def start(self):

        if not self.started:

            # prevent socket from being left in TIME_WAIT state, enabling reuse
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if os_name == 'posix':

                if self.send:
                    self.sender.bind((self.interface, socket.htons(FLAGS.ETH_P_ALL)))

                # enable promiscuous mode
                import fcntl # posix-only
                ifr = ifreq()
                ifr.ifr_ifrn = self.interface.encode('utf-8')[:15] + b'\x00'
                fcntl.ioctl(self.socket, FLAGS.SIOCGIFFLAGS, ifr) # get the flags
                ifr.ifr_flags |= FLAGS.IFF_PROMISC # add the promiscuous flag
                fcntl.ioctl(self.socket, FLAGS.SIOCSIFFLAGS, ifr) # update
                self.ifr = ifr

            else:
                # the public network interface
                HOST = socket.gethostbyname(socket.gethostname())

                if self.send:
                    self.sender.bind((HOST,0))
                
                self.socket.bind((HOST, 0))

                # include IP headers
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                # enable promiscuous mode
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            self.started = True


    def stop(self):

        self.__exit__()


    def packet_stream(self, buf=65536):

        self.start()

        while 1:
            yield self.socket.recv(self.buf)
    

    def __enter__(self):
        '''
        __enter__ / __exit__ for "with" statement
        '''

        return self.packet_stream()


    def __exit__(self, *args, **kwargs):
        '''
        __enter__ / __exit__ for "with" statement
        '''

        # disable promiscuous mode
        if os_name == 'posix':
            import fcntl
            self.ifr.ifr_flags ^= FLAGS.IFF_PROMISC # mask it off (remove)
            fcntl.ioctl(self.socket, FLAGS.SIOCSIFFLAGS, self.ifr) # update

        else:
            self.qlockioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        self.socket.close()
        if self.sender is not None:
            self.sender.close()
        self.started = False





def get_interface():
    # TODO: handle M$

    # handle Linux
    if os_name == 'posix':

        # try interface with default route first
        routes = run(['ip', '-o', 'route'], stdout=PIPE).stdout.split(b'\n')
        for route in routes:
            if route.startswith(b'default via'):
                return route.split()[4].decode('utf-8')

        # if unsuccessful, just get first interface in line (excluding loopback)
        interfaces = [i.split() for i in run(['ip', '-o', 'link'], stdout=PIPE).stdout.split(b'\n')]
        for line in interfaces:
            if not line[1] == b'lo:':
                return line[1].split(b':')[0].decode('utf-8')

    return None



if __name__ == '__main__':

    ### ARGUMENTS ###

    def_ifc = get_interface()

    parser = argparse.ArgumentParser(description="bridger.py")

    parser.add_argument('host',                 nargs='?',      default='0.0.0.0',  help="connect to host (client mode) or bind to (server mode)")
    parser.add_argument('-c', '--client',       action='store_true',                help="client mode (default: server)")
    parser.add_argument('-i', '--interface',                    default=def_ifc,    help="interface to bridge (default: {})".format(def_ifc), metavar='')
    parser.add_argument('-p', '--port',         type=int,       default=8080,       help="port number on which to listen/connect (default: 8080)", metavar='')
    parser.add_argument('-v', '--verbose',      action='store_true',                help="print what's happening")

    try:

        options = parser.parse_args()
        if os_name == 'posix':
            assert options.interface, "Please specify interface"
        assert (not options.client) or (options.host != parser.get_default('host')), "Please specify host for client mode"

        t = FunTunnel(interface=options.interface, host=options.host, port=options.port, client_mode=options.client, verbose=options.verbose)
        t.start()


    except argparse.ArgumentError:
        stderr.write("\n[!] Check your syntax. Use -h for help.\n")
        exit(2)
    except AssertionError as e:
        stderr.write("\n[!] {}\n".format(str(e)))
        exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Program interrupted.\n")
        exit(2)

    finally:
        try:
            t.stop()
        except:
            pass