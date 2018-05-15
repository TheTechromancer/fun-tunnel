#!/usr/bin/env python3

'''
TODO:
 - Windows support (needs third-party driver for L2 headers - possibly either TAP or PCAP)
 - experiment with STUN (to circumvent NAT)
 - try tunneling using websockets
'''

import os
import ssl
import sys
import queue
import pickle
import socket
import struct
import argparse
import threading
from time import sleep
from base64 import b64decode
from tempfile import NamedTemporaryFile
from subprocess import run, PIPE, CalledProcessError

if os.name == 'posix':
    from fcntl import ioctl

ssl_cert = 'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBN0RRNEV6UGpqWm5JV1lsa0Npb25BMTBEeFdWOUlibk43bzNuRndBK2JlUXZkQzhsCnY5V0o1OVg0WXIrWFhwc0w5SWZXSUdCMVZHbGRUS2ZtSzUwTmVDNU5SUEQ4QUNTUmhQK0ZpL3E3dEswUXR4L1UKc1l6OG9TQStIUmVkNFJMaGNzK1IzMEc2ZTJySGVBaE8yYnZiVW9MOHozb1d4emRWZlRUOHlCZkw4OWpoU1VUZwpqemR3NGUyWlFBT0phbEdIZTJPUitYWk1EZEgxOHpLNktFSW4vM1o2RU9TeFBiQUI5NHUxYTF5eVlrMlRWbXBnCnRsT1NXV1BtcUJja2cwQU5raHFpYStxMGE1emx0VXdUZzZyRDRReGxPamZHQy9GVmtLUVJqTFVaM3BEUDFJM1YKT3BVYXcyUGVvYXRDZGk2ZWpoSVFjVk5lYmFGUEVpOGZLWnBoOVFJREFRQUJBb0lCQVFDc0c2eVVTV1hRUXJLYQpreUtpeVc0ZDVFT2dMTUFOdC81V2lXMU45QzZKRWhDRnZ1anBxK1hOV0xxZzhXdVJVclpXV2pmcTVYMzRvTUdMCjNuYzNaanR2UzRXZjYxd2ptb0d5QUNIR0NrK0ZhZWxaRmNkOEMvZjBTN01XcmFPcllYK0drYnAvaTd3ZXU0SlcKY3U5SmRibHNtT2N2SW8zQVlSQllxQ2hjZ0FKclRVRVZzUnlpWG5nZjZrQXFIWCtESFVlRzRQZXl4SnFaWVZ2UQpISE1JeHVGdG9pVHNpMHRkZ21vemJIS1E2eWpUSGpXMElDMnl3S1UyMEN0dm1ZaGxQRERJejV6WlJ5YlVzNEtYCk5qY3JKVXcxKzQ1c09pTlBLdCt3Y1FwTndIWWFxZzF0THk1YmsvM2FuMXJvN2ZFV3NnR1dvM3lOMmI5N2swYjgKR21QSEw3NkJBb0dCQVBkeDgrWHM5S0tJdzlRSWRmYmNMb0lXM1owSDJWZEtxOTlsNURoTm9vckh4c3U5ZW1aRwoxazJUVk1pUTVnTVdjQmVOQWVLM081TkxQQTlMT1FsaTJ4TWcwTkt1d05MbU80V3hVMW1QeHYwbGtWVU9LUlhNCkRGU2Nobm9WbXkzZVN6WC9aOEJqNDNVcVhWZ3VTcXoyMEMzSEpxSW9TZnpFdXNPUS8rajFITkFoQW9HQkFQUmUKeG1YRGpUMWhzTHlKSklXYTloTzR1QjhIUjhPRnQ5M1dGeWtMTmNBK05ua1NkMndWeDFzVVUvaUJqSUtycWlTWgpyamVkQWkxem0rWUNrWVVYZTBDNEJLYnVvN2ZObWRHUkQ3SWxMNjljMHY4RXNHdFAxNkVHQ2VHRVNQYjRCVVQyCmJuTnU4VExBdWpMdEVNcTlJRTVUQllLNWhKRjZPVzFYa01xMXpHZFZBb0dBU3RrOVhaOS9vR3FlVWRUOVdkN2cKY3BsWUQ5Zi85bGV3QmJOY2hXdDJiMlJlemVKUzAvMDVkZDNMRjZBODgxSW1OZm1CU0lNRWtsbC9vV0N2c0JjbgpEWEl2dUlzRDZNZWIyYVQ2QVcxc1U4YTVYM0VaSEc3TWpBdU00Z0VISDZqT04xYzZtd2VjRmlUcWQzSUpSS2lqCjhEVDlpcStGTWVDUVhmZk9jVGt6cmdFQ2dZQU42SDcrTjcwSUsxRTF5ZEJzVWorREs5WSszZGsxeFp5TFlhMzcKeGdtUElYdFVOTHJiU2ZvSXN3VjhkVk1iOU0xQVBBYndYMTFLWFBRWWlUampERTBWaCtPcjVKVW8xdWpVUnA5UQpFbEcrZDFnQzc2OWl6QzZIbWFKaVZYY1pwMUFWZHJrZWxNZmhqWnFMWDNhL016aHRmTWdwZ29tTEJodlNuMU04ClZsQ0Y2UUtCZ1FDb0VrYVJFNDdnQUozRjh4OWJDeGhva2NBOHFsbFJFcXVLYmNoUGxhcGdSMDkvWDI2Z0RyTEMKenpMU0lOYjArajVtYVZjazhZZWNPbDk2VnNEWU9ySGFaMkhWV01JazQzQUZldjl2Nzk5clRiYlZ4U0RsbnNIZwozZGdSTEs3em9tMm9LcGZiQklvMTRQZ0lKVGswV2dmWDdydU5UL2lUalhzVkl3QVBrUGY1K3c9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRE1EQ0NBaGdDQ1FDeUZ6UkMwNFZyNGpBTkJna3Foa2lHOXcwQkFRc0ZBREJaTVFzd0NRWURWUVFHRXdKRwpWREVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFaE1COEdBMVVFQ2d3WVNXNTBaWEp1WlhRZ1YybGtaMmwwCmN5QlFkSGtnVEhSa01SSXdFQVlEVlFRRERBbEdkVzVVZFc1dVpXd3dJQmNOTVRnd05URTFNRE15TkRBNFdoZ1AKTkRjMU5qQTBNVEF3TXpJME1EaGFNRmt4Q3pBSkJnTlZCQVlUQWtaVU1STXdFUVlEVlFRSURBcFRiMjFsTFZOMApZWFJsTVNFd0h3WURWUVFLREJoSmJuUmxjbTVsZENCWGFXUm5hWFJ6SUZCMGVTQk1kR1F4RWpBUUJnTlZCQU1NCkNVWjFibFIxYm01bGJEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU93ME9CTXoKNDQyWnlGbUpaQW9xSndOZEE4VmxmU0c1emU2TjV4Y0FQbTNrTDNRdkpiL1ZpZWZWK0dLL2wxNmJDL1NIMWlCZwpkVlJwWFV5bjVpdWREWGd1VFVUdy9BQWtrWVQvaFl2NnU3U3RFTGNmMUxHTS9LRWdQaDBYbmVFUzRYTFBrZDlCCnVudHF4M2dJVHRtNzIxS0MvTTk2RnNjM1ZYMDAvTWdYeS9QWTRVbEU0STgzY09IdG1VQURpV3BSaDN0amtmbDIKVEEzUjlmTXl1aWhDSi85MmVoRGtzVDJ3QWZlTHRXdGNzbUpOazFacVlMWlRrbGxqNXFnWEpJTkFEWklhb212cQp0R3VjNWJWTUU0T3F3K0VNWlRvM3hndnhWWkNrRVl5MUdkNlF6OVNOMVRxVkdzTmozcUdyUW5ZdW5vNFNFSEZUClhtMmhUeEl2SHltYVlmVUNBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQUFZc2paekNRbURQMTdOUC8KeEZROW9Va05KejZJS2V3S0U4Y1FMRTlBcGt1ZlRWQVhhRkEyVXFGN0wwVnpVUmhNS1JBMVBVODE3NUp0b3VSbApJeURJSVZVSFpOc25tZGhCKzJhNVV2cFpxZEZkNG8yR2JBRkhZd0dTbmhicmRHL3l1Rm1IZXFRcVVtaitOZFkwCkd6S1dYYlBPRHdGQVhYZk1pcW1Zb2FTN1VkZXlHNklKdFlRbitjanVWYXhQcEhyWXQxUGpZb1QvemFaWmFHVnkKOE9tSTc3c2RCWDZTclRlZWora0h1eTg1bzlCL044WDVkTHdhcDJNS0ozZEE3NG1jM1o5QlA3N0I0Y0dCQ1VFQgprbmV3Y1FwUmNncjF6VUloZ1BmRHE2NkkxQTFUZmJMZjBLVEEzazhYZXZwd1pCUjNqbWJmcEhCamFrQzdzUll1CkI0a2tUUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'

# various flags
class FLAGS():
    # linux/if_ether.h
    ETH_P_ALL       = 0x0003 # all protocols
    ETH_P_IP        = 0x0800 # IP only
    # linux/if.h
    IFF_PROMISC     = 0x100  # promiscuous mode for interface
    # linux/sockios.h
    SIOCGIFFLAGS    = 0x8913 # get the active flags
    SIOCSIFFLAGS    = 0x8914 # set the active flags
    # linux/if_tun.h
    TUNSETIFF       = 0x400454ca # ??
    IFF_TAP         = 0x0002     # TAP interface
    IFF_NO_PI       = 0x1000     # don't return packet details


### MAIN CLASS ###

class FunTunnel():

    def __init__(self, interface=None, host=None, port=80, client_mode=False, use_ssl=True, verbose=False, buf_size=65536):

        # create a virtual interface on server only
        if client_mode:
            self.interface      = SniffDevice(interface)
        else:
            self.interface      = TAPDevice()

        self.ifc_name           = interface

        # plaintext tunnel socket
        self._tcp_session       = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_session.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # enable socket reuse
        self.peer               = None # socket representing tunnel to peer

        self.host               = host
        self.port               = port

        # set up SSL
        # basic obfuscation of traffic - nothing more
        if use_ssl:
            with NamedTemporaryFile(mode='wb') as f:
                f.write(b64decode(ssl_cert))
                f.flush()
                

                if client_mode:
                    #self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                    self._tunnel     = self.ssl_context.wrap_socket(self._tcp_session, server_hostname='FunTunnel')
                else:
                    self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    self.ssl_context.load_cert_chain(certfile=f.name)
                    self._tunnel     = self.ssl_context.wrap_socket(self._tcp_session, server_side=True)
        else:
            self._tunnel = self._tcp_session

       
        self.net_listener       = threading.Thread(target=self._net_listener, daemon=True)
        self.tun_listener       = threading.Thread(target=self._tun_listener, daemon=True)
        self.tun_sender         = threading.Thread(target=self._tun_sender, daemon=True)
        self.outgoing_queue     = queue.Queue(100) # buffer 100 outgoing packets

        self.mac_table          = [] # table which contains MACs from other side of tunnel
        self.verbose            = verbose
        self.buf_size           = buf_size
        self.client_mode        = client_mode # true or false
        self._stop              = False


    def start(self):

        self.verbose_print('[+] Starting sniffer on {}'.format(self.ifc_name))
        self.interface.up()

        if not (self.client_mode and self.host):
            self.verbose_print('[+] Starting tunnel in server mode\n[+] Listening on port {}'.format(self.port))
            print(self.host, self.port)
            self._tunnel.bind((self.host, self.port))
            self._tunnel.listen(0)

        self.tun_sender.start()
        self.tun_listener.start()
        self.net_listener.start()

        while not self._stop:
            sleep(1)


    def stop(self):

        self._stop = True
        self.peer.shutdown()
        self.peer.close()
        if not self.client_mode:
            self._tunnel.shutdown(socket.SHUT_RDWR)
        self.sniffer.stop()


    def _net_listener(self):

        while not self._stop:
            packet = self.interface.read()
            self.proc_net_incoming(packet)


    def _tun_listener(self):

        self.verbose_print('[+] Starting tunnel listener')

        while not self._stop:

            if self.peer is not None:
                try:
                    with self.peer.makefile(mode='rb') as p:
                        packet = pickle.load(p)
                    self.proc_tun_incoming(packet)

                except:
                    if self._stop:
                        break
                    else:
                        self.verbose_print('[!] Error receiving from tunnel')
                        self._reset_tunnel()

            else:
                self.verbose_print('[!] No tunnel yet')
                self._reset_tunnel()
                sleep(.1)


    def _tun_sender(self):

        while not self._stop:
            packet = self.outgoing_queue.get()
            self.proc_tun_outgoing(packet)            


    def proc_net_incoming(self, packet):
        '''
        process packets sniffed off the wire
        '''

        # source and destination MAC addresses
        src,dst = packet[6:12],packet[:6]

        if self.verbose:
            s = ':'.join('{:02X}'.format(i) for i in src)
            d = ':'.join('{:02X}'.format(i) for i in dst)
            print('[*] {} -> {}'.format(s, d), end='', flush=True)

        is_multicast = (dst[0] & 1) == 1 # least significant bit in most significant byte

        # if destination is on the other side of the tunnel
        # or if it's multicast/broadcast
        if (dst in self.mac_table) or (src not in self.mac_table and is_multicast):

            self.verbose_print(' SENDING')

            # send it across the tunnel
            try:
                self.outgoing_queue.put(packet)
            except queue.Full:
                self.verbose_print('[!] Outgoing queue is full. Dropping packet.')
                sleep(.1)
            
        else:
            self.verbose_print('')


    def proc_tun_incoming(self, packet):
        '''
        process incoming packets from tunnel

        from https://github.com/python/cpython/blob/master/Modules/socketmodule.c:
            - an AF_PACKET socket address is a tuple containing a string
            specifying the ethernet interface and an integer specifying
            the Ethernet protocol number to be received. For example:
            ("eth0",0x1234).  Optional 3rd,4th,5th elements in the tuple
            specify packet-type and ha-type/addr.
        '''

        src= packet[6:12]

        # add source MAC to table
        if not src in self.mac_table:
            self.verbose_print('[+] Adding new MAC {}'.format(':'.join('{:02X}'.format(i) for i in src)))
            self.mac_table.append(src)

        self.interface.write(packet)


    def proc_tun_outgoing(self, packet):
        '''
        sends a packet across the tunnel
        '''

        try:
            if self.peer is not None:
                with self.peer.makefile(mode='wb') as p:
                    pickle.dump(packet, p)

        except BrokenPipeError:
            self._reset_tunnel()


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
                self._tunnel.connect((self.host, self.port))
                self.peer = self._tunnel
            else:
                self.peer,address = self._tunnel.accept()
                print('\n[+] Connection from {}\n'.format(address[0]))

        except (OSError,ValueError) as e:
            self._stop = True
            self.err_print('Error setting up tunnel:\n{}'.format(str(e)))




### TAP DEVICE CLASS ###


class TAPDevice:

    def __init__(self, name='fun0', addr=None):

        self.name = name
        self.addr = addr
        self.dev = None


    def up(self):

        self.dev = self.create_tap_dev()
        self.set_addr()


    def read(self, num_bytes=2048):

        return os.read(self.dev, num_bytes)


    def write(self, data):

        os.write(self.dev, data)


    def create_tap_dev(self):
        '''
        Creates TUN (virtual network) device.
        Returns:
            file descriptor used to read/write to device.
        '''

        TUNSETIFF       = 0x400454ca # ??
        IFF_TAP         = 0x0002     # TAP interface
        IFF_NO_PI       = 0x1000     # don't return packet details

        ifr = struct.pack('16sH', self.name.encode('ascii'), IFF_TAP | IFF_NO_PI)
        fid = os.open('/dev/net/tun', os.O_RDWR)
        ioctl(fid, TUNSETIFF, ifr)
        return fid


    def set_addr(self):
        '''
        Assign IP address to TAP device
        '''

        if os.name == 'posix':

            # if we want to have an IP
            if self.addr:
                # assign it to the interface
                run(['ip', 'addr', 'add', '{}/24'.format(self.addr), 'dev', self.name])

            run(['ip', 'link', 'set', 'up', 'dev', self.name])




### SNIFFER CLASS ###

# most of this code is shamelessly borrowed from zeigotaro's "python-sniffer"
# https://github.com/zeigotaro/python-sniffer/blob/master/snifferCore.py


class SniffDevice(): 
    '''
    Basic sniffer class

        with SniffDevice(interface) as stream:
            for packet in stream:
                do_stuff(packet)

    or

        s = SniffDevice(interface)
        s.start()
        s.socket.recv(65536)
        s.stop()
    '''

    def __init__(self, interface=None):

        self.interface  = interface
        self.started    = False

        if os.name == 'posix':
            assert interface, "Please specify interface"

            # htons: converts 16-bit positive integers from host to network byte order
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))

        else:
            # create a raw socket and bind it to the public interface
            #self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(FLAGS.ETH_P_ALL))


    def up(self):

        if not self.started:

            # prevent socket from being left in TIME_WAIT state, enabling reuse
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if os.name == 'posix':

                self.socket.bind((self.interface, 0))
                
                # enable promiscuous mode
                ifc = self.interface.encode('ascii')
                ifr = bytearray(struct.pack('16sH', ifc, 0)) # create the struct
                ioctl(self.socket, FLAGS.SIOCGIFFLAGS, ifr) # get the flags
                ifr = bytearray(struct.pack('16sH', ifc, struct.unpack('16sH', ifr)[1] | FLAGS.IFF_PROMISC)) # add the promiscuous flag
                ioctl(self.socket, FLAGS.SIOCSIFFLAGS, ifr) # update
                self.ifr = ifr

            else:
                # the public network interface
                HOST = socket.gethostbyname(socket.gethostname())

                self.socket.bind((HOST, 0))
                #self.socket.bind((HOST, 0))

                # include IP headers
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

                # enable promiscuous mode
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            self.started = True


    def read(self, buf_size=65536):

        if os.name == 'posix':
            return self.socket.recv(buf_size)
        else:
            #return self.socket.recvfrom(buf)[0]
            return self.socket.recv(buf_size)


    def write(self, data):

        self.socket.send(data)


    def down(self):

        self.__exit__()


    def packet_stream(self, buf_size=65536):

        self.up()

        while 1:
            yield self.socket.recv(buf_size)
    

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
        if os.name == 'posix':
            ifc,flags = struct.unpack('16sH', self.ifr) ^ FLAGS.IFF_PROMISC # mask it off (remove)
            self.ifr = bytearray(struct.pack('16sH', ifc, flags))
            ioctl(self.socket, FLAGS.SIOCSIFFLAGS, self.ifr) # update

        else:
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        self.socket.close()
        self.started = False



def get_interface():
    # TODO: handle M$

    # handle Linux
    if os.name == 'posix':

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

    parser = argparse.ArgumentParser(description="im in ur network sniffin ur packetz")

    parser.add_argument('host',                 nargs='?',      default='0.0.0.0',  help="connect to host (client mode) or bind to (server mode)")
    parser.add_argument('-c', '--client',       action='store_true',                help="client mode (default: server)")
    parser.add_argument('-i', '--interface',                    default=def_ifc,    help="interface to bridge (default: {})".format(def_ifc), metavar='')
    parser.add_argument('-p', '--port',         type=int,       default=8080,       help="port number on which to listen/connect (default: 8080)", metavar='')
    parser.add_argument('-v', '--verbose',      action='store_true',                help="print what's happening")

    try:

        options = parser.parse_args()
        if os.name == 'posix':
            assert options.interface, "Please specify interface"
        assert (not options.client) or (options.host != parser.get_default('host')), "Please specify host for client mode"

        t = FunTunnel(interface=options.interface, host=options.host, port=options.port, client_mode=options.client, verbose=options.verbose)
        t.start()


    except argparse.ArgumentError:
        sys.stderr.write("\n[!] Check your syntax. Use -h for help.\n")
        exit(2)
    except AssertionError as e:
        sys.stderr.write("\n[!] {}\n".format(str(e)))
        exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Program interrupted.\n")
        exit(2)

    finally:
        try:
            t.stop()
        except:
            pass