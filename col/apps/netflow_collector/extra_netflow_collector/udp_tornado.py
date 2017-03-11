#!/urs/bin/python

import socket
import tornado
import time
import functools
from tornado import ioloop, iostream

class UDPStream(object):
    def __init__(self, socket, in_ioloop=None):
        self.socket = socket
        self._state = None
        self._read_callback = None
        self._read_timeout = 10
        self.ioloop = in_ioloop or tornado.ioloop.IOLoop.instance()

    def _add_io_state(self, state):
        if self._state is None:
            self._state = tornado.ioloop.IOLoop.ERROR | state
            self.ioloop.add_handler(
                self.socket.fileno(), self._handle_events, self._state)
        elif not self._state & state:
            self._state = self._state | state
            self.ioloop.update_handler(self.socket.fileno(), self._state)

    def send(self,msg):
        return self.socket.send(msg)

    def recv(self,sz):
        return self.socket.recv(sz)
    
    def close(self):
        self.ioloop.remove_handler(self.socket.fileno())
        self.socket.close()
        self.socket = None

    def read_chunk(self, callback=None, timeout=4):
        self._read_callback = callback
        self._read_timeout = self.ioloop.add_timeout( time.time() + timeout, 
            self.check_read_callback )
        self._add_io_state(self.ioloop.READ)

    def check_read_callback(self):
        if self._read_callback:
            # XXX close socket?
            self._read_callback(None, error='timeout');

    def _handle_read(self):
        if self._read_timeout:
            self.ioloop.remove_timeout(self._read_timeout)
        if self._read_callback:
            try:
                data = self.socket.recv(4096)
                
                return data
            except:
                # conn refused??
                data = None
            self._read_callback(data);
            self._read_callback = None
        return "Test failed"
    
    def _handle_events(self, fd, events):
        if events & self.ioloop.READ:
            self._handle_read()
        if events & self.ioloop.ERROR:
            logging.error('%s event error' % self)
            


def handle_input(self, fd, events):
    (data, source_ip_port) = self.sock.recvfrom(4096)
    bdict = bdecode(data)

    #Got a response from some previous query
    if bdict["y"] == "r":
        self.handle_response(bdict, source_ip_port)

    #Porb gonna have to ad a listenr socket
    #Got a query for something
    if bdict["y"] == "q":
        self.handle_query(bdict, source_ip_port)


def main1():
    #udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ##udpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ##udpsock.setblocking(0)
    #udpsock.bind(("", 8888))
    ##udpsock.connect( ("", 8888) )
    #s = UDPStream(udpsock)
    ###s.send("some data")
    #print "Start the loop"
    #while True:
    #    rec = s.recv(1024)
    #    if not rec:
    #        continue
    #    
    #    print rec
    
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.setblocking(False)
    udpsock.connect( ("", 8888) )
    s = UDPStream(udpsock)
    callback = functools.partial(s._handle_events)
    test_data = callback()
    print test_data
    
    
def main2():
    """
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    io_loop.add_handler(sock.fileno(), handle_input, io_loop.READ)
    
    
    
if __name__ == '__main__':
    print "Start"
    main1()
    print "End"


