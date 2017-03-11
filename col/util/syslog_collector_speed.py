import socket
import sys
import time

from pylib.timing import speed_printer
from multiprocessing import Pool

class mysocket:
    '''demonstration class only
      - coded for clarity, not efficiency
    '''
    def __init__(self, sock=None):
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        totalsent = 0
        msglen = len(msg)
        while totalsent < msglen:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def close(self, host, port):
        self.sock.close()

def main(x):
    """
    Test the overall speed of the syslog collector. It generates a dummy log
    traffic at about 1000 mps to the syslog port 1514 from 30 processes
    simultaneously. The syslog collector and the sink listening on collector_out
    must be runnng
    """

    syslog_client = mysocket()
    syslog_client.connect("0.0.0.0", 1514)

    log_msg = "Jan 14 00:01:50 sujan System Preferences[222]: .scriptSuite warning for result type of command 'timedLoad' in suite 'SystemPreferences': the type NSNumber ('long') doesn't match the result Apple event code ('doub').\n"

    sp = speed_printer(10000)
    while True:
        syslog_client.send(log_msg)
        sp.next()
        time.sleep(0.001)

    syslog_client.close()

if __name__ == '__main__':
    no_of_clients = 30
    p = Pool(no_of_clients)
    p.map(main, range(no_of_clients))
