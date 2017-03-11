import time
import socket
import sys

try:
    host = sys.argv[1]
    port = int(sys.argv[2])
    address = (host, port)
except IndexError:
    address = ('0.0.0.0', 514)

data = "<124> May 06 15:02:24 [emerg] (17)File exists: Couldn't create accept lock (/private/var/log/apache2/accept.lock.19) (5)\n"
n = 100000

print 'connecting to %s' % str(address)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(address)
print 'connected to %s' % str(address)

start = time.time()

for i in xrange(1, n):
    sock.send(data)
    print 'sent', i

duration = time.time() - start
print n, duration, n/duration

sock.close()
