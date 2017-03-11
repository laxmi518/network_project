
import os
import time
import unittest
import socket
import ssl
from subprocess import Popen
import re

import gevent
from pylib.wiring import gevent_zmq as zmq
from nose.tools import eq_
from pylib import wiring, disk, conf, inet


class test_snare_collector(unittest.TestCase):
    os.environ["TZ"] = "UTC"
    zmq_context = zmq.Context()

    def setUp(self):
        # snare collector forwards the received msg to normalizer_in
        # starting snare collector
        config_path = disk.get_sibling(__file__, 'test-config.json')
        config = conf.load(config_path)
        self.port = config['port']

        self.normalizer = wiring.Wire('norm_front_in',
                zmq_context=self.zmq_context)

        self.snare_collector = Popen(['python', 'snare_collector.py',
                                       config_path])
        # Allow to prepare for serving
        time.sleep(0.5)

    def tearDown(self):
        self.snare_collector.kill()
        self.normalizer.close()
        time.sleep(0.5)

    def send_message(self, address=None, message=None, flow='udp'):
        address = address or ('127.0.0.1', self.port)
        message = message or "<124> May 06 2012 15:02:24 [emerg] (17)File exists: Couldn't create accept lock (/private/var/log/apache2/accept.lock.19) (5)\n"

        host, port = address
        if flow == 'tcp':
            client, sockaddr = inet.create_address(host, port)
            client.connect(sockaddr)
            client.send(message)
        elif flow == 'ssl':
            client, sockaddr = inet.create_address(host, port)
            client = ssl.wrap_socket(client)
            client.connect(sockaddr)
            client.send(message)
        elif flow == 'udp':
            client, sockaddr = inet.create_address(host, port,
                    socket.SOCK_DGRAM)
            client.sendto(message, sockaddr)
        else:
            raise ValueError('Unknown flow type: %r' % flow)

        event = gevent.with_timeout(5, self.normalizer.recv, timeout_value=None)

        mid = event.pop('mid')
        assert re.match(r'^LogInspect500\|snare\|(127.0.0.1|::1)\|\d+\|1$', mid)
        eq_(event, dict(
            msg=message.rstrip('\n'),
            severity=4,
            facility=15,
            log_ts=1336316544,
            device_ip=address[0],
            device_name='localhost',
            collected_at='LogInspect500',
            _type_num='log_ts severity facility',
            _type_str='msg device_name collected_at',
            _type_ip='device_ip',
            ))

    def test_tcp_basic_flow(self):
        self.send_message(flow='tcp')

    def test_udp_basic_flow(self):
        self.send_message(flow='udp')

    def test_tcp6_flow(self):
        self.send_message(('::1', self.port), flow='tcp')

    def test_udp6_flow(self):
        self.send_message(('::1', self.port), flow='udp')


if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
