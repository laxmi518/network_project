#!/usr/bin/env python

from gevent import monkey; monkey.patch_all()

import logging
import os
from pyftpdlib import ftpserver

from pylib import disk, homing, inet, textual, conf
from fi_applications import make_zip

ftpserver.log = lambda msg: logging.info(msg)
ftpserver.logline = lambda msg: logging.debug(msg)


def _parse_args():
    options, config = conf.parse_config()
    return config

class FTPHandler(ftpserver.FTPHandler):

    def __init__(self, conn, server, config):
        ftpserver.FTPHandler.__init__(self, conn, server)
        
        self.ip = inet.get_ip(conn.getpeername())
        
        logging.warn('FileInspect FTP Server; Connection attempted from IP %r' % self.ip)

        self.authorizer = ftpserver.DummyAuthorizer()

        user = config['username']
        password = config['password']
        basedir = config['basedir'].replace('$LOGINSPECT_HOME',
                                                homing.LOGINSPECT_HOME)
        permission = config['permission']
        
        self.authorizer.add_user(user, password, basedir, permission)
    
    def on_login(self, username):
        logging.warn('FileInspect FTP Server; User %r login from IP %r' % (username, self.ip))
    
    def on_login_failed(self, username, password):
        logging.warn('FileInspect FTP Server; User %r login failed from IP %r' % (username, self.ip))
    
    def on_logout(self, username):
        logging.warn('FileInspect FTP Server; User %r logout from IP %r' % (username, self.ip))
    
    def on_file_sent(self, file):
        logging.warn('FileInspect FTP Server; File %r sent to IP %r' % (file, self.ip))
    
    def on_incomplete_file_sent(self, file):
        logging.warn('FileInspect FTP Server; Incomplete file %r sent to IP %r' % (file, self.ip))

def make_inet6_compatible(ftpserver, port):
    if ftpserver.socket:
        ftpserver.socket.close()
    # create_socket in FTPServer
    sock, sockaddr = inet.create_external_address(port)
    sock.setblocking(0)
    ftpserver.set_socket(sock)

    ftpserver.set_reuse_addr()
    ftpserver.bind(sockaddr)
    ftpserver.listen(5)

def _prepare_application_directory(config):
    make_zip.create_zipped_application_packages(config['basedir'])

def main():
    #config = {'port':221, 'username':'fileinspect', 'password':'f1leInspecT', 'permission': 'lr', 'basedir':'c:\\test1\\'}
    config = _parse_args()
    config = textual.utf8(config)
    
    _prepare_application_directory(config)
    
    port = config['port']
    address = ('0.0.0.0', port)
    
    logging.warn('starting fileinspect ftp server')
    ftpd = ftpserver.FTPServer(address,
                               lambda conn, server:
                               FTPHandler(conn, server, config))
    FTPHandler.use_sendfile = False
    
    make_inet6_compatible(ftpd, port)

    ftpd.max_cons = 256
    ftpd.max_cons_per_ip = 5
    ftpd.serve_forever()


if __name__ == '__main__':
    main()
