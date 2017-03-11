#!/usr/bin/env python

from gevent import monkey; monkey.patch_all()

import logging
import os
import time
from pyftpdlib import ftpserver

from libcol.collectors import file_handler, shelves
from libcol import config_reader
from pylib import conf, disk, homing, textual, inet

ftpserver.log = lambda msg: logging.info(msg)
ftpserver.logline = lambda msg: logging.debug(msg)


def _parse_args():
    options, config = conf.parse_config()
    return config


class FTPHandler(ftpserver.FTPHandler):

    def __init__(self, conn, server, config, db_file):
        ftpserver.FTPHandler.__init__(self, conn, server)

        self.config = config = textual.utf8(config)
        self.ip = inet.get_ip(conn.getpeername())
        self.db_file = db_file

        self.config_ip = config_reader.get_config_ip(self.ip, config)
        if not self.config_ip:
            conn.send('Please add your device %s to ftp_collector in LogInspect to send logs.\n' % self.ip)
            self.close()
            return

        self.profiles = config['client_map'][self.config_ip]
        
        # TODO use hashed password in config file
        self.authorizer = ftpserver.DummyAuthorizer()

        for user, profile in self.profiles.iteritems():
            password = profile['password']
            permission = profile['permission']

            basedir = config['basedir'].replace('$LOGINSPECT_HOME',
                                                homing.LOGINSPECT_HOME)
            home = profile['home'].lstrip('/')  # let home not be absolute path

            user_home = os.path.join(basedir, home)
            disk.prepare_path(user_home + '/')

            self.authorizer.add_user(user, password, user_home, permission)

    def on_file_received(self, localfile):
        profile = self.config['client_map'][self.config_ip][self.username]
        sid = profile['sid']
        parser = profile['parser']
        charset = profile['charset']
        device_name = profile['device_name']
        device_ip = self.ip
        logging.debug('file transfer; completed')

        vc = shelves.VersionChecker(self.db_file, sid, localfile)
        cursor = vc.get_old_cursor(localfile)
        if cursor < 0:
            return
        file_handler.main(sid, time.time(), parser, localfile, charset, device_name, cursor,
                profile.get('regex_pattern'), profile.get('regexparser_name'), device_ip,
                conf_path=self.config.get('wiring_conf_path') or None)

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


def main():
    config = _parse_args()
    port = config['port']
    address = ('0.0.0.0', port)
    
    basedir = config['basedir'].replace('$LOGINSPECT_HOME', homing.LOGINSPECT_HOME)
    
    db_file = os.path.join(basedir, 'checksums.pdict')
    
    ftpd = ftpserver.FTPServer(address,
                               lambda conn, server:
                                FTPHandler(conn, server, config, db_file))
    make_inet6_compatible(ftpd, port)

    ftpd.max_cons = 256
    ftpd.max_cons_per_ip = 5
    ftpd.serve_forever()


if __name__ == '__main__':
    main()
