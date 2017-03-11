
import os
import re
import logging

from pylib.make_greenletsafe_fabric import patch; patch()
from pylib.ipv6_fabric import patch; patch()

from fabric.api import env, get, hide
from fabric.sftp import SFTP

from pylib import homing

private_keyfile = homing.home_join("storage/col/scp_fetcher/ssh/id_rsa")

def setup(ip, port, user, password=None):
    env.linewise = True
    env.abort_on_prompts = True
    env.no_keys = True

    env.host_string = "%s@%s:%s" % (user, ip, port)

    if password:
        env.key_filename = None
        env.password = password
    else:
        env.key_filename = private_keyfile
        env.password = None

def _check_regex_match(pattern, file_path):
    if not pattern:
        return True

    file_name = os.path.basename(file_path)
    regex = re.compile(pattern)
    if regex.search(file_name):
        return True

    return False

def fetch_file_mtime(remotepath, pattern=None):
    sftp = SFTP(env.host_string)
    if not sftp.isdir(remotepath):
        logging.debug('%s is not dir', remotepath)
        normalized_path = sftp.normalize(remotepath)
        parent = os.path.dirname(normalized_path)
        for f in sftp.ftp.listdir_attr(parent):
            if f.filename == os.path.basename(remotepath):
                if _check_regex_match(pattern, f.filename):
                    yield remotepath, f.st_mtime
                break
    else:
        logging.debug('%s is dir', remotepath)
        for filename, mtime in fetch_fileinfos(sftp, remotepath):
            if _check_regex_match(pattern, filename):
                yield filename, mtime
        for context, dirs, files in sftp.walk(remotepath):
            for dir in dirs:
                folder = os.path.join(context, dir)
                for filename, mtime in fetch_fileinfos(sftp, folder):
                    if _check_regex_match(pattern, filename):
                        yield filename, mtime

def fetch_fileinfos(sftp, folder):
    for f in sftp.ftp.listdir_attr(folder):
        filename = os.path.join(folder, f.filename)
        if not sftp.isdir(filename):
            yield filename, f.st_mtime

def scp_get(remotepath, localpath=None):
    with hide('everything'):
        result = get(remotepath, localpath)
    return result


if __name__ == '__main__':
    setup('192.168.2.205', 22, 'sujan', 'suzan123')
    print scp_get('sujan', 'log')
    print 'done'
