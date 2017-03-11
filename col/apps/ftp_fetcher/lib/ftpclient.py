
import calendar
import cStringIO as StringIO
import logging
import os
import ftplib
import re
import time

FILES_RE = re.compile(r'^-.*?\d\d:\d\d (.*?)$', re.MULTILINE)
DIRS_RE = re.compile(r'^d.*?\d\d:\d\d (.*?)$', re.MULTILINE)
error_proto_msg_re = re.compile(r"""25\d ['"](.*)['"] is the current directory.""")


def remove_null_char(data):
    return data.replace('\x00', '')


def safe_ftp(func, *args, **kwargs):
    """Some functions such as pwd and cwd in ftplib raises error with status code 25x
    eg: 250, 257, after the function call succeeds.
    While some functions raise error with 200 when switching ascii and binary mode in between the commands
    used by the functions.

    This function silently passes those errors.
    """

    try:
        return func(*args, **kwargs)
    except Exception, err:
        message = remove_null_char(str(err))
        if isinstance(err, ftplib.error_proto) and (message.startswith('250') or message.startswith('257')):
            logging.debug("Silently handling exception: %r", message)
            return error_proto_msg_re.search(message).group(1)
        elif message.startswith("200 Type set to:") or message.startswith("213 "):
            logging.debug("Retrying after: %r", message)
            return func(*args, **kwargs)
        else:
            raise


def get_mtime(ftp, path):
    result = safe_ftp(ftp.sendcmd, 'MDTM %s' % path)
    mtime_gmt = result.split()[1][:14]
    struct = time.strptime(mtime_gmt, "%Y%m%d%H%M%S")
    return calendar.timegm(struct)


def login(ip, port, user, password, cwd=None):
    ftp = ftplib.FTP()
    ftp.connect(ip, port)
    logging.info('Connected to %s:%s', ip, port)

    ftp.login(user, password)
    logging.info('Logged in with %s', user)
    if cwd:
        safe_ftp(ftp.cwd, cwd)
    return ftp


def isdir(ftp, path):
    pwd = safe_ftp(ftp.pwd)
    try:
        safe_ftp(ftp.cwd, path)
        isdir = True
        safe_ftp(ftp.cwd, pwd)
    except Exception, err:
        message = remove_null_char(str(err))
        if message.startswith("550"):
            logging.debug("not dir because err=%r", err)
            isdir = False
        else:
            raise
    return isdir


def listdir(ftp, path=None):
    path = path or '.'
    output_buffer = StringIO.StringIO()
    safe_ftp(ftp.retrbinary, 'LIST %s' % path, output_buffer.write)
    data = output_buffer.getvalue()
    data = remove_null_char(data)
    logging.debug('LIST output: %r', data)
    files = FILES_RE.findall(data)
    dirs = DIRS_RE.findall(data)
    files = [file.rstrip('\r') for file in files]
    dirs = [dir.rstrip('\r') for dir in dirs]
    return dirs, files


def walk(ftp, top, topdown=True, onerror=None):
    try:
        dirs, files = listdir(ftp, top)
    except Exception, err:
        logging.warn(err)
        if onerror is not None:
            onerror(err)
        return
    if topdown:
        yield top, dirs, files
    for name in dirs:
        path = os.path.join(top, name)
        for x in walk(ftp, path, topdown, onerror):
            yield x
    if not topdown:
        yield top, dirs, files

def _check_regex_match(pattern, file_path):
    if not pattern:
        return True

    file_name = os.path.basename(file_path)
    regex = re.compile(pattern)
    if regex.search(file_name):
        return True

    return False

def fetch_file_mtime(ftp, remotepath, pattern=None):
    if not isdir(ftp, remotepath):
        logging.debug('%s is not dir', remotepath)
        mtime = get_mtime(ftp, remotepath)
        if _check_regex_match(pattern, remotepath):
            yield remotepath, mtime
        return

    logging.debug('%s is dir', remotepath)
    for context, dirs, files in walk(ftp, remotepath):
        for file in files:
            remotefile = os.path.join(context, file)
            mtime = get_mtime(ftp, remotefile)
            if _check_regex_match(pattern, remotefile):
                yield remotefile, mtime


def download(ftp, remotefile, localfile):
    with open(localfile, 'wb', 10*1024) as f:
        try:
            ftp.retrbinary('RETR %s' % remotefile, f.write)
        except Exception, err:
            message = remove_null_char(str(err))
            if message.startswith("550"):
                # no such file or directory/permission error etc.
                os.unlink(localfile)
            raise type(err)(message)
