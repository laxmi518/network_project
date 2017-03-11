
from nose.tools import eq_

import sys
sys.path.append('.')

from pylib import wiring
from libcol.collectors import file_handler


def test_file_handler():
    col_type = 'ftp'
    sid = 'ftp|192.168.1.2'
    col_ts = '1234567890'
    parser = 'SyslogParser'
    file = '/dummy/path'
    charset = 'utf-8'
    device_name = "makalu"
    normalizer = "norm1"
    repo = "repo1"
    device_ip="192.168.1.2"

    file_handler.main(sid, col_type, col_ts, parser, file, charset, device_name, normalizer, repo, device_ip=device_ip)

    batch_processor_in = wiring.Wire('batch_processor_in')
    event = batch_processor_in.recv()

    eq_(event, dict(sid=sid,
                col_ts=col_ts,
                parser=parser,
                file=file,
                charset=charset,
                device_name=device_name,
                cursor=0,
                normalizer=normalizer,
                repo=repo,
                device_ip=device_ip, 
                regexparser_name=None, 
                regex_pattern=None, 
                col_type=col_type
                ))

