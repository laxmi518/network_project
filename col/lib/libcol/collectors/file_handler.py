
"""
When file transfer is completed, ftp_collector, ftp_fetcher and
scp_fetcher will call file_handler.main()
main() sends the dict of sid, col_ts, parser and file path to
batch_processor through wiring.
"""

from pylib.wiring import Wire
from pylib import logger


log = logger.getLogger(__name__)

PROCESSOR = None


def main(sid, col_type, timestamp, parser, file_path, charset, device_name, normalizer, repo, cursor=0,
        regex_pattern=None, regexparser_name=None, device_ip=None, use_gevent=True, conf_path=None,
        source_name=None):
    """
    sends to the batch_processor zmq for processing
    """
    global PROCESSOR
    if PROCESSOR is None:
        PROCESSOR = Wire('batch_collector_out', use_gevent=use_gevent, conf_path=conf_path)

    log.info('Collector file handler; file %r; sending to batch_processor', file_path)

    file_info = {
        'sid': sid,
        'col_type': col_type,
        'col_ts': str(int(timestamp)),
        'parser': parser,
        'file': file_path,
        'cursor': cursor,
        'charset': charset,
        'device_name': device_name,
        'regex_pattern': regex_pattern,
        'regexparser_name': regexparser_name,
        'device_ip': device_ip,
        'normalizer': normalizer,
        'repo': repo,
        'source_name': source_name
    }

    PROCESSOR.send(file_info)
    log.info('Collector file handler; file %r; sent to batch_processor', file_path)
