
import logging
import re
import time, datetime

from LineParser import LineParser
from pylib import timestamp, msgfilling

log = logging.getLogger(__name__)


class SnareParser(LineParser):

    def __init__(self, sid=None, charset=None):
        super(SnareParser, self).__init__(sid, charset)

        self.regex = re.compile(r"""\s*
            (?:<(?P<pri>\d{1,3})>)?\s*  # some clients dont send <pri> digit
            (?:(?P<log_time>[a-zA-Z]{3}\s+\d{1,2}\s+(?P<year>\d{4}\s+)?\d\d:\d\d:\d\d))?
            """, re.VERBOSE)

    def next(self):
        event = super(SnareParser, self).next()
        found = self.regex.match(event['msg'])

        if not found:
            # this never happens because everything is optional in regex
            log.warn('snare parser; received message with incorrect snare format;'
                     ' sid=%s; msg=%r', self.sid, event['msg'])
        else:
            pri = found.group('pri')
            log_time = found.group('log_time')
            year = found.group('year')
            flag_syslog = True
                
            if not log_time:
                log.debug("Set current time as log_time")
                log_time = time.strftime("%b %d %Y %H:%M:%S ", time.gmtime())
                #year = time.gmtime().tm_year
                log_ts = int(time.mktime(time.gmtime()))
                flag_syslog = False

            
            if not pri and not log_time:
                log.info('snare parser; received message with incorrect snare format;'
                         ' sid=%s; msg=%r', self.sid, event['msg'])
                
            else:
                if log_time and flag_syslog:
                    if year:
                        log_ts = timestamp.fromsyslogtime_with_year(log_time)
                    else:
                        try:
                            log_ts = timestamp.fromsyslogtime(log_time)
                        except ValueError, e:
                            log.warn("error while parsing log_ts; possibly because client timezone is not UTC; sid=%s; log_time=%s", self.sid, log_time)
                            log_ts = None

                if log_ts:
                    event['log_ts'] = log_ts
                    msgfilling.add_types(event, '_type_num', 'log_ts')

                if pri:
                    pri = int(pri)
                    sev = pri % 8
                    fac = pri // 8

                    event['severity'] = sev
                    event['facility'] = fac
                    msgfilling.add_types(event, '_type_num', 'severity facility')

        return event


if __name__ == '__main__':
    sp = SnareParser()

    sp.write('<23> Jan 12 23:59:59 hello world\n<24> Jan 13 23:59:59 hello foobar\n')
    sp.write('ram ram\n<166> Aug 11 2011 12:58:28: hari hari 1313046808\n')
    sp.write('Aug 11 2011 12:58:29: ram ramand ram\n')
    
    for msg in sp:
        print msg
