
import logging
import re

from LineParser import LineParser
from pylib import timestamp, msgfilling

log = logging.getLogger(__name__)


class SyslogParser(LineParser):

    def __init__(self, sid=None, charset=None):
        super(SyslogParser, self).__init__(sid, charset)

        self.regex = re.compile(r"""\s*
            (?:<(?P<pri>\d{1,3})>)?\s*  # some clients dont send <pri> digit
            (?:(?P<log_time>[a-zA-Z]{3}\s+\d{1,2}\s+(?P<year>\d{4}\s+)?\d\d:\d\d:\d\d))?
            """, re.VERBOSE)

    def next(self):
        event = super(SyslogParser, self).next()
        found = self.regex.match(event['msg'])

        if not found:
            # this never happens because everything is optional in regex
            log.warn('syslog parser; received message with incorrect syslog format;'
                     ' sid=%s; msg=%r', self.sid, event['msg'])
        else:
            pri = found.group('pri')
            log_time = found.group('log_time')
            year = found.group('year')

            if not pri and not log_time:
                log.info('syslog parser; received message with incorrect syslog format;'
                         ' sid=%s; msg=%r', self.sid, event['msg'])
            else:
                event["_normalized_fields"] = {}
                if log_time:
                    if year:
                        log_ts = timestamp.fromsyslogtime_with_year(log_time)
                    else:
                        try:
                            log_ts = timestamp.fromsyslogtime(log_time)
                        except ValueError:
                            log.warn("error while parsing log_ts; possibly because client timezone is not UTC; sid=%s; log_time=%s", self.sid, log_time)
                            log_ts = None

                    if log_ts:
                        event["_normalized_fields"]["log_ts"] = log_ts

                        #event['log_ts'] = log_ts
                        msgfilling.add_types(event, '_type_num', 'log_ts')

                if pri:
                    pri = int(pri)
                    sev = pri % 8
                    fac = pri // 8

                    event["_normalized_fields"]["severity"] = sev
                    event["_normalized_fields"]["facility"] = fac

                    #event['severity'] = sev
                    #event['facility'] = fac
                    msgfilling.add_types(event, '_type_num', 'severity facility')

        return event


if __name__ == '__main__':
    sp = SyslogParser()

    sp.write('<23> Jan 12 23:59:59 hello world\n<24> Jan 13 23:59:59 hello foobar\n')
    sp.write(' <166>Aug 11 2011 12:58:28: %as 1313046808\n')
    sp.write('<14>last message repeated 8 times\n')

    for msg in sp:
        print msg
