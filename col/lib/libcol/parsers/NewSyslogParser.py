import logging
import pyparsing

from LineParser import LineParser

log = logging.getLogger(__name__)

sp = pyparsing.White(" ", exact=1)
nilvalue = pyparsing.Word("-")
time_hour = pyparsing.Regex('0[0-9]|1[0-9]|2[0-3]')
time_minute = pyparsing.Regex('[0-5][0-9]')
time_second = time_minute
time_secfrac = pyparsing.Regex('\.[0-9]{1,6}')
time_numoffset = pyparsing.Or([pyparsing.Regex('\+'), pyparsing.Regex('-')]) + \
                 time_hour + ':' + time_minute
time_offset = pyparsing.Or([pyparsing.Regex('Z'), time_numoffset])
partial_time = time_hour + ':' + time_minute + ':' + time_second + \
               pyparsing.Optional(time_secfrac)
full_time = partial_time + time_offset
date_mday = pyparsing.Regex('[0-9]{2}')
date_month = pyparsing.Regex('0[1-9]|1[0-2]')
date_fullyear = pyparsing.Regex('[0-9]{4}')
full_date = date_fullyear + '-' + date_month + '-' + date_mday
timestamp = pyparsing.Combine(pyparsing.Or([nilvalue, full_date + 'T' + full_time]))
timestamp = timestamp.setResultsName('TIMESTAMP')

version = pyparsing.Regex('[1-9][0-9]{0,2}').setResultsName('VERSION')
prival = pyparsing.Regex("[0-9]{1,3}").setResultsName('PRIVAL')
pri = "<" + prival + ">"

msg_len = pyparsing.Word(pyparsing.nums)
header = pyparsing.Optional(msg_len + sp) + pyparsing.Optional(pri) + pyparsing.Optional(version + sp) + timestamp

class rfc5424Parser(LineParser):

    def __init__(self, sid=None, charset=None):
        #In case two newlines come at once
        super(rfc5424Parser, self).__init__(sid, charset, True, False)

        self.memory = ""

    def next(self):
        while True:
            #Get a line from the log
            event = super(rfc5424Parser, self).next()

            #Check to see if it matches the syslog header format
            #match = self.regex.match(event['msg'])
            try:
                header.parseString(event['msg'])
                #If it matches, then send the buffer to uppler layer
                if self.memory:
                    to_return = self.memory
                    self.memory = event
                    return to_return
                else:
                    self.memory = event

            except:
                #Add the current line to memory as the start of new msg or the continuation of
                #old message

                if self.memory:
                    message = self.memory['msg'] + '\n' + event['msg']
                    self.memory.update(event)
                    self.memory['msg'] = message
                else:
                    self.memory = event

if __name__ == '__main__':
    rp = rfc5424Parser()

    rp.write('123 <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMThis is a \nashok\nmessage..\n', old_parser=True)
    rp.write('<166>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMThis is a \n\n\nmessage..\n', old_parser=True)

    rp.write('2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMThis is a \n\nmessage..\n', old_parser=True)
    rp.write('<168>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMThis is a \n\nmessage..\n', old_parser=True)
    for msg in rp:
        print msg
