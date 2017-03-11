# -*- coding: utf-8

import logging
import warnings

class LineParser(object):

    def __init__(self, sid=None, charset=None, strip=True, skip_if_empty=True):
        self.sid = sid
        self.charset = charset
        self.buffer = ''
        self.buffer_limit = 10000
        self.strip = strip
        self.skip_if_empty = skip_if_empty

    def write(self, buffer, old_parser=False):
        self.stop_iter = False
        self.old_parser = old_parser
        buffer = encode(buffer, self.charset, self.sid)
        self.buffer += buffer

        if len(self.buffer) >= self.buffer_limit:
            logging.warn("Log message too long; sent by sid=%s; msg=%r",
                         self.sid, self.buffer[:100])
            self.buffer = ""

    def __iter__(self):
        return self

    def next(self):
        if self.old_parser:
            msg_buffer = self.buffer.split('\n', 1)
            if len(msg_buffer) == 2:
                msg, self.buffer = msg_buffer
                if self.strip:
                    msg = msg.strip()
                if self.skip_if_empty and msg == "":
                    return self.next()
                return dict(msg=msg, _type_str='msg')
            else:
                self.buffer = msg_buffer[0]
                raise StopIteration
        else:
            if self.stop_iter:
                raise StopIteration
            
            msg_buffer = self.buffer.split('\n', 1)
            if len(msg_buffer) == 2:
                msg, self.buffer = msg_buffer
            else:
                self.stop_iter = True
                msg = msg_buffer[0]
                self.buffer = ''
            
            if self.strip:
                msg = msg.strip()
            if self.skip_if_empty and msg == "":
                return self.next()
            return dict(msg=msg, _type_str='msg')


def encode(buffer, charset, sid=None):
    """encodes the given buffer with charset codec into utf-8
    if charset is already utf-8, the buffer is purified by replacing non-utf-8 chars by '�
    """
    charset = charset or 'utf8'
    try:
        ubuffer = unicode(buffer, charset)
    except UnicodeDecodeError, err:
        warnings.warn("log data could not be decoded using %s; sid=%s; log=%r" % (
                    charset, sid, buffer), UnicodeWarning)
        ubuffer = unicode(buffer, charset, 'replace')
    return ubuffer.encode('utf-8')


if __name__ == '__main__':
    lp = LineParser()

    lp.write('apple\n\nmango\nbanana\ncoco')

    for line in lp:
        print line

    lp.write('nut\ngrapes')

    for line in lp:
        print line

    #msg = "Jan 14 16:28:35 Manishs-MacBook-Pro com.apple.SecurityServer[24]: Killing auth hosts"
