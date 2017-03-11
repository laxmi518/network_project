#!/usr/bin/env python
# -*- coding: utf-8 -*-


def encode(buffer, charset):
    """encodes the given buffer with charset codec into utf-8
    if charset is already utf-8, the buffer is purified by replacing
    non-utf-8 chars by '�'
    """
    # print "Here ", buffer, charset
    charset = charset or 'utf8'
    try:
        ubuffer = unicode(buffer, charset)
    except UnicodeDecodeError:
        # print("log data could not be decoded using %s; log=%r; err: %s" %
        #       (charset, buffer, err), UnicodeWarning)
        ubuffer = unicode(buffer, charset, 'replace')
    return ubuffer.encode('utf-8')
