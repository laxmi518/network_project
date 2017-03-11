#!/usr/bin/python
# -*- encoding: iso-8859-1 -*-

"""
    Python netflow client.

    python client.py 5  //for v5
    python clien.py 9   //for v9
"""
import socket

def get_v5_message():
    with open("v5-data.txt", "rb") as v5:
        message = v5.read()
        return message

def get_v9_message():
    with open("v9-advance-data.txt", "rb") as v9:
        message = v9.read()
        return message

def get_v10_message():
    with open("v10-advance-data.txt", "rb") as v10:
        message = v10.read()
        return message

def netflow(message, host = '127.0.0.1', port=9001):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (host, port))
    sock.close()


if __name__ == "__main__":
    import sys
    version = int(sys.argv[1])
    num = 1
    if len(sys.argv) > 2:
        num = int(sys.argv[2]) or 10
    if version == 5:
        message = get_v5_message()
    elif version == 9:
        message = get_v9_message()
    else:
        message = get_v10_message()

    for i in xrange(num):
        netflow(message)
