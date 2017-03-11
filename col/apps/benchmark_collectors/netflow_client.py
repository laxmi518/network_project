#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Python netflow client.

    python client.py 5  //for v5
    python client.py 9   //for v9
    python client.py 10  //for v10
"""
import socket
import argparse


def get_v5_message():
    with open("v5-data.txt", "rb") as v5:
        message = v5.read()
        return message


def get_v9_message(file):
    with open(file, "rb") as v9:
        message = v9.read()
        return message


def get_v10_message():
    with open("v10-advance-data.txt", "rb") as v10:
        message = v10.read()
        return message


def netflow(message, host='127.0.0.1', port=9001):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (host, port))
    sock.close()


if __name__ == "__main__":
    usage = """ Usage: python client.py -h  //for help"""
    print usage
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', default=1)
    parser.add_argument('--file', default="v9-advance-data.txt")
    parser.add_argument('-v', default="v9")
    args = parser.parse_args()

    if int(args.v) == 5:
        print "sending", args.n, "packets version: ", str(args.v), \
            "using file ", "v5-data.txt"
    elif int(args.v) == 10:
        print "sending", args.n, "packets version: ", str(args.v),  \
            "using file ", "v10-advance-data.txt"
    else:
        print "sending", args.n, "packets version: ", str(args.v),  \
            "using file ", str(args.file)

    version = int(args.v)
    file = str(args.file)
    num = int(args.n) or 1
    if version == 5:
        message = get_v5_message()
    elif version == 9:
        message = get_v9_message(file)
    else:
        message = get_v10_message()

    for i in xrange(num):
        netflow(message)
