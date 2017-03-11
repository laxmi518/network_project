#!/usr/bin/python
# -*- encoding: iso-8859-1 -*-

"""
    Python syslog client.

    This code is placed in the public domain by the author.
    Written by Christian Stigen Larsen.

    This is especially neat for Windows users, who (I think) don't
    get any syslog module in the default python installation.

    See RFC3164 for more info -- http://tools.ietf.org/html/rfc3164

    Note that if you intend to send messages to remote servers, their
    syslogd must be started with -r to allow to receive UDP from
    the network.
    """

import sys
import argparse
import socket

# I'm a python novice, so I don't know of better ways to define enums

FACILITY = {
	'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
	'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
	'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
	'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
	'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
	'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
	'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}


def syslog(message, host = '127.0.0.1', port=1514,  protocol = "udp", level=LEVEL['notice'], facility=FACILITY['daemon']):
    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = '<%d>%s' % (level + facility*8, message)
        sock.connect((host, port))
        sock.send(data)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# socket.SOCK_DGRAM)    
        # data = '<%d>%s' % (level + facility*8, message)
        data = message
        sock.sendto(data, (host, port))
        sock.close()

def syslog_file(data, host = '127.0.0.1', port=1514,  protocol = "udp"):
    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # data = '<%d>%s' % (level + facility*8, message)
        sock.connect((host, port))
        sock.send(data)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# socket.SOCK_DGRAM)    
        # data = '<%d>%s' % (level + facility*8, message)
        sock.sendto(data, (host, port))
        sock.close()

def syslog_msg(data, host = '127.0.0.1', port=1514,  protocol = "udp"):
    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # data = '<%d>%s' % (level + facility*8, message)
        sock.connect((host, port))
        sock.send(data)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)# socket.SOCK_DGRAM)    
        # data = '<%d>%s' % (level + facility*8, message)
        sock.sendto(data, (host, port))
        sock.close()

# message = "<14>Mar 29 2004 09:56:39: %PIX-5-304001: 192.168.0.2 Accessed URL 216.52.17.116:/b/ss/novellcom/0/G.1-XP-R/s14102280031206?[AQB]purl=http%3A%2F%2Fwww.novell.com%2Fde-de%2F&pccr=true&&ndh=1&t=29/2/2004%2012%3A20%3A20%201%20-120&ch=www.novell.com/de-de/&se"

# message = "<14>Apr 22 19:12:12 1,2013/04/22 19:12:12,001606001785,TRAFFIC,start,1,2013/04/22 19:12:11,192.168.168.150,108.160.160.177,90.225.6.231,108.160.160.177,10_Internet,,,dropbox,vsys1,Trust_Inside,Untrust_Inet,ethernet1/2,ethernet1/1,Logfrwd-LP-DK,2013/04/22 19:12:12,49711,1,51010,443,56321,443,0x400000,tcp,allow,1936,282,1654,6,2013/04/22 19:12:11,1,online-personal-storage,0,1779008,0x0,192.168.0.0-192.168.255.255,United States,0,3,3"

if __name__=="__main__":
    usage = """ Usage: python syslog_client.py -h  //for help"""
    print usage
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', default=1)
    parser.add_argument('--file', default=None)
    parser.add_argument('--msg', default = None)
    parser.add_argument('--proto', default="udp")
    parser.add_argument('--host', default="127.0.0.1")
    parser.add_argument('--port', default=1514)
    args = parser.parse_args()
    if args.file == None:
        if args.msg == None:
            print "sending", args.n, " msgs to ", str(args.host)+ ":"+ str(args.port), " using ", args.proto 
            for i in xrange(int(args.n)):
                syslog(message, args.host, int(args.port), args.proto)
        else:
            print "sending", args.n, " msgs to ", str(args.host)+ ":"+ str(args.port), " using ", args.proto, "using msg ", args.msg  
            print len(args.msg)
            # args.msg = "abc\n"
            syslog_msg(args.msg, args.host, int(args.port), args.proto)
    else:
        print "sending", args.n, " msgs to ", str(args.host)+ ":"+ str(args.port), " using ", args.proto , "using file", args.file
        lines = []
        with open(args.file) as f:
            for line in f:
                if line:
                    line = line.strip()
                    line = line + "\n"
                    lines.append(line)
        # print lines
        while True:
            for line in lines:
                syslog_file(line, args.host, int(args.port), args.proto)