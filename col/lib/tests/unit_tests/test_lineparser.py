# -*- coding: utf-8

from nose.tools import eq_
from libcol.parsers import GetParser

def test_LineParser():
    lp = GetParser('LineParser')

    chunk1 = (
"5 1 2010-11-22T05:25:37+00:00 Nov 22 11:08:28 192.168.2.170 pc MSWinEventLog 4 Security 1395 Mon Nov 22 11:08:26 2010 593 Security User User Success Audit PC Detailed Tracking  A process has exited:     Process ID: 3104     Image File Name: C:\Python25\python.exe     User Name: User     Domain: PC     Logon ID: (0x0,0x143B1)     1346\n  \n"

"5 1 2010-11-22T05:26:34+00:00 Nov 22 11:09:25 192.168.2.170 pc MSWinEventLog 4 Security 1396 Mon Nov 22 11:09:25 2010 592 Security User User Success Audit PC Detailed Tracking  A new process has been created:     New Process ID: 3148     Image File Name: C:\Python25\python.exe     Creator Process ID: 2808     User Name: User     Domain: PC     Logon ID: (0x0,0x143B1)     1347\n"

"5 1 2010-11-22T05:26:42+00:00 Nov 22 11:09:33 192.168.2.170 pc MSWinEventLog 4 Security 1397 Mon Nov 22 11:09:29 2010 593 Security User User Success Audit PC Detailed Tracking  A process"
)
    chunk2 = (
"has exited:     Process ID: 3148     Image File Name: C:\Python25\python.exe     User Name: User     Domain: PC     Logon ID: (0x0,0x143B1)     1348\n"

"5 1 2010-11-22T05:27:12+00:00 Nov 22 11:10:04 192.168.2.170 pc MSWinEventLog 4 Security 1398 Mon Nov 22 11:10:04 2010 861 Security NETWORK SERVICE Well Known Group Failure Audit PC Detailed Tracking  The Windows Firewall has detected an application listening for incoming traffic.        Name: -    Path: C:\WINDOWS\system32\svchost.exe    Process identifier: 748    User account: NETWORK SERVICE    User domain: NT AUTHORITY    Service: Yes    RPC server: No    IP version: IPv4    IP protocol: UDP    Port number: 55561    Allowed: No    User notified: No   1349\n"
)

    lp.write(chunk1)
    count1 = sum(1 for msg in lp)
    assert count1 == 3

    lp.write(chunk2)
    count2 = sum(1 for msg in lp)
    assert count2 == 2

def test_unspecified_charset():
    log = u"あいうえお नेपाल"
    chunk = (log + '\n').encode('utf-8')
    lp = GetParser('LineParser')
    lp.write(chunk)

    eq_({'msg': log.encode('utf-8'), '_type_str': 'msg'}, lp.next())

def _check_charset(charset):
    log = u"あいうえお नेपाल"
    chunk = (log + '\n').encode(charset)
    lp = GetParser('LineParser', charset=charset)
    lp.write(chunk)

    eq_({'msg': log.encode('utf-8'), '_type_str': 'msg'}, lp.next(), charset)

def test_charset():
    charsets = ['utf-8', 'utf-16', 'utf-32']
    map(_check_charset, charsets)
