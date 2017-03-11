import ftplib

def test(ip, port, username, password, remotepath):
    ftp = ftplib.FTP()
    ftp.connect(ip, port, timeout=10)
    ftp.login(username, password)
    ftp.retrbinary("LIST %s" % remotepath, lambda path: path)


if __name__ == '__main__':
    test('127.0.0.1', 2021, 'alpha', 'alpha', 'cale.rtf')
