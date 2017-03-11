
import sys
from pylib import disk
sys.path.append(disk.get_sibling(__file__, '../../../apps/scp_fetcher/lib'))
import scp

def test(ip, port, username, password, remotepath):
    scp.setup(ip, port, username, password)
    if remotepath.startswith('~'):
        remotepath = '.' + remotepath[1:]
    for filename, mtime in scp.fetch_file_mtime(remotepath):
        break

if __name__ == '__main__':
    test("192.168.2.205", 22, "sujan", "mypassword", ".profile")
