import unittest
from pylib import disk

from fabric.api import env #, get, hide
import sys
sys.path.append(disk.get_sibling(__file__,'../../../scp_fetcher/'))

from lib.scp import setup, private_keyfile

class TestScpFetcher(unittest.TestCase):
    def setUp(self):
        self.ip = '192.168.2.22'
        self.port = 22
        self.user = 'ashok'

    def test_setup_no_pwd(self):
        self.password = None
        setup(self.ip, self.port, self.user, self.password)

        self.assertEqual(env.linewise, True)
        self.assertEqual(env.abort_on_prompts, True)
        self.assertEqual(env.no_keys, True)
        self.assertEqual(env.password, None)
        self.assertEqual(env.key_filename, private_keyfile)

    def test_setup_yes_pwd(self):
        self.password = 'ashok'
        setup(self.ip, self.port, self.user, self.password)

        self.assertEqual(env.linewise, True)
        self.assertEqual(env.abort_on_prompts, True)
        self.assertEqual(env.no_keys, True)
        self.assertEqual(env.password, self.password)
        self.assertEqual(env.key_filename, None)

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestScpFetcher)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()
