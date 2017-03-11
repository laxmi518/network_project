import unittest

class TestOpsecFetcher(unittest.TestCase):
    def setUp(self):
        pass

    def test_dummy(self):
        self.assertTrue(True)

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestOpsecFetcher)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()

