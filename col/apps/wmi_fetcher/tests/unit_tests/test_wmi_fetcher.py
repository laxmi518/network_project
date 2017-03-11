import unittest
import sys

from pylib import disk
sys.path.append(disk.get_sibling(__file__, '../../../wmi_fetcher/'))

from lib.fetcherloop import from_time

class TestWmiFetcher(unittest.TestCase):
    def setUp(self):
        pass

    def test_from_time_no_time(self):
        self.assertEqual(from_time(), '**************.******+***')

    def test_from_time_year_added(self):
        self.assertEqual(from_time('2012'), '2012**********.******+***')

    def test_from_time_month_added(self):
        self.assertEqual(from_time('2012', '03'), '201203********.******+***')

    def test_from_time_day_added(self):
        self.assertEqual(from_time('2012', '06', '27'), '20120627******.******+***')

    def test_from_time_hours_added(self):
        self.assertEqual(from_time('2012', '06', '27', '10'), '2012062710****.******+***')

    def test_from_time_minutes_added(self):
        self.assertEqual(from_time('2012', '06', '27', '10', '10'), '201206271010**.******+***')

    def test_from_time_seconds_added(self):
        self.assertEqual(from_time('2012', '06', '27', '10', '10', '10'), '20120627101010.******+***')

    def test_from_time_microseconds_added(self):
        self.assertEqual(from_time('2012', '06', '27', '10', '10', '10', '111111'), '20120627101010.111111+***')

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestWmiFetcher)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()
