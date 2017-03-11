from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1155 import ObjectName
from pysnmp.proto.rfc1157 import univ

from pylib import disk

import re
import sys
sys.path.append(disk.get_sibling(__file__,'../../../snmp_fetcher/'))

from lib.fetcherloop import _get_mib_viewer
from lib.fetcherloop import process_snmp_fetcher_data
from lib.fetcherloop import _handle_data
import unittest

class MockColOut:
    def send_with_norm_policy_and_repo(self, event):
        pass
    def start_benchmarker_processing(self):
        pass

class TestSnmpFetcher(unittest.TestCase):

    def setUp(self):
        self.cmdGen = cmdgen.CommandGenerator()
        self.mibView = _get_mib_viewer(self.cmdGen)
        self.snmp_fetcher_out = MockColOut()
        self.snmp_data = {'cmdGen': None,
                'errorIndex': univ.Integer('0'),
                'errorStatus': None,
                'mibView': self.mibView,
                'cmdGen': self.cmdGen,
                'errorIndication': None,
                }

    def test_data_for_leaf_oid_case(self):
        self.snmp_data['walk_flag'] = False
        self.snmp_data['oid'] = u'1.3.6.1.4.1.2021.4.1.0'
        self.snmp_data['varBindTable'] = [(ObjectName('1.3.6.1.4.1.2021.4.2.0'), univ.Integer('0'))]

        expected = {'_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_2_0 device_name collected_at',
                    'device_name': 'localhost',
                    'collected_at': 'LiV5',
                    'iso_org_dod_internet_private_enterprises_2021_4_2_0': '0'}

        processed_by_library = process_snmp_fetcher_data(self.snmp_data)
        data = processed_by_library.next()
        _handle_data(data, '127.0.0.1', 'snmp_fetcher', 'localhost', 'LiV5', self.snmp_fetcher_out)

        mid = data.pop('mid')
        assert re.match(r'^LiV5\|snmp_fetcher\|(127.0.0.1|::1)\|\d+\|\d+$', mid)

        msg = data.pop('msg')
        assert re.match(r'iso_org_dod_internet_private_enterprises_2021_4_2_0 = \w+$', msg)

        self.assertEqual(data, expected)

    def test_data_for_branch_oid_case(self):
            self.snmp_data['oid'] = u'1.3.6.1.4.1.2021.4'
            self.snmp_data['walk_flag'] = True
            self.snmp_data['varBindTable'] = [
                    [(ObjectName('1.3.6.1.4.1.2021.4.1.0'), univ.Integer(0))],
                    [(ObjectName('1.3.6.1.4.1.2021.4.2.0'), univ.OctetString('swap'))],
                    [(ObjectName('1.3.6.1.4.1.2021.4.12.0'), univ.Integer(16000))]
            ]
            expected = [
                    {'_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_1_0 device_name collected_at',
                            'collected_at': 'LiV5', 'device_name': 'localhost',
                            'iso_org_dod_internet_private_enterprises_2021_4_1_0': '0'},
                        {'_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_2_0 device_name collected_at',
                            'collected_at': 'LiV5', 'device_name': 'localhost',
                                'iso_org_dod_internet_private_enterprises_2021_4_2_0': 'swap'},
                        {'_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_12_0 device_name collected_at',
                                'iso_org_dod_internet_private_enterprises_2021_4_12_0': '16000',
                                'collected_at': 'LiV5', 'device_name':'localhost'}
                        ]
            processed_by_library = process_snmp_fetcher_data(self.snmp_data)
            oid_suff = [1, 2, 12]
            for index, data in enumerate(processed_by_library):
                _handle_data(data, '127.0.0.1', 'snmp_fetcher', 'localhost', 'LiV5', self.snmp_fetcher_out)
                mid = data.pop('mid')
                assert re.match(r'^LiV5\|snmp_fetcher\|(127.0.0.1|::1)\|\d+\|\d+$', mid)

                msg = data.pop('msg')
                assert re.match(r'iso_org_dod_internet_private_enterprises_2021_4_%s_0 = \w+$' % oid_suff[index], msg)

                self.assertEqual(data, expected[index])

suite = unittest.TestLoader().loadTestsFromTestCase(TestSnmpFetcher)
unittest.TextTestRunner(verbosity=2).run(suite)
