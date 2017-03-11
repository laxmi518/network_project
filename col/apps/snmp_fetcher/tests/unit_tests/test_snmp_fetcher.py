from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1155 import ObjectName
from pysnmp.proto.rfc1157 import univ
from pysnmp.entity.rfc3413.oneliner.cmdgen import UsmUserData, CommunityData
from pysnmp.proto.rfc1905 import NoSuchInstance

from pylib import disk

import sys
sys.path.append(disk.get_sibling(__file__,'../../../snmp_fetcher/'))

from lib.fetcherloop import _get_mib_viewer
from lib.fetcherloop import get_community_function
from lib.fetcherloop import get_result_without_mib_lookup
from lib.fetcherloop import get_snmpfetcher_data
from lib.fetcherloop import process_snmp_fetcher_data

import unittest

def get_data(oid, cmdGen, mibView, walk_flag=False, varBindTable=None, errorStatus=univ.OctetString('noError'), \
                        errorIndex=univ.Integer('0'), errorIndication='Some Error'):
    result_template = {}
    result_template['errorIndication'] = errorIndication
    result_template['errorStatus'] = errorStatus
    result_template['errorIndex'] = errorIndex
    result_template['varBindTable'] = varBindTable
    result_template['oid'] = oid
    result_template['walk_flag'] = walk_flag
    result_template['cmdGen'] = cmdGen
    result_template['mibView'] = mibView

    return result_template

class TestSnmpFetcher(unittest.TestCase):

    def setUp(self):
        self.ip = '127.0.0.1'
        self.prop = {}
        self.port = '161'
        self.prop["community_string"] = 'public'
        self.prop["snmp_version"] = 'v12'
        self.cmdGen = cmdgen.CommandGenerator()
        self.mibView = _get_mib_viewer(self.cmdGen)

    def test_get_community_function_v12(self):
        self.assertTrue(isinstance(get_community_function(self.prop), CommunityData))

    def test_get_community_function_v3(self):
        prop = {}
        prop["snmp_version"] = 'v3'
        prop['username'] = 'ashok'
        prop['auth-key'] = 'somekey'
        prop['priv-key'] = 'privkey'
        self.assertTrue(isinstance(get_community_function(prop), UsmUserData))

    def test_get_community_function_wrong_version(self):
        self.prop["snmp_version"] = 'someother_version'
        self.assertEqual(get_community_function(self.prop), None)

    @unittest.skip('test skipped because this will be included after 5.1.1 version')
    def test_get_result_with_mib_lookup(self):
        return False

    def test_get_result_without_mib_lookup(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')
        val = univ.OctetString('swap')

        expected = {'msg': 'iso_org_dod_internet_private_enterprises_2021_4_2_0 = swap',
                    '_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_2_0',
                    'iso_org_dod_internet_private_enterprises_2021_4_2_0': 'swap'}

        result = get_result_without_mib_lookup(self.mibView, oid, val)
        self.assertEqual(result, expected)

    def test_get_snmp_fetcher_data_wrong_c_function(self):
        self.prop["community_string"] = 'public'
        self.prop["snmp_version"] = 'hawafaltu'
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')

        self.assertEqual(get_snmpfetcher_data(self.ip, self.port, self.prop, oid), {})

    def test_get_snmp_fetcher_data_wrong_transoprt_function(self):
        self.ip = 'wrong_ip_address'
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')

        self.assertEqual(get_snmpfetcher_data(self.ip, self.port, self.prop, oid), {})

    def test_get_snmp_fetcher_data_oid_overflow(self):
        oid = ObjectName('1002.3.6.1.4.1.2021.4.2.0')

        self.assertEqual(get_snmpfetcher_data(self.ip, self.port, self.prop, oid), {})

    @unittest.skip("this cant be tested cause the ObjectName object cant be constructed with such ill oid")
    def test_get_snmp_fetcher_data_oid_malform(self):
        oid = ObjectName('1.3e.6.1.4.1.2021.4.2.0')
        self.assertEqual(get_snmpfetcher_data(self.ip, self.port, self.prop, oid), {})

    def test_process_snmp_fetcher_data_varbind_none(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')
        data_dict = get_data(oid, self.cmdGen, self.mibView)
        result = process_snmp_fetcher_data(data_dict)
        self.assertEqual(result.next(), {})

    def test_process_snmp_fetcher_data_no_instance(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0.1')
        varBindTable = [(ObjectName('1.3.6.1.4.1.2021.4.2.0.1'), NoSuchInstance(''))]
        data_dict = get_data(oid, self.cmdGen, self.mibView, varBindTable=varBindTable)
        result = process_snmp_fetcher_data(data_dict)
        self.assertEqual(result.next(), {})

    def test_process_snmp_fetcher_data_error_indication(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.3.0')
        data_dict = get_data(oid, self.cmdGen, self.mibView, walk_flag=True)
        result = process_snmp_fetcher_data(data_dict)
        self.assertEqual(result.next(), {})

    def test_process_snmp_fetcher_error_status(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')
        data_dict = get_data(oid, self.cmdGen, self.mibView, walk_flag=True, errorIndication=None, errorStatus=univ.Integer('1'))
        result = process_snmp_fetcher_data(data_dict)
        self.assertEqual(result.next(), {})

    def test_process_snmp_fetcher_correct(self):
        oid = ObjectName('1.3.6.1.4.1.2021.4.2.0')
        varBindTable = [(ObjectName('1.3.6.1.4.1.2021.4.2.0'), univ.OctetString('swap'))]
        data_dict = get_data(oid, self.cmdGen, self.mibView, walk_flag=False, varBindTable=varBindTable, \
                errorIndication=None, errorStatus=univ.Integer('0'))
        result = process_snmp_fetcher_data(data_dict)
        expected = {'msg': 'iso_org_dod_internet_private_enterprises_2021_4_2_0 = swap',
                'iso_org_dod_internet_private_enterprises_2021_4_2_0': 'swap',
                '_type_str': 'msg iso_org_dod_internet_private_enterprises_2021_4_2_0'}
        self.assertEqual(result.next(), expected)

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSnmpFetcher)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()
