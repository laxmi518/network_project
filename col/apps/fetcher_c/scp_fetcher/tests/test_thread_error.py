import unittest
import logging
import re
import subprocess
import time
import shutil
import json
import os
import datetime
import cStringIO as StringIO
# from nose.tools import eq_

suppression = "--suppressions=/home/pritesh/programming/\
python/Python-2.7.6/Misc/valgrind-python.supp --gen-suppressions=yes "
# --show-possibly-lost=no --show-reachable=yes
base_leak = None
# log_file = "leak2.log"
checksum_file = "/opt/immune/storage/col/scp_fetcher/checksums.json"


class IntegrationTests(unittest.TestCase):

    def generate_config(self, device_ip, user, password, path,
                        fetch_interval_seconds):
        shutil.copy2("example-config.json", "example-config-new.json")
        f = open("example-config-new.json").read()
        j = json.loads(f)
        key = j["client_map"].keys()[0]
        j["client_map"][key]['device_ip'] = device_ip
        j["client_map"][key]['user'] = user
        j["client_map"][key]['password'] = password
        j["client_map"][key]['path'] = path
        j["client_map"][key]['fetch_interval_seconds'] = fetch_interval_seconds
        # f.write()
        with open("example-config-new.json", "w") as file_new:
            file_new.write(json.dumps(j))

    def run_executable(self, executable, example_config, delete_config, log_file, sleep_interval):
        # print tool+ " " + executable
        command = "valgrind --tool=helgrind %s\
--log-file=%s ../%s %s" % (suppression, log_file, executable, example_config)
        buffer = StringIO.StringIO()
        result = subprocess.Popen(command.split(" "),
                                  stdout = open("abc.txt","w")
                                  )
        print command
        # print result.pid
        # print error
        # if error != " ":
        #     print "error running command"
        #     return -1
        # else:
        #     print "no error"
        time.sleep(sleep_interval)
        result.send_signal(2)
        result.wait()
        if os.path.exists("abc.txt"):
            os.remove("abc.txt")
        if delete_config == 1:
            if os.path.exists(example_config):
                os.remove(example_config)


    def get_leaks(self,log_file,delete_logfile):
        leaks = {}
        if not os.path.exists(log_file):
            leaks["definitely_lost"] = -1
            leaks["indirectly_lost"] = -1
            leaks["possibly_lost"] = -1
            # leaks["still_reachable"] = -1
            # os.remove("example-config-new.json")
            return leaks
        f= open(log_file).read()

        s = re.search(r".*definitely lost: ([\d+,?]+) bytes", f)
        if s:
            leaks["definitely_lost"] = s.groups()[0]
        else:
            leaks["definitely_lost"] = "-1"

        s = re.search(r".*indirectly lost: ([\d+,?]+) bytes", f)
        if s:
            leaks["indirectly_lost"] = s.groups()[0]
        else:
            leaks["indirectly_lost"] = "-1"

        s = re.search(r".*possibly lost: ([\d+,?]+) bytes", f)
        if s:
            leaks["possibly_lost"] = s.groups()[0]
        else:
            leaks["possibly_lost"] = "-1"

        # s = re.search(r".*still reachable: ([\d+,?]+) bytes", f)
        # if s:
        #     leaks["still_reachable"] = s.groups()[0]
        # else:
        #     leaks["still_reachable"] = "-1"
        if delete_logfile == 1:
            if os.path.exists(log_file):
                os.remove(log_file)
        # return self.definitely_lost
        # self.assertTrue(leaks["definitely_lost"] != "-1")
        # self.assertTrue(leaks["indirectly_lost"] != "-1")
        # self.assertTrue(leaks["possibly_lost"] != "-1")
        # self.assertTrue(leaks["still_reachable"] != "-1")
        return leaks

    def setUp(self):
        print "at setUp"
        if os.path.exists(checksum_file):
            os.remove(checksum_file)
        
        # global base_leak
        # print base_leak
        # if not base_leak:
        #     print "should happen only once"
        #     if os.path.exists(checksum_file):
        #         os.remove(checksum_file)
        #     self.generate_config("110.44.116.197", "support", "support@immune", "scp_test/asdf", 10)
        #     self.run_executable("scp_fetcher", "example-config-new.json", 1, "leak1.log", 3)
        #     base_leak = self.get_leaks("leak1.log", 0)
        #     print base_leak

    def tearDown(self):
        if os.path.exists(checksum_file):
            os.remove(checksum_file)

    def test_mt(self):
        print "test_mt"
        # self.generate_config("110.44.116.197", "support", "support@immune", "scp_test/test4/", 100)
        self.run_executable("scp_fetcher", "example-config-mt-small.json", 0, "leak2.log", 20)
        leaks_mt = self.get_leaks("leak2.log", 0)
        # self.assertEqual(base_leak, leaks_mt)

    #total 5696

if __name__ == '__main__':
    unittest.main()