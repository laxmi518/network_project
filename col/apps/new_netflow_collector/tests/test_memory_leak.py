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
python/Python-2.7.6/Misc/valgrind-python.supp "
# --show-possibly-lost=no --show-reachable=yes
# --track-origins=yes --run-libc-freeres=no
base_leak = None

class IntegrationTests(unittest.TestCase):

    def generate_config(self, parser,charset, device_name, normalizer, repo):
        shutil.copy2("example-config.json", "example-config-new.json")
        f = open("example-config-new.json").read()
        j = json.loads(f)
        key = j["client_map"].keys()[0]
        j["client_map"][key]['parser'] = parser
        j["client_map"][key]['charset'] = charset
        j["client_map"][key]['device_name'] = device_name
        j["client_map"][key]['normalizer'] = normalizer
        j["client_map"][key]['repo'] = repo
        # f.write()
        with open("example-config-new.json", "w") as file_new:
            file_new.write(json.dumps(j))

    def run_executable(self, executable, example_config, delete_config, log_file):
        # print tool+ " " + executable
        command = "valgrind --tool=memcheck --leak-check=full %s\
--log-file=%s ../%s %s" % (suppression, log_file, executable, example_config)
        buffer = StringIO.StringIO()
        result = subprocess.Popen(command.split(" "),
                                  stdout = open("abc.txt","w")
                                  )
        print command
        # result.send_signal(2)
        # result.wait()
        if os.path.exists("abc.txt"):
            os.remove("abc.txt")
        if delete_config == 1:
            if os.path.exists(example_config):
                os.remove(example_config)
        time.sleep(15)
        return result

    def send_logs(self, command, duration):
        print command
        buffer = StringIO.StringIO()
        result = subprocess.Popen(command,
                                  stdout = open("abc1.txt","w")
                                  ).communicate()
        if os.path.exists("abc1.txt"):
            os.remove("abc1.txt")
        time.sleep(duration)

    def get_leaks(self, log_file, delete_logfile):
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

        # s = re.search(r".*possibly lost: ([\d+,?]+) bytes", f)
        # if s:
        #     leaks["possibly_lost"] = s.groups()[0]
        # else:
        #     leaks["possibly_lost"] = "-1"

        # s = re.search(r".*still reachable: ([\d+,?]+) bytes", f)
        # if s:
        #     leaks["still_reachable"] = s.groups()[0]
        # else:
        #     leaks["still_reachable"] = "-1"
        if delete_logfile == 1:
            if os.path.exists(log_file):
                os.remove(log_file)
        # return self.definitely_lost
        self.assertTrue(leaks["definitely_lost"] == "0")
        self.assertTrue(leaks["indirectly_lost"] == "0")
        # self.assertTrue(leaks["possibly_lost"] != "-1")
        # self.assertTrue(leaks["still_reachable"] != "-1")
        return leaks

    def setUp(self):
        print "at setUp"
        global base_leak
        if not base_leak:
            print "should happen only once"
            result = self.run_executable("netflow_collector", "example-config.json", 0, "leak0.log")
            self.send_logs(["python", "../../benchmark_collectors/netflow_client.py", "-n",  "1", "-v", "5"], 5)
            result.send_signal(2)
            result.wait()
            base_leak = self.get_leaks("leak0.log", 1)
            print base_leak


    def tearDown(self):
        print "tearDown"

    def test_netflow_v5(self): 
        print "test_netflow_v5"
        result = self.run_executable("netflow_collector", "example-config.json", 0, "leak1.log")
        self.send_logs(["python", "../../benchmark_collectors/netflow_client.py", "-n",  "1000", "-v", "5"], 5)
        result.send_signal(2)
        result.wait()
        leak = self.get_leaks("leak1.log", 1)
        self.assertEqual(base_leak, leak)

    def test_netflow_v9(self): 
        print "test_netflow_v9"
        result = self.run_executable("netflow_collector", "example-config.json", 0, "leak1.log")
        self.send_logs(["python", "../../benchmark_collectors/netflow_client.py", "-n",  "1000", "-v", "9"], 5)
        result.send_signal(2)
        result.wait()
        leak = self.get_leaks("leak1.log", 1)
        self.assertEqual(base_leak, leak)

    def test_netflow_v10(self): 
        print "test_netflow_v10"
        result = self.run_executable("netflow_collector", "example-config.json", 0, "leak1.log")
        self.send_logs(["python", "../../benchmark_collectors/netflow_client.py", "-n",  "1000", "-v", "10"], 5)
        result.send_signal(2)
        result.wait()
        leak = self.get_leaks("leak1.log", 1)
        self.assertEqual(base_leak, leak)

if __name__ == '__main__':
    unittest.main()