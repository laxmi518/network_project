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
parsers = ["LineParser", "SyslogParser", "NewSyslogParser"]


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
    
        # global base_leak
        # print base_leak
        # if not base_leak:
        #     print "should happen only once"
        #     if os.path.exists(checksum_file):
        #         os.remove(checksum_file)
        #     self.generate_config("SyslogParser", "utf-8", "localhost", "None", "default")
        #     result = self.run_executable("syslog_collector", "example-config-new.json", 0, "leak1.log")
        #     self.send_logs("python ../../../benchmark_collectors/syslog_client.py -n 10",5)
        #     result.send_signal(2)
        #     result.wait()
        #     base_leak = self.get_leaks("leak1.log", 0)
        #     print base_leak

    def tearDown(self):
        print "tearDown"

    def test_blank_udp(self): 
        print "test_blank_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg="], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=\n"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_text_udp(self): 
        print "test_text_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=test_text_udp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=test_text_udp nl\n"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_sf_udp(self): 
        print "test_sf_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text\n"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_date_udp(self): 
        print "test_date_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39 some text\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39 some text\n"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_sf_date_udp(self):
        print "test_sf_date_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39 some text\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39 some text\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39 some text\n"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39 some text"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39 some text\n"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_pattern_udp(self):
        print "test_pattern_udp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=before 1st pattern 1<11>5 \
                Mar 29 2004 09:56:39 after 1st pattern 2<22>5 Mar 29 2004 09:56:39 after second pattern 3<33>5 Mar 29 2004 09:56:39 \
                after thrid pattern, should not appear\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=before 1st pattern"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=1<29> Mar 29 2004 09:56:39"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=after 1st pattern"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=3<29>Mar 29 2004 09:56:39 after second pattern"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=2<29>Mar 29 2004 09:56:39 after thrid pattern, should not appear"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_blank_tcp(self): # should generate zero event
        print "test_blank_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=\n", "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_text_tcp(self): # should generate zero event
        print "test_text_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=test_text_udp" , "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=test_text_udp nl\n" , "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_sf_tcp(self): # should generate zero event
        print "test_sf_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text\n", "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_date_tcp(self): # should generate zero event
        print "test_date_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39 some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39 some text", "--proto=tcp"], 5)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_sf_date_tcp(self): #should generate zero event
        print "test_sf_date_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39 some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29>Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39 some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29>Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39 some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=<29> some text Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39 some text", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=some text <29> some text Mar 29 2004 09:56:39 some text\n", "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

    def test_pattern_tcp(self):
        print "test_pattern_tcp"
        for parser in parsers:
            print parser
            self.generate_config(parser, "utf-8", "localhostnew", "None", "default")
            result = self.run_executable("syslog_collector", "example-config-new.json", 1, "leak3.log")
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=before 1st pattern 1<11>5 \
                Mar 29 2004 09:56:39 after 1st pattern 2<22>5 Mar 29 2004 09:56:39 after second pattern 3<33>5 Mar 29 2004 09:56:39 \
                after thrid pattern, should not appear\n", "--proto=tcp"], 0)

            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=before 1st pattern\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=1<11>5 Mar 29 2004 09:56:39\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=after 1st pattern\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=2<22>5 Mar 29 2004 09:56:39 after second pattern\n", "--proto=tcp"], 0)
            self.send_logs(["python", "../../../benchmark_collectors/syslog_client.py", "-n",  "1", "--msg=3<33>5 Mar 29 2004 09:56:39 after thrid pattern, should not appear\n", "--proto=tcp"], 5)
            result.send_signal(2)
            result.wait()
            leak = self.get_leaks("leak3.log", 1)

if __name__ == '__main__':
    unittest.main()