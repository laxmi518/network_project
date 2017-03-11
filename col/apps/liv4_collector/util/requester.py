#!/usr/bin/env python

import sys
import time
from pylib import wiring, mongo

def main():
    try:
        repo = sys.argv[1]
    except:
        sys.exit("Usage python requester.py <repo>")

    db = mongo.get_makalu()
    requester = wiring.Wire('liv4_collector_progress_request', repo_name=repo)
    while True:
        status = db.datatransport.find_one({'repo': repo}).get("status")
        if status == "run":
            requester.send(())
            print requester.recv()
            time.sleep(5)
        elif status == "finished":
            print "finished"
            return
        else:
            print 'invalid stat %r' % status
            return

main()
