#!/usr/bin/env python

import zmq
import time

def main():
    zmq_context = zmq.Context()
    norm_front_in = zmq_context.socket(zmq.PULL)
    norm_front_in.setsockopt(zmq.SNDHWM, 10000)
    norm_front_in.setsockopt(zmq.RCVHWM, 10000)
    norm_front_in.bind("tcp://127.0.0.1:5502")

    cnt = 0
    while True:
        raw_data = norm_front_in.recv()
        if cnt == 0:
            start = time.time()
        cnt += 1
        if cnt % 1000 == 0:
            print "count = %s speed = %s" % (cnt ,time.time()) 
        # print "%s%s" % (cnt ,raw_data)


if __name__ == '__main__':
    main()
