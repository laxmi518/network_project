#!/bin/sh

#kill the fw1-loggrabber
#called only after the opsec fetcher has been deleted
ps -aux | grep fw1-loggrabber | grep -v grep | awk '{print $2}' | xargs kill -9
