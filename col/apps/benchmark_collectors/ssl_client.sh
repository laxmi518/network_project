#!/bin/bash

if [ $# -lt 2 ]
  then
    echo "Supply msg, count"
else
echo $1 $2
for i in `seq $2`
do
	printf $1| openssl s_client -connect localhost:9999 &
done 
fi
