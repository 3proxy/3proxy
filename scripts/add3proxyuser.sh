#!/bin/sh
if [ $4 ]; then  
	echo bandlimin $4 $1 >> /etc/3proxy/conf/bandlimiters
fi
if [ $3 ]; then  
	echo countin \"`wc -l /etc/3proxy/conf/counters|awk '{print $1}'`/$1\" D $3 $1 >> /etc/3proxy/conf/counters
fi
if [ $2 ]; then  
	echo $1:`/bin/mycrypt $$ $2` >> /etc/3proxy/conf/passwd
else
	echo usage: $0 username password [day_limit] [bandwidth]
	echo "	"day_limit - traffic limit in MB per day
	echo "	"bandwidth - bandwith in bits per second 1048576 = 1Mbps
fi

