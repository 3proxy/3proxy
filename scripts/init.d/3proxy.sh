#!/bin/sh
### BEGIN INIT INFO
# Provides:          3proxy
# Required-Start:    
# Required-Stop:     
# Should-Start:      
# Should-Stop:       
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start/stop 3proxy
# Description:       Start/stop 3proxy, tiny proxy server
### END INIT INFO
# chkconfig: 2345 20 80
# description: 3proxy tiny proxy server

case "$1" in
   start)    
       echo Starting 3Proxy
   
       /bin/mkdir -p /var/run/3proxy
       /bin/3proxy /etc/3proxy/3proxy.cfg &
   
       RETVAL=$?
       echo
       [ $RETVAL ]    
       ;;

   stop)
       echo Stopping 3Proxy
       if [ -f /var/run/3proxy/3proxy.pid ]; then
	       /bin/kill `cat /var/run/3proxy/3proxy.pid`
       else
               /usr/bin/killall 3proxy
       fi
   
       RETVAL=$?
       echo
       [ $RETVAL ]
       ;;

   restart|reload)
       echo Reloading 3Proxy
       if [ -f /var/run/3proxy/3proxy.pid ]; then
	       /bin/kill -s USR1 `cat /var/run/3proxy/3proxy.pid`
       else
               /usr/bin/killall -s USR1 3proxy
       fi
       ;;


   *)
       echo Usage: $0 "{start|stop|restart}"
       exit 1
esac
exit 0 

