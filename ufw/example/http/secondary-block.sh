#!/bin/sh

(
# syn
echo s
# wait 1 sec for syn/ack, send ack
echo '*1;a'

# send http request
echo 'pa;GET /falun HTTP/1.1\r\nHost: \r\n'

#wait 2 sec, send an ack, expecting rst's
while true; do echo '*1;_' ; done
# usually last for 90 seconds, you need to ^C by your self
) | ufw -aw3 $1 $2
