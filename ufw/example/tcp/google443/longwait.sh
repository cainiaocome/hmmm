#!/bin/sh

(
echo s
while true; do
sleep 3600
echo _
done
)| ufw -w0 64.233.189.100 443
