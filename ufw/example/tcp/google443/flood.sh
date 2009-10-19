#!/bin/sh

(
echo s
while true; do
sleep 0.01
echo _
done
)| ufw -d flood.cap -w3 64.233.189.100 443
