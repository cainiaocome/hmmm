#!/bin/sh

(
echo s
while true; do
sleep 1
echo _
done
)| ufw -w3 -d block.cap 64.233.189.100 443
