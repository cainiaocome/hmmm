#!/bin/sh

(
echo s
while true; do
sleep 0.01
echo _
done
)| ../ufw -w3 docs.google.com 443
