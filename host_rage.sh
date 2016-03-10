#!/bin/bash

set +v
if [ -n "$1" ]
then
  echo 'about to rage against host: ' $1
  command -v nmap > /dev/null 2>&1 || { echo "You dont appear to have nmap. exiting"; exit 1; }
  for portnum in `nmap $1 -sT | grep open | cut -d '/' -f 1`; 
    do 
    echo $portnum
    screen -d -m ./rage -p $portnum -f ./master_packets.txt -t $1 
    done;
else
  echo 'must give me a target host. exiting'
  exit
fi
