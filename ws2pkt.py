#!/usr/bin/env python

import sys

# to be run against the output of tshark -x -r <minimized pcap>
# IP:TCP:0:548:CS:000300010000000000000002000000000f00:DSI Request GetStatus (OSX 10.9)

packets = []

if len(sys.argv) !=3:
  print 'Please provide an input file and port'

infile = sys.argv[1]
inlines = open(infile,'r').readlines()

portNum = sys.argv[2]

def get_offset(line):
  return line[:4]

def get_line_bytes(line):
  if (line.find('Frame')>-1 or line.find('Reass')>-1):
    return ''
  pieces = line.split(' ')
  linebytes = ''.join(pieces[2:18])
  return linebytes

currentPacket = ''

for l in inlines:
  offset = get_offset(l)
  lineBytes = get_line_bytes(l)  
  #print 'offset: %s bytes: %s' % (offset,lineBytes)
  if offset=='0000':
    #print '%s\n' % (currentPacket)
    print 'IP:TCP:0:'+portNum+':CS:'+currentPacket+':test-packet'
    currentPacket=''
  currentPacket += lineBytes


