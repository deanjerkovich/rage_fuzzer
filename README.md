rage against the network
========================

a dumb protocol-unaware packet fuzzer/replayer
----------------------------------------------

## Basic ideas:
* ridiculously easy to use (near-zero setup cost)
* protocol-unaware; blind brute-force fuzzing
* fairly quick (todo: proper epoll)
* comes with a collection of packets for common protocols ready to go

## Current status:
* IP only (TCP and UDP)
* Client-side only
* not particularly fast (single-thread blocking)
* deterministic; fuzz-runs can be repeated given the seed of a prior run
* target process monitoring is left as an excersize to the reader
* naive unconfigurable mutations

## Usage
```
Usage: rage [-d] -p <port> -t <target> -f <filename>
        -f filename      file to read packet zoo from
        -d               enable debug [excessive]
        -l               print out all packets in file
        -p portnum       specify target port for fuzzing
        -t host          specify target host for fuzzing
        -s milliseconds  specify a send delay 
        -b               don't fuzz, send original packets and exit 
        -r               provide a seed for srand (repeat a fuzz run)
        -c               number of packets sent before forced reconnect
        -z               a dummy arg to ID different fuzzers on same host

```
## packet file format
todo

## doing a fuzz run
todo

## bugs found
todo
