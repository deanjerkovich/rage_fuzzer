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
* TCP only
* IP only
* Client-side only
* not particularly fast (single-thread blocking)
* deterministic; fuzz-runs can be repeated given the seed of a prior run
* target process monitoring is left as an excersize to the reader
* naive unconfigurable mutations

## packet file format
todo

## doing a fuzz run
todo

## bugs found
todo
