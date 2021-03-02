#!/bin/bash -x

# some commands might work, some others might not

ipset create test123 hash:ip
ipset create test789 hash:ip
ipset list
ipset test test123 127.0.0.1
ipset rename test123 test456
ipset swap test456 test789
ipset save test456
ipset destroy test123
ipset destroy test456
ipset destroy test789
