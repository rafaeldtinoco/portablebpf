#!/bin/bash -x

# some commands might work, some others might not

ipset create test123 hash:ip
ipset create test456 hash:ip
ipset create test789 hash:ip
ipset destroy test123
ipset destroy test456
ipset destroy test789
