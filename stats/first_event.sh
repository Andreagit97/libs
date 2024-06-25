#! /usr/bin/bash
taskset 0x20 /home/ubuntu/lsm_poc/build-scap-full/libscap/examples/01-open/scap-open --modern_bpf --ppm_sc 197 --policy 1 > first.txt &
sleep 2
taskset 0x10 /home/ubuntu/lsm_poc/stats/main &
taskset 0x40 /home/ubuntu/lsm_poc/stats/main &
taskset 0x80 /home/ubuntu/lsm_poc/stats/main &
sleep 30
kill -2 $(pidof scap-open)
kill -9 $(pidof main)
