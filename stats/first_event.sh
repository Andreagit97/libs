#! /usr/bin/bash
taskset 0x80 /home/ubuntu/lsm_poc/build-scap-full/libscap/examples/01-open/scap-open --modern_bpf --ppm_sc 197 --policy 1 > first.txt &
sleep 2
taskset 0x01 /home/ubuntu/lsm_poc/stats/main &
taskset 0x02 /home/ubuntu/lsm_poc/stats/main &
taskset 0x04 /home/ubuntu/lsm_poc/stats/main &
taskset 0x08 /home/ubuntu/lsm_poc/stats/main &
sleep 30
kill -2 $(pidof scap-open)
kill -9 $(pidof main)
