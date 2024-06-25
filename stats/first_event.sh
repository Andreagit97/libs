#! /usr/bin/bash
taskset 0x8000 /home/ubuntu/libs/build-scap-full/libscap/examples/01-open/scap-open --modern_bpf --ppm_sc 197 --policy 1 > first.txt &
sleep 1
/home/ubuntu/libs/stats/new_main 10 50 &
sleep 30
kill -2 $(pidof scap-open)
kill -9 $(pidof main)
