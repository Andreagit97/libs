#! /usr/bin/bash
taskset 0x2 /home/ubuntu/libs/build-scap-full/libscap/examples/01-open/scap-open --modern_bpf --ppm_sc 20 --policy 0 > loop.txt &
sleep 1
/home/ubuntu/libs/stats/new_main 20000 &
sleep 30
kill -2 $(pidof scap-open)
kill -9 $(pidof main)
