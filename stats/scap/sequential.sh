#! /usr/bin/bash
taskset 0x2 /home/ubuntu/libs/build-scap-full/libscap/examples/01-open/scap-open --modern_bpf --ppm_sc 20 --policy 2 > sequential.txt &
sleep 1
/home/ubuntu/libs/stats/wrapper 650000 0 &
sleep 30
kill -2 $(pidof scap-open)
kill -9 $(pidof stressor)
