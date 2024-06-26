#! /usr/bin/bash
taskset 0x2 /home/ubuntu/libs/build-sinsp-full/libsinsp/examples/sinsp-example -m -f'evt.type in (openat) and proc.name="noone"' -p 0 > loop.txt &
sleep 1
/home/ubuntu/libs/stats/new_main 10 50 &
sleep 30
kill -2 $(pidof sinsp-example)
kill -9 $(pidof main)
