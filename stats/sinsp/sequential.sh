#! /usr/bin/bash
taskset 0x2 /home/ubuntu/libs/build-sinsp-full/libsinsp/examples/sinsp-example -m -f'evt.type in (fstat) and proc.name="noone"' -p 2 > sequential.txt &
sleep 1
/home/ubuntu/libs/stats/new_main 20000 &
sleep 30
kill -2 $(pidof sinsp-example)
kill -9 $(pidof main)
