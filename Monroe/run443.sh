#!/bin/bash

#use:sudo ./run443.sh nameinterface


chmod 777 script443.sh

nohup ./script443.sh aa $1 &

nohup ./script443.sh ab $1 &

nohup ./script443.sh ac $1 &

nohup ./script443.sh ad $1 &

nohup ./script443.sh ae $1 &

nohup ./script443.sh af $1 &

nohup ./script443.sh ag $1 &

nohup ./script443.sh ah $1 &

nohup ./script443.sh ai $1 &
