#!/bin/bash

#use:sudo ./run80.sh nameinterface


chmod 777 script80.sh

nohup ./script80.sh aa $1 &

nohup ./script80.sh ab $1 &

nohup ./script80.sh ac $1 &

nohup ./script80.sh ad $1 &

nohup ./script80.sh ae $1 &

nohup ./script80.sh af $1 &

nohup ./script80.sh ag $1 &

nohup ./script80.sh ah $1 &

nohup ./script80.sh ai $1 &
