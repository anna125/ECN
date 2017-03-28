#!/bin/bash

#use:sudo ./runget80.sh nameinterface


chmod 777 scriptget80.sh

nohup ./scriptget80.sh aa $1 &

nohup ./scriptget80.sh ab $1 &

nohup ./scriptget80.sh ac $1 &

nohup ./scriptget80.sh ad $1 &

nohup ./scriptget80.sh ae $1 &

nohup ./scriptget80.sh af $1 &

nohup ./scriptget80.sh ag $1 &

nohup ./scriptget80.sh ah $1 &

nohup ./scriptget80.sh ai $1 &
