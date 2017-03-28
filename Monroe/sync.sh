#!/bin/bash

date="$(date +%s)"
nodeid="$(head -n 1 /etc/nodeid)"

sshpass -pitalia17 ssh -o StrictHostKeyChecking=no netcom@163.117.253.6 mkdir /home/netcom/ecnres/${date}${nodeid}

rsync --remove-source-files -vru --rsh="/usr/bin/sshpass -p italia17 ssh -o BindAddress=172.16.0.194 -o StrictHostKeyChecking=no -l netcom" /home/monroeSA/anna/2703/res*  netcom@163.117.253.6:/home/netcom/ecnres/${date}${nodeid}

