#!/bin/bash

#use:sudo ./run80.sh nameinterface
chmod 777 sync.sh

./run80.sh wwan0
./run443.sh wwan0
./run61987.sh wwan0
./runget80.sh wwan0
./runget443.sh wwan0


