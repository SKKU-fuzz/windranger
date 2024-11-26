#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target binary> <number of nodes>"
    exit 1
fi

TARGET=$1
NUM_NODES=$2

./fuzz/afl-fuzz -m none -i in -o sync_dir/ -M fuzzer01 $TARGET > /dev/null 2>&1 &

for i in $(seq -w 2 $NUM_NODES); do
    ./fuzz/afl-fuzz -m none -i in -o sync_dir/ -S fuzzer$i $TARGET > /dev/null 2>&1 &
done

./fuzz/afl-gotcpu

