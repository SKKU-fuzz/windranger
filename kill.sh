#!/bin/bash

fuzz_pids=$(pgrep afl-fuzz)

if [ -z "$fuzz_pids" ]; then
    echo "There is no afl-fuzz process running."
    exit 0
fi

echo "Killing afl-fuzz processes: $fuzz_pids"
kill $fuzz_pids

if [ $? -eq 0 ]; then
    echo "All afl-fuzz processes have been killed."
else
    echo "Failed to kill afl-fuzz processes."
    exit 1
fi
