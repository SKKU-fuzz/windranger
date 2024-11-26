# Windranger fuzzer compatible with llvm 16
https://sites.google.com/view/windranger-directed-fuzzing

## Dependencies
* llvm 16 (https://github.com/llvm/llvm-project/tree/llvmorg-16.0.4)
* SVF (https://github.com/SVF-tools/SVF) build with llvm 16
* rustc release 1.70.0
  
## Usage
* build target source
``` shell
./build.sh <target src>
```

* fuzz with single processor
``` shell
./fuzz/afl-fuzz -m none -i in -o out <target binary>
```

* fuzz with multiprocessor
``` shell
./parallel-fuzz.sh <target binary> <number of nodes>

# check active nodes(processors)
./fuzz/afl-gotcpu
```

* clean up
``` shell
# kill active processes
./kill.sh

# clean up artifacts
./clean.sh
```
