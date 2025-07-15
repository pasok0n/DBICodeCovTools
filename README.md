# DBICodeCovTools
This repository contains the source code for the tools utilized in [DBICodeCovBench](https://github.com/pasok0n/DBICodeCovBench).

[frida-spawn.py](https://github.com/pasok0n/DBICodeCovTools/blob/main/frida-spawn.py) is a modified version from yrp's [frida-drcov.py](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida) to enable spawn mode.

The [frida.patch](https://github.com/pasok0n/DBICodeCovTools/blob/main/frida.patch) file applies modifications to yrp's original [frida-drcov.py](https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida) script. These modifications enable the instrumentation to cease automatically upon the termination of the target process.

To compile `pin_cov.cpp`, follow these steps:

1.  **Download and Extract Pin:**
    Execute the following commands in your terminal to download the Pin framework, extract its contents, and rename the directory for convenience:
    ```bash
    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    tar -xzf pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    rm pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz && \
    mv pin-external-3.31-98869-gfa6f126a8-gcc-linux pin
    ```
    This sequence of commands retrieves the Pin archive, decompresses it, removes the original archive, and renames the extracted directory to `pin`.

2.  **Navigate and Compile:**
    Change your current directory to the location where `pin_cov.cpp` is situated within the Pin tools structure. Then, create the necessary build directory and initiate the compilation process:
    ```bash
    cd pin/source/tools/MyPinTool && \
    mkdir obj-intel64 && \
    make obj-intel64/pin_cov.so
    ```
    This set of commands navigates to the Pin tool's source directory, creates a subdirectory for 64-bit object files, and compiles `pin_cov.cpp` into a shared library named `pin_cov.so`.
