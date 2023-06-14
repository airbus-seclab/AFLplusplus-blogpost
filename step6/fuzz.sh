#!/bin/bash
FUZZ_DIR=`dirname $(realpath -s $0)`
source "$FUZZ_DIR/afl_config.sh"

children=()
function start_child() {
    eval "$@ > /dev/null 2>&1 &"
    child_pid="$!"
    echo "Started child with pid $child_pid and command line $@"
    children+=("$!")
}

function stop_children() {
    for pid in "${children[@]}"; do
        kill "$pid" 2>/dev/null
        echo "Killed child with pid $pid"
    done
}

# See https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_binary-only_targets.md#qemu-mode
# and https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores

# Run 1 afl-fuzz instance with CMPLOG (-c 0 + AFL_COMPCOV_LEVEL=2)
AFL_COMPCOV_LEVEL=2 start_child "'$afl_path/afl-fuzz' -Q -c 0 -S 'afl-compcov' -i '$corpus_path' -o '$output_path' -- '$target_path' /tmp/.afl_fake_input"

# Run 1 afl-fuzz instance with QASAN (AFL_USE_QASAN=1)
# We disable this for our example because it requires updating all addresses in
# afl_config.sh (and ensuring that ASLR is properly disabled on the host)
# If you want to use this, make sure to set QASAN_LOG=1 and QASAN_DEBUG=1, and
# change QEMU_BASE_ADDRESS in afl_config.sh to the value shown in the maps
#AFL_USE_QASAN=1 start_child "'$afl_path/afl-fuzz' -Q -S 'afl-qasan' -i '$corpus_path' -o '$output_path' -- '$target_path' /tmp/.afl_fake_input"

# Run 1 afl-fuzz instance with LAF (AFL_PRELOAD=libcmpcov.so + AFL_COMPCOV_LEVEL=2)
AFL_COMPCOV_LEVEL=2 AFL_PRELOAD="$AFL_PRELOAD:$afl_path/libcompcov.so" start_child "'$afl_path/afl-fuzz' -Q -S 'afl-libcompcov' -i '$corpus_path' -o '$output_path' -- '$target_path' /tmp/.afl_fake_input"

# Run 1 afl-fuzz instance with the custom mutator
AFL_DISABLE_TRIM="$_AFL_DISABLE_TRIM" AFL_CUSTOM_MUTATOR_ONLY="$_AFL_CUSTOM_MUTATOR_ONLY" AFL_CUSTOM_MUTATOR_LIBRARY="$_AFL_CUSTOM_MUTATOR_LIBRARY" start_child "'$afl_path/afl-fuzz' -Q -S 'afl-custom_mutator' -i '$protobuf_corpus_path' -o '$protobuf_output_path' -- '$target_path' /tmp/.afl_fake_input"

# Note: if you have enough cores left, you should run as many "regular"
# instances of afl-fuzz as possible here. For our example, it's not necessary
#for i in `seq 4 $(nproc)`; do  # Start at 4 since there are instances started separately
#    start_child "'$afl_path/afl-fuzz' -Q -S 'afl-$i' -i '$corpus_path' -o '$output_path' -- '$target_path' /tmp/.afl_fake_input"
#done

# Run main afl-fuzz instance
"$afl_path/afl-fuzz" -Q -M "afl-main" -i "$corpus_path" -o "$output_path" -- "$target_path" /tmp/.afl_fake_input

# Make sure to stop all other instances as well after the main instance stops
stop_children
