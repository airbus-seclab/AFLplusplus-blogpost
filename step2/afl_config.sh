FUZZ_DIR=`dirname $(realpath -s $0)`

## Paths

export BASEPATH=`dirname $FUZZ_DIR`
export afl_path="$BASEPATH/AFLplusplus"
export corpus_path="$FUZZ_DIR/corpus_unique"
export output_path="$FUZZ_DIR/output"
export target_path="$BASEPATH/src/target"

## Debug

#export AFL_NO_UI=1
#export AFL_DEBUG=1
#export AFL_DEBUG_CHILD=1

export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

#export AFL_BENCH_UNTIL_CRASH=1

## Base address

case $(file "$target_path") in
  *"statically linked"*)
    QEMU_BASE_ADDRESS=0
    ;;
  *"32-bit"*)
    QEMU_BASE_ADDRESS=0x40000000
    ;;
  *"64-bit"*)
    QEMU_BASE_ADDRESS=0x4000000000
    ;;
  *) echo "Failed to guess QEMU_BASE_ADDRESS"; exit 1
esac

## Helper functions

function find_func() {
    objdump -t "$target_path" | awk -n /"$1"'$/{print "0x"$1, "0x"$5}'
}
function hex_encode() {
    printf "0x%x" "$1"
}

## Instrumentation

# We only want AFL++ to instrument our target function, not the rest of the
# binary we're fuzzing
# See https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md#6-partial-instrumentation
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert_buf")
inst_start=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
inst_end=$(hex_encode $(("$inst_start" + "$fuzz_func_size")))
export AFL_QEMU_INST_RANGES="$inst_start-$inst_end"

## Entrypoint

# Define a custom AFL++ entrypoint executed later than the default (the binary's
# entrypoint)
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert")
export AFL_ENTRYPOINT=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
