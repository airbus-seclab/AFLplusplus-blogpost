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

## Persistent mode + in-memory hook

# Use persistent mode to loop on the parse_cert_buf function without forking for
# each iteration. In addition, use an in-memory hook to directly write the fuzz
# data to the target's memory
read fuzz_func_addr fuzz_func_size < <(find_func "parse_cert_buf")
export AFL_QEMU_PERSISTENT_ADDR=$(hex_encode $(("$QEMU_BASE_ADDRESS" + "$fuzz_func_addr")))
export AFL_QEMU_PERSISTENT_HOOK="$BASEPATH/src/hook/libhook.so"
export AFL_QEMU_PERSISTENT_GPR=1
export AFL_QEMU_PERSISTENT_CNT=10000

# Create an empty file so the target doesn't exit early on the first run
# when it doesn't find the input file
# The content doesn't matter as the hook will override the input buffer
# address
touch /tmp/.afl_fake_input

# Abort early with a clear error message if the hook hasn't been built
if [ ! -z "$AFL_QEMU_PERSISTENT_HOOK" ] && [ ! -f "$AFL_QEMU_PERSISTENT_HOOK" ]; then
  echo "Error: \$AFL_QEMU_PERSISTENT_HOOK set to '$AFL_QEMU_PERSISTENT_HOOK' but file does not exist, aborting"
  echo "Run 'make -C ../src libhook' to build"
  exit 1
fi

## Mutator

# Use a custom grammar-aware mutator based on libprotobuf to generate ASN.1 data
export AFL_DISABLE_TRIM=1
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY="$BASEPATH/src/mutator/libcustom_mutator.so"

# Abort early with a clear error message if the hook hasn't been built
if [ ! -z "$AFL_CUSTOM_MUTATOR_LIBRARY" ] && [ ! -f "$AFL_CUSTOM_MUTATOR_LIBRARY" ]; then
  echo "Error: \$AFL_CUSTOM_MUTATOR_LIBRARY set to '$AFL_CUSTOM_MUTATOR_LIBRARY' but file does not exist, aborting"
  echo "Run 'make -C ../src libcustom_mutator' to build"
  exit 1
fi
