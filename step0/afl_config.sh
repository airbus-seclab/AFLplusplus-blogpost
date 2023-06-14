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
