#!/bin/bash
FUZZ_DIR=`dirname $(realpath -s $0)`
source "$FUZZ_DIR/afl_config.sh"

"$afl_path/afl-showmap" -Q -C -i "$output_path"/afl-main/queue/ -o afl-main.cov -- "$target_path" /tmp/.afl_fake_input
"$afl_path/afl-showmap" -Q -C -i "$output_path"/afl-compcov/queue/ -o afl-compcov.cov -- "$target_path" /tmp/.afl_fake_input
"$afl_path/afl-showmap" -Q -C -i "$output_path"/afl-libcompcov/queue/ -o afl-libcompcov.cov -- "$target_path" /tmp/.afl_fake_input
AFL_DISABLE_TRIM="$_AFL_DISABLE_TRIM" AFL_CUSTOM_MUTATOR_ONLY="$_AFL_CUSTOM_MUTATOR_ONLY" AFL_CUSTOM_MUTATOR_LIBRARY="$_AFL_CUSTOM_MUTATOR_LIBRARY" "$afl_path/afl-showmap" -Q -C -i "$output_path"/afl-custom_mutator/queue/ -o afl-mutator.cov -- "$target_path" /tmp/.afl_fake_input
