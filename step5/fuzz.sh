#!/bin/bash
FUZZ_DIR=`dirname $(realpath -s $0)`
source "$FUZZ_DIR/afl_config.sh"

"$afl_path"/afl-fuzz -Q -i "$corpus_path" -o "$output_path" -- "$target_path" /tmp/.afl_fake_input
