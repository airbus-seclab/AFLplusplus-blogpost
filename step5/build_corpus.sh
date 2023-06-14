#!/bin/bash
FUZZ_DIR=`dirname $(realpath -s $0)`
source "$FUZZ_DIR/afl_config.sh"

python3 -m venv ../src/mutator/.env
source ../src/mutator/.env/bin/activate

in_path="$FUZZ_DIR/corpus"
out_path="$corpus_path"

if [ -d "$out_path" ]
then
  echo "$out_path alread exists, aborting"
  exit 1
fi

"$afl_path"/afl-cmin -Q -i "$in_path" -o "$out_path" -- "$target_path" /tmp/.afl_fake_input

if [ -d "$out_path" ]
then
  cd "$out_path"
  for i in *; do
    "$afl_path"/afl-tmin -Q -i "$i" -o "$i".min -- "$target_path" /tmp/.afl_fake_input

    echo "Converting ASN.1 to protobuf format..."
    "$BASEPATH/src/mutator/asn1_to_protobuf.py" "$i" "$i".protobuf
    rm "$i" "$i".min
  done
else
  echo "afl-cmin failed, aborting"
fi
