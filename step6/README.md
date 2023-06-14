# Step 6

In step 6, several instances of AFL++ are run with various strategies in order
to improve coverage (see `afl_config.sh`).

## Project organization

- `corpus`: folder containing the initial corpus. In this case, it simply
  contains a certificate generated using OpenSSL;
- `afl_config.sh`: script containing all the configuration options for AFL++;
- `build_corpus.sh`: script to minimize corpus files and make the corpus unique;
- `fuzz.sh`: script to launch AFL++-QEMU on our target.

## Running

### Building the target

Assuming you haven't already compiled the target:

```sh
make -C ../src
```

### Building the corpus

To build the corpus (only needs to be done once):

```sh
./build_corpus.sh
```

**Warning:** The corpus for this step combines multiple formats, so it must be
rebuilt.

### Fuzzing

To start a campaign, simply run:

```sh
./fuzz.sh
```
