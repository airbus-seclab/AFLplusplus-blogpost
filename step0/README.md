# Step 0

To get started, we provide a basic fuzzing setup, which should allow you to run
AFL++ in QEMU mode with its default configuration.

## Project organization

- `corpus`: folder containing the initial corpus. In this case, it simply
  contains a certificate generated using OpenSSL and base64-encoded;
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

### Fuzzing

To start a campaign, simply run:

```sh
./fuzz.sh
```
