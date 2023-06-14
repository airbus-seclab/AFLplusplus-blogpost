# Step 3

In step 3, AFL++'s persistent mode has been configured to improve performance
(see `afl_config.sh`).

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

**Note:** You may copy the folder from a previous step to avoid rebuilding it:

```sh
cp -R ../step0/corpus_unique corpus_unique
```

### Fuzzing

To start a campaign, simply run:

```sh
./fuzz.sh
```
