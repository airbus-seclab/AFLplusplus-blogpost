# Step 5

In step 5, a custom grammar-aware mutator has been added to generate ASN.1 data
(see `afl_config.sh`).

## Project organization

- `corpus`: folder containing the initial corpus. In this case, it simply
  contains a certificate generated using OpenSSL;
- `afl_config.sh`: script containing all the configuration options for AFL++;
- `build_corpus.sh`: script to minimize corpus files and make the corpus unique;
- `fuzz.sh`: script to launch AFL++-QEMU on our target.

This step also adds a dependency on the [mutator](../src/mutator) folder.

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

**Warning:** The corpus format is different for this step, so it must be
rebuilt.

### Fuzzing

To start a campaign, simply run:

```sh
./fuzz.sh
```
