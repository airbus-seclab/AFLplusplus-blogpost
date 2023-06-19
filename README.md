# Lab for grammar-aware in-memory persistent fuzzing

## Introduction

This repository contains all scripts and data (as well as an ELF target) to follow along as you read the [associated blogpost](https://airbus-seclab.github.io/AFLplusplus-blogpost) by experimenting on your own on one example: [src/target.c](./src/target.c) (the source code of the **target**).

Repository organization:

* [step0](./step0): **basic fuzzing setup**, default configuration
* [step1](./step1): custom **instrumentation** (targeting `parse_cert_buf` function)
* [step2](./step2): with a customized **entrypoint**
* [step3](./step3): with **persistent mode**
* [step4](./step4): with an **in-memory hook**
  * [src/hook](./src/hook): source code of the hook
* [step5](./step5): custom **grammar-aware mutator**
  * [src/mutator](./src/mutator): source code of the custom mutator
* [step6](./step6): with **multi-processing**


## Setup

### AFL++

Clone and compile AFL++ from the base folder:

```bash
$ git clone https://github.com/AFLplusplus/AFLplusplus.git -b dev
$ cd AFLplusplus
$ git apply ../src/mutator/afl-fuzz-run.patch
$ make distrib
```

**Note:**
* See [this discussion](https://github.com/AFLplusplus/AFLplusplus/issues/1397)
  to understand why this patch is necessary
* Tested with commit `4063a3eb4c4099e37aef4f1d96e8b80d58d65fe2` from `Mon Jan 23
12:50:57 2023 +0100`

### libprotobuf-mutator

Clone and compile `libprotobuf-mutator` (used to build our custom mutator) from
the base folder:

```bash
$ git clone https://github.com/google/libprotobuf-mutator.git
$ cd libprotobuf-mutator
$ mkdir build && cd build
$ cmake .. -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC"
$ ninja
```

**Note:** Tested with commit `af3bb18749db3559dc4968dd85319d05168d4b5e` from
`Wed Dec 7 15:21:20 2022 -0800`

Clone and compile the protobuf ASN.1 mutator from the base folder:

```bash
$ git clone https://github.com/google/fuzzing.git google-fuzzing
$ cd google-fuzzing/proto/asn1-pdu/
$ ../../../libprotobuf-mutator/build/external.protobuf/bin/protoc *.proto --python_out=. --cpp_out=.
$ git apply ../../../src/mutator/google-fuzzing.patch
```

**Note:**
* See [this pull request](https://github.com/google/fuzzing/pull/110) to
  understand why this patch is necessary
* Tested with commit `128a82660ffe414036ded9a6e561a9532945280d` from `Wed Oct 26
14:12:31 2022 +0200`

### Python packages

Install Python3 and the venv package:

```
$ apt update
$ apt install python3 python3-venv
```

Setup a virtual environment and install dependencies:

```
$ cd src/mutator
$ python3 -m venv .env
$ source .env/bin/activate
$ pip3 install -r requirements.txt
```

### Blog

Compile the target and libraries created for this blogpost from the base folder:

```
make -C src
```

Finally, generate the corpus:

```bash
$ cd <step folder>
$ ./build_corpus.sh
```

## Run

Simply use the `fuzz.sh` script from the step you are on:

```bash
$ cd <step folder>
$ ./fuzz.sh
```
