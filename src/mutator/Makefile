AFL_DIR=../../AFLplusplus
LPM_DIR=../../libprotobuf-mutator
PROTOBUF_DIR=$(LPM_DIR)/build/external.protobuf
ASN1_PROTOBUF_DIR=../../google-fuzzing/proto/asn1-pdu
CFLAGS=-O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -fPIC -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

all: protobuf mutator protobuf_to_der

protobuf:
	$(MAKE) -C $(ASN1_PROTOBUF_DIR) all

mutator: custom_mutator.cpp
	g++ $(CFLAGS) -Wno-unused-parameter -Wno-unused-function -c custom_mutator.cpp -I$(PROTOBUF_DIR)/include -I$(LPM_DIR) -I$(LPM_DIR)/src -I$(ASN1_PROTOBUF_DIR) -I$(AFL_DIR)/include -I$(AFL_DIR)/custom_mutators/examples
	g++ -shared -o libcustom_mutator.so custom_mutator.o $(ASN1_PROTOBUF_DIR)/*.o $(LPM_DIR)/build/src/libfuzzer/libprotobuf-mutator-libfuzzer.a $(LPM_DIR)/build/src/libprotobuf-mutator.a $(PROTOBUF_DIR)/lib/libprotobuf.a -lcrypto

protobuf_to_der: protobuf_to_der.cpp
	g++ $(CFLAGS) -o protobuf_to_der.o protobuf_to_der.cpp $(ASN1_PROTOBUF_DIR)/*.o -I$(PROTOBUF_DIR)/include -I$(LPM_DIR) -I$(ASN1_PROTOBUF_DIR) $(LPM_DIR)/build/src/libfuzzer/libprotobuf-mutator-libfuzzer.a $(LPM_DIR)/build/src/libprotobuf-mutator.a $(PROTOBUF_DIR)/lib/libprotobuf.a -lcrypto

clean:
	$(RM) *.so *.o
	$(MAKE) -C $(ASN1_PROTOBUF_DIR) clean
