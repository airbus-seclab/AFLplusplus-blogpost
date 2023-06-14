#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#define MAX_CERT_SIZE 4096
#define MAX_CN_SIZE 64

typedef struct {
    char *file_path;
    unsigned char buf[MAX_CERT_SIZE];
    int len;
} state_struct;

state_struct state;


int read_file(char *path, unsigned char *out, int *out_len) {
    FILE *fp;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open certificate at %s: %s\n", path, strerror(errno));
        return EXIT_FAILURE;
    }

    *out_len = fread(out, 1, MAX_CERT_SIZE, fp);
    if (ferror(fp)) {
        perror("Failed to read certificate");
        return EXIT_FAILURE;
    }
    if (!feof(fp)) {
        fprintf(stderr, "Warning: truncating input file to %d\n", MAX_CERT_SIZE);
    }

    fclose(fp);
    printf("Read %d bytes from %s\n", *out_len, path);
    return EXIT_SUCCESS;
}

__attribute__ ((noinline))
int base64_decode(const unsigned char *in, int len, unsigned char *out) {
  return EVP_DecodeBlock(out, in, len);
}

__attribute__ ((noinline))
int parse_cert_buf(const unsigned char *buf, int len) {
    X509 *cert;
    char cn_buf[MAX_CN_SIZE];

    cert = d2i_X509(NULL, &buf, len);
    if (!cert) {
        fprintf(stderr, "Failed to parse DER certificate\n");
        return EXIT_FAILURE;
    }

    // Extract the CN from the certificate
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    memset(cn_buf, 0, sizeof(cn_buf));
    strcpy(cn_buf, subj);  // Oops
    // strncpy(cn_buf, subj, sizeof(cn_buf) - 1);  // better
    printf("Got CN='%s' (len=%ld) from certificate at '%s'\n", cn_buf, strlen(cn_buf), state.file_path);

    OPENSSL_free(subj);
    X509_free(cert);
    return EXIT_SUCCESS;
}

__attribute__ ((noinline))
int parse_cert(char *path) {
    int err;

    err = read_file(path, state.buf, &state.len);
    if (err) {
        return err;
    }

    state.len = base64_decode(state.buf, state.len, state.buf);
    if (state.len < 0) {
        printf("Failed to decode base64 data\n");
        return EXIT_FAILURE;
    }

    return parse_cert_buf(state.buf, state.len);
}

void init(char *path) {
    state.file_path = path;
    memset(state.buf, 0, sizeof(state.buf));
    usleep(50000);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: ./target <file path>\n");
        return EXIT_FAILURE;
    }
    init(argv[1]);
    return parse_cert(argv[1]);
}
