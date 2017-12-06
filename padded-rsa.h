#ifndef PADDEDRSA_H
#define PADDEDRSA_H

#include <openssl/bn.h>

typedef struct rsa_enc_dec_options
{
  char* key_file;
  char* in_file;
  char* out_file;
  void (*print)(const struct rsa_enc_dec_options*);
} RSAEncDecOptions;

RSAEncDecOptions* new_RSAEncDecOptions();

RSAEncDecOptions* parse_RSAEncDecOptions(const int argc, char * const argv[]);

void print_RSAEncDecOptions(const RSAEncDecOptions* options);

typedef struct rsa_keygen_options
{
  char *public_key_file;
  char *secret_key_file;
  unsigned long num_bits;
  void (*print)(const struct rsa_keygen_options*);
} RSAKeygenOptions;

RSAKeygenOptions* new_RSAKeygenOptions();

RSAKeygenOptions* parse_RSAKeygenOptions(const int argc, char * const argv[]);

void print_RSAKeygenOptions(const RSAKeygenOptions* options);

typedef struct rsa_key
{
  BIGNUM* d;
  BIGNUM* e;
  BIGNUM* N;
  unsigned long num_bits;
} RSAKey;

RSAKey* new_RSAKey();

void free_RSAKey(RSAKey* rsa_key);

RSAKey* gen_RSAKey(int num_bits);

void write_RSAKey(FILE* fout, unsigned long num_bits, const char* N,
                  const char* key);

typedef struct public_rsa_key
{
  BIGNUM* e;
  BIGNUM* N;
  unsigned long num_bits;
} PublicRSAKey;

PublicRSAKey* new_PublicRSAKey();

PublicRSAKey* read_file_PublicRSAKey(FILE* public_key_fin);

typedef struct secret_rsa_key
{
  BIGNUM* d;
  BIGNUM* N;
  unsigned long num_bits;
} SecretRSAKey;

SecretRSAKey* new_SecretRSAKey();

SecretRSAKey* read_file_SecretRSAKey(FILE* secret_key_fin);

BIGNUM* read_file_bn(FILE *fin);

void write_file_bn(const BIGNUM* bn, FILE* fout);

BIGNUM* calc_phi_N(const BIGNUM* p, const BIGNUM* q, BN_CTX* bn_ctx);

int calc_d(BIGNUM* d, const BIGNUM* e, const BIGNUM* phi_N, BN_CTX* bn_ctx);

BIGNUM* generate_r(unsigned long num_bits);

BIGNUM* padded_rsa_encrypt(BIGNUM* m, BIGNUM* N, BIGNUM* e,
                           unsigned long num_bits);

BIGNUM* padded_rsa_decrypt(BIGNUM* c, BIGNUM* N, BIGNUM* d,
    unsigned long num_bits);

void print_openssl_err_and_exit();
#endif
