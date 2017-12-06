#include "padded-rsa.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

const char* rsa_enc_dec_arg_options = "k:i:o:";
const char* rsa_keygen_arg_options = "p:s:n:";

void strip_newline(char* s)
{
  if (s[strlen(s)-1] == '\n') s[strlen(s)-1] = '\0';
}

RSAEncDecOptions* new_RSAEncDecOptions()
{
  RSAEncDecOptions* options = malloc(sizeof(RSAEncDecOptions));

  options->key_file = NULL;
  options->in_file = NULL;
  options->out_file = NULL;
  options->print = print_RSAEncDecOptions;

  return options;
}

RSAEncDecOptions* parse_RSAEncDecOptions(const int argc, char * const argv[])
{
  int option;
  RSAEncDecOptions* rsa_options = new_RSAEncDecOptions();

  while ((option = getopt(argc, argv, rsa_enc_dec_arg_options)) != -1) {
    switch(option) {
      case 'k':
        rsa_options->key_file = optarg;
        break;
      case 'i':
        rsa_options->in_file = optarg;
        break;
      case 'o':
        rsa_options->out_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  if (rsa_options->key_file == NULL || rsa_options->in_file == NULL ||
      rsa_options->out_file == NULL) {
    fprintf(stderr, "-k -i -o options are required\n");
    exit(1);
  }

  return rsa_options;
}

void print_RSAEncDecOptions(const RSAEncDecOptions* options)
{
  printf("key file: %s\n", options->key_file);
  printf("input file: %s\n", options->in_file);
  printf("output file: %s\n", options->out_file);
}

RSAKeygenOptions* new_RSAKeygenOptions()
{
  RSAKeygenOptions *options = malloc(sizeof(RSAKeygenOptions));

  options->public_key_file = NULL;
  options->secret_key_file = NULL;
  options->num_bits = 0;
  options->print = print_RSAKeygenOptions;

  return options;
}

RSAKeygenOptions* parse_RSAKeygenOptions(const int argc, char * const argv[])
{
  int option;
  RSAKeygenOptions* keygen_options = new_RSAKeygenOptions();

  while ((option = getopt(argc, argv, rsa_keygen_arg_options)) != -1) {
    switch(option) {
      case 'p':
        keygen_options->public_key_file = optarg;
        break;
      case 's':
        keygen_options->secret_key_file = optarg;
        break;
      case 'n':
        sscanf(optarg, "%ld", &(keygen_options->num_bits));
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  if (keygen_options->public_key_file == NULL ||
      keygen_options->secret_key_file == NULL) {
    fprintf(stderr, "-p -s -n options are required\n");
    exit(1);
  }

  return keygen_options;
}

void print_RSAKeygenOptions(const RSAKeygenOptions* options)
{
  printf("public key file: %s\n", options->public_key_file);
  printf("secret key file: %s\n", options->secret_key_file);
  printf("number of bits: %ld\n", options->num_bits);
}

/** CORE FUNCTION **/
RSAKey* new_RSAKey()
{
  RSAKey* rsa_key = malloc(sizeof(RSAKey));

  if (!rsa_key) return NULL;

  rsa_key->d = BN_new();
  rsa_key->e = BN_new();
  rsa_key->N = BN_new();
  rsa_key->num_bits = 0;

  if (!rsa_key->d || !rsa_key->e || !rsa_key->N) {
    goto handle_new_RSAKey_error;
  }

  if (!BN_dec2bn(&rsa_key->e, "3")) {
    goto handle_new_RSAKey_error;
  }

  return rsa_key;

  handle_new_RSAKey_error:
    if (rsa_key->d) BN_clear_free(rsa_key->d);
    if (rsa_key->e) BN_clear_free(rsa_key->e);
    if (rsa_key->N) BN_clear_free(rsa_key->N);
    if (rsa_key) free(rsa_key);
    return NULL;
}

void free_RSAKey(RSAKey* rsa_key)
{
  if (rsa_key) {
    if (rsa_key->d) BN_clear_free(rsa_key->d);
    if (rsa_key->e) BN_clear_free(rsa_key->e);
    if (rsa_key->N) BN_clear_free(rsa_key->N);
    free(rsa_key);
  }
}

/** CORE FUNCTION **/
RSAKey* gen_RSAKey(int num_bits)
{
  RSAKey* rsa_key = new_RSAKey();
  BIGNUM* p = BN_new();
  BIGNUM* q = BN_new();

  if (!rsa_key || !p || !q) {
    goto handle_gen_RSAKey_error;
  }

  rsa_key->num_bits = (unsigned long) num_bits;

  if (!BN_generate_prime_ex(p, num_bits / 2, 0, NULL, NULL, NULL) ||
      !BN_generate_prime_ex(q, num_bits / 2, 0, NULL, NULL, NULL)) {
    goto handle_gen_RSAKey_error;
  }

  BN_CTX* bn_ctx = BN_CTX_new();

  if (!bn_ctx || !BN_mul(rsa_key->N, p, q, bn_ctx)) {
    goto handle_gen_RSAKey_error;
  }

  BIGNUM* phi_N = calc_phi_N(p, q, bn_ctx);

  if (!phi_N || !calc_d(rsa_key->d, rsa_key->e, phi_N, bn_ctx)) {
    goto handle_gen_RSAKey_error;
  }

  return rsa_key;

  handle_gen_RSAKey_error:
    if (rsa_key) free_RSAKey(rsa_key);
    if (p) BN_clear_free(p);
    if (q) BN_clear_free(q);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    if (phi_N) BN_clear_free(phi_N);
    return NULL;
}

void write_RSAKey(FILE* fout, unsigned long num_bits, const char* N,
                  const char* key)
{
  fprintf(fout, "%ld\n", num_bits);
  fprintf(fout, "%s\n", N);
  fprintf(fout, "%s\n", key);
}

PublicRSAKey* new_PublicRSAKey()
{
  PublicRSAKey* public_rsa_key = malloc(sizeof(PublicRSAKey));

  if (!public_rsa_key) return NULL;

  public_rsa_key->e = BN_new();
  public_rsa_key->N = BN_new();
  public_rsa_key->num_bits = 0;

  if (!public_rsa_key->e || !public_rsa_key->N) {
    goto handle_new_PublicRSAKey_error;
  }

  return public_rsa_key;

  handle_new_PublicRSAKey_error:
    if (public_rsa_key->e) BN_clear_free(public_rsa_key->e);
    if (public_rsa_key->N) BN_clear_free(public_rsa_key->N);
    return NULL;
}

PublicRSAKey* read_file_PublicRSAKey(FILE* public_key_fin)
{
  char* num_bits_str = NULL;
  char* N_str = NULL;
  char* e_str = NULL;
  size_t num_bits_str_getline_buf_size = 0;
  size_t N_str_getline_buf_size = 0;
  size_t e_str_getline_buf_size = 0;
  PublicRSAKey* public_rsa_key = NULL;

  getline(&num_bits_str, &num_bits_str_getline_buf_size, public_key_fin);
  getline(&N_str, &N_str_getline_buf_size, public_key_fin);
  getline(&e_str, &e_str_getline_buf_size, public_key_fin);

  strip_newline(num_bits_str);
  strip_newline(N_str);
  strip_newline(e_str);

  public_rsa_key = new_PublicRSAKey();

  sscanf(num_bits_str, "%ld", &(public_rsa_key->num_bits));
  BN_dec2bn(&(public_rsa_key->N), N_str);
  BN_dec2bn(&(public_rsa_key->e), e_str);

  free(num_bits_str);
  free(N_str);
  free(e_str);

  return public_rsa_key;
}

SecretRSAKey* new_SecretRSAKey()
{
  SecretRSAKey* secret_rsa_key = malloc(sizeof(SecretRSAKey));

  if (!secret_rsa_key) return NULL;

  secret_rsa_key->d = BN_new();
  secret_rsa_key->N = BN_new();
  secret_rsa_key->num_bits = 0;

  if (!secret_rsa_key->d || !secret_rsa_key->N) {
    goto handle_new_SecretRSAKey_error;
  }

  return secret_rsa_key;

  handle_new_SecretRSAKey_error:
    if (secret_rsa_key->d) BN_clear_free(secret_rsa_key->d);
    if (secret_rsa_key->N) BN_clear_free(secret_rsa_key->N);
    return NULL;
}

SecretRSAKey* read_file_SecretRSAKey(FILE* secret_key_fin)
{
  char* num_bits_str = NULL;
  char* N_str = NULL;
  char* d_str = NULL;
  size_t num_bits_str_getline_buf_size = 0;
  size_t N_str_getline_buf_size = 0;
  size_t d_str_getline_buf_size = 0;
  SecretRSAKey* secret_rsa_key = NULL;

  getline(&num_bits_str, &num_bits_str_getline_buf_size, secret_key_fin);
  getline(&N_str, &N_str_getline_buf_size, secret_key_fin);
  getline(&d_str, &d_str_getline_buf_size, secret_key_fin);

  strip_newline(num_bits_str);
  strip_newline(N_str);
  strip_newline(d_str);

  secret_rsa_key = new_SecretRSAKey();

  sscanf(num_bits_str, "%ld", &(secret_rsa_key->num_bits));
  BN_dec2bn(&(secret_rsa_key->N), N_str);
  BN_dec2bn(&(secret_rsa_key->d), d_str);

  free(num_bits_str);
  free(N_str);
  free(d_str);

  return secret_rsa_key;
}

BIGNUM* read_file_bn(FILE *fin)
{
  char *bn_str = NULL;
  size_t bn_str_getline_buf_size = 0;
  BIGNUM* bn = BN_new();

  getline(&bn_str, &bn_str_getline_buf_size, fin);
  strip_newline(bn_str);
  BN_dec2bn(&bn, bn_str);

  free(bn_str);

  return bn;
}

void write_file_bn(const BIGNUM* bn, FILE* fout)
{
  fprintf(fout, "%s\n", BN_bn2dec(bn));
}

/** CORE FUNCTION **/
BIGNUM* calc_phi_N(const BIGNUM* p, const BIGNUM* q, BN_CTX* bn_ctx)
{
  BIGNUM* p_minus_one = BN_new();
  BIGNUM* q_minus_one = BN_new();
  BIGNUM* phi_N = BN_new();

  if (!p_minus_one || !q_minus_one || !phi_N) {
    goto handle_calc_phi_N_error;
  }

  if (!BN_sub(p_minus_one, p, BN_value_one()) ||
      !BN_sub(q_minus_one, q, BN_value_one()) ||
      !BN_mul(phi_N, p_minus_one, q_minus_one, bn_ctx)) {
    goto handle_calc_phi_N_error;
  }

  BN_clear_free(p_minus_one);
  BN_clear_free(q_minus_one);

  return phi_N;

  handle_calc_phi_N_error:
    if (p_minus_one) BN_clear_free(p_minus_one);
    if (q_minus_one) BN_clear_free(q_minus_one);
    if (phi_N) BN_clear_free(phi_N);
    return NULL;
}

/** CORE FUNCTION **/
int calc_d(BIGNUM* d, const BIGNUM* e, const BIGNUM* phi_N, BN_CTX* bn_ctx)
{
  return BN_mod_inverse(d, e, phi_N, bn_ctx) != NULL;
}

/** CORE FUNCTION **/
BIGNUM* generate_r(unsigned long r_num_bits)
{
  int r_contains_zero_byte = 1;
  BIGNUM* r = BN_new();
  unsigned long bytes_in_r = r_num_bits / 8;
  unsigned char* bytes_r = malloc(bytes_in_r);

  while (r_contains_zero_byte) {
    BN_generate_prime_ex(r, r_num_bits, 0, NULL, NULL, NULL);
    BN_bn2bin(r, bytes_r);
    r_contains_zero_byte = 0;
    for (int i = 0; i < bytes_in_r; i++) {
      if (bytes_r[i] == 0) {
        r_contains_zero_byte = 1;
      }
    }
  }

  return r;
}

/** CORE FUNCTION **/
BIGNUM* padded_rsa_encrypt(BIGNUM* m, BIGNUM* N, BIGNUM* e,
    unsigned long num_bits)
{
  size_t r_bit_len = num_bits / 2;
  size_t m_required_bit_len = (num_bits / 2) - 24;
  BIGNUM* enc_element = NULL;
  BIGNUM* ciphertext = NULL;
  BIGNUM* r = NULL;
  BN_CTX* bn_ctx = NULL;

  /* allocate encryption element and zero initialize (0x00) */
  enc_element = BN_new();
  if (!enc_element || !BN_zero(enc_element)) {
    goto handle_padded_rsa_encrypt_error;
  }
  /* append 0x02 to encryption element */
  if (!BN_lshift(enc_element, enc_element, 8) || !BN_add_word(enc_element, 2)) {
    goto handle_padded_rsa_encrypt_error;
  }
  /* append r to encryption element */
  r = generate_r(r_bit_len);
  if (!r || !BN_lshift(enc_element, enc_element, r_bit_len) ||
      !BN_add(enc_element, enc_element, r)) {
    goto handle_padded_rsa_encrypt_error;
  }
  /* append 0x00 to encryption element */
  if (!BN_lshift(enc_element, enc_element, 8) || !BN_add_word(enc_element, 0)) {
    goto handle_padded_rsa_encrypt_error;
  }
  /* append m to encryption element */
  if (!BN_lshift(enc_element, enc_element, m_required_bit_len) ||
      !BN_add(enc_element, enc_element, m)) {
    goto handle_padded_rsa_encrypt_error;
  }

  /* encrypt via modular exponentiation */
  ciphertext = BN_new();
  bn_ctx = BN_CTX_new();
  if (!ciphertext || !bn_ctx ||
      !BN_mod_exp(ciphertext, enc_element, e, N, bn_ctx)) {
    goto handle_padded_rsa_encrypt_error;
  }
  /* free allocated memory */
  BN_clear_free(enc_element);
  BN_clear_free(r);
  BN_CTX_free(bn_ctx);

  return ciphertext;

  handle_padded_rsa_encrypt_error:
    if (enc_element) BN_clear_free(enc_element);
    if (r) BN_clear_free(r);
    if (ciphertext) BN_clear_free(ciphertext);
    if (bn_ctx) BN_CTX_free(bn_ctx);
    return NULL;
}

/** CORE FUNCTION **/
BIGNUM* padded_rsa_decrypt(BIGNUM* c, BIGNUM* N, BIGNUM* d,
    unsigned long num_bits)
{
  BIGNUM* m_prime = BN_new();
  BN_CTX* bn_ctx = BN_CTX_new();
  int m_prime_mask_bit_len = (num_bits / 2) - 24;

  BN_mod_exp(m_prime, c, d, N, bn_ctx);
  BN_mask_bits(m_prime, m_prime_mask_bit_len);

  return m_prime;
}

void print_openssl_err_and_exit()
{
  fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
  exit(1);
}

