#include "file-locker.h"
#include "aes-modes.h"
#include "padded-rsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#define AES_BLOCK_BYTE_LEN 16
#define SHA_256_BYTE_LEN 32

const char* rsa_sig_arg_options = "k:m:s:";

RSASigOptions* new_RSASigOptions()
{
  RSASigOptions* rsa_sig_options = malloc(sizeof(RSASigOptions));

  rsa_sig_options->key_file = NULL;
  rsa_sig_options->message_file = NULL;
  rsa_sig_options->sig_file = NULL;

  return rsa_sig_options;
}

RSASigOptions* parse_RSASigOptions(int argc, char * const argv[])
{
  int option;
  RSASigOptions* rsa_sig_options = new_RSASigOptions();

  while ((option = getopt(argc, argv, rsa_sig_arg_options)) != -1) {
    switch(option) {
      case 'k':
        rsa_sig_options->key_file = optarg;
        break;
      case 'm':
        rsa_sig_options->message_file = optarg;
        break;
      case 's':
        rsa_sig_options->sig_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);

    }
  }

  return rsa_sig_options;
}

void print_RSASigOptions(const RSASigOptions* rsa_sig_options)
{
  printf("Key file: %s\n", rsa_sig_options->key_file);
  printf("Message file: %s\n", rsa_sig_options->message_file);
  printf("Signature file: %s\n", rsa_sig_options->sig_file);
}

unsigned char* sha_256_hash(char* data, size_t data_size)
{
  unsigned char* hash = malloc(SHA_256_BYTE_LEN);
  hash = SHA256((unsigned char*) data, data_size, hash);
  return hash;
}

BIGNUM* generate_rsa_sig(char* message, size_t message_len,
    SecretRSAKey* secret_rsa_key)
{
  // Hash message using SHA 256
  unsigned char* message_hash = sha_256_hash(message, message_len);

  // Encode hashed message as BN
  BIGNUM* message_hash_bn = BN_new();
  message_hash_bn = BN_bin2bn(message_hash, SHA_256_BYTE_LEN,
      message_hash_bn);

  // Sign Hash, raise hash to d, mod N
  BN_CTX* bn_ctx = BN_CTX_new();
  BIGNUM* sig_bn = BN_new();
  BN_mod_exp(sig_bn, message_hash_bn, secret_rsa_key->d, secret_rsa_key->N,
      bn_ctx);

  BN_CTX_free(bn_ctx);

  return sig_bn;
}

int rsa_sign(const RSASigOptions* rsa_sig_options)
{
  FILE* secret_rsa_key_fin = fopen(rsa_sig_options->key_file, "r");
  SecretRSAKey* secret_rsa_key = read_file_SecretRSAKey(secret_rsa_key_fin);
  fclose(secret_rsa_key_fin);

  FILE* message_fin = fopen(rsa_sig_options->message_file, "r");
  char* message = read_single_line_file(message_fin);
  fclose(message_fin);

  BIGNUM* rsa_sig_bn = generate_rsa_sig(message, strlen(message),
      secret_rsa_key);

  FILE* sig_fout = fopen(rsa_sig_options->sig_file, "w");
  fprintf(sig_fout, "%s", BN_bn2dec(rsa_sig_bn));
  fclose(sig_fout);

  return 1;
}

int rsa_validate(const RSASigOptions* rsa_sig_options)
{
  FILE* public_rsa_key_fin = fopen(rsa_sig_options->key_file, "r");
  PublicRSAKey* public_rsa_key = read_file_PublicRSAKey(public_rsa_key_fin);
  fclose(public_rsa_key_fin);

  FILE* message_fin = fopen(rsa_sig_options->message_file, "r");
  char* message = read_single_line_file(message_fin);
  fclose(message_fin);

  FILE* sig_fin = fopen(rsa_sig_options->sig_file, "r");
  char* sig = read_single_line_file(sig_fin);
  fclose(sig_fin);

  unsigned char* message_hash = sha_256_hash(message, strlen(message));

  BIGNUM* message_hash_bn = BN_new();
  message_hash_bn = BN_bin2bn(message_hash, SHA_256_BYTE_LEN,
      message_hash_bn);

  BN_CTX* bn_ctx = BN_CTX_new();

  BIGNUM* message_hash_mod_N = BN_new();
  BN_mod(message_hash_mod_N, message_hash_bn, public_rsa_key->N, bn_ctx);
  BIGNUM* sig_bn = BN_new();
  BN_dec2bn(&sig_bn, sig);

  BIGNUM* inverted_sig_bn = BN_new();
  BN_mod_exp(inverted_sig_bn, sig_bn, public_rsa_key->e, public_rsa_key->N,
      bn_ctx);

  if (BN_cmp(inverted_sig_bn, message_hash_mod_N) == 0) {
    return 1;
  }

  return 0;
}

const char* cbc_mac_arg_options = "k:m:t:";

CBCMacOptions* new_CBCMacOptions()
{
  CBCMacOptions* cbc_mac_options = malloc(sizeof(CBCMacOptions));

  cbc_mac_options->key_file = NULL;
  cbc_mac_options->message_file = NULL;
  cbc_mac_options->output_file = NULL;

  return cbc_mac_options;
}

CBCMacOptions* parse_CBCMacOptions(int argc, char * const argv[])
{
  int option;
  CBCMacOptions* cbc_mac_options = new_CBCMacOptions();

  while ((option = getopt(argc, argv, cbc_mac_arg_options)) != -1) {
    switch(option) {
      case 'k':
        cbc_mac_options->key_file = optarg;
        break;
      case 'm':
        cbc_mac_options->message_file = optarg;
        break;
      case 't':
        cbc_mac_options->output_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  return cbc_mac_options;
}

void print_CBCMacOptions(const CBCMacOptions* cbc_mac_options)
{
  printf("Key file: %s\n", cbc_mac_options->key_file);
  printf("Message file: %s\n", cbc_mac_options->message_file);
  printf("Output file: %s\n", cbc_mac_options->output_file);
}

ByteBuf* generate_cbc_mac_tag(AesKey* aes_key, ByteBuf* padded_message)
{
  /* Allocate zero-initialized iv */
  ByteBuf* iv = new_ByteBuf();
  iv->len = AES_BLOCK_BYTE_LEN;
  iv->data = calloc(iv->len, 1);

  /* cbc encrypt message */
  ByteBuf* ciphertext = cbc_aes_encrypt(aes_key, padded_message, iv);

  /* extract tag as last block of ciphertext */
  ByteBuf* tag = new_ByteBuf();
  tag->len = AES_BLOCK_BYTE_LEN;
  tag->data = malloc(AES_BLOCK_BYTE_LEN);
  memcpy(tag->data, &ciphertext->data[ciphertext->len - tag->len], tag->len);

  /* Free ciphertext and iv */
  free(iv->data);
  free(iv);
  free(ciphertext->data);
  free(ciphertext);

  return tag;
}

int cbc_mac_tag(const CBCMacOptions* cbc_mac_options)
{
  AesKey* aes_key = get_aes_key(cbc_mac_options->key_file);
  ByteBuf* padded_message = get_cbc_plaintext(cbc_mac_options->message_file);

  ByteBuf* tag = generate_cbc_mac_tag(aes_key, padded_message);

  FILE* tag_fout = fopen(cbc_mac_options->output_file, "w");
  fwrite(tag->data, 1, AES_BLOCK_BYTE_LEN, tag_fout);
  fclose(tag_fout);

  return 1;
}

int cbc_mac_validate(const CBCMacOptions* cbc_mac_options)
{
  AesKey* aes_key = get_aes_key(cbc_mac_options->key_file);
  ByteBuf* padded_message = get_cbc_plaintext(cbc_mac_options->message_file);

  /* Get tag for message */
  ByteBuf* generated_tag = generate_cbc_mac_tag(aes_key, padded_message);

  /* Get message tag from file */
  ByteBuf* read_tag = read_file_contents(cbc_mac_options->output_file);

  /* Compare generated tag vs. read tag */
  if (memcmp(generated_tag->data, read_tag->data, AES_BLOCK_BYTE_LEN) == 0) {
    return 1;
  }

  return 0;
}

const char* file_locker_arg_options = "d:p:r:vk:";

FileLockerOptions* new_FileLockerOptions()
{
  FileLockerOptions* file_locker_options = malloc(sizeof(FileLockerOptions));

  file_locker_options->directory = NULL;
  file_locker_options->action_public_key = NULL;
  file_locker_options->action_private_key = NULL;
  file_locker_options->validating_public_key = NULL;

  return file_locker_options;
}

FileLockerOptions* parse_FileLockerOptions(int argc, char * const argv[])
{
  int option;
  int should_read_validating_public_key = 0;
  FileLockerOptions* file_locker_options = new_FileLockerOptions();

  while ((option = getopt(argc, argv, file_locker_arg_options)) != -1) {
    switch(option) {
      case 'd':
        file_locker_options->directory = optarg;
        break;
      case 'p':
        file_locker_options->action_public_key = optarg;
        break;
      case 'r':
        file_locker_options->action_private_key = optarg;
        break;
      case 'v':
        should_read_validating_public_key = 1;
        break;
      case 'k':
        if (should_read_validating_public_key) {
          file_locker_options->validating_public_key = optarg;
        }
        break;
      default:
        fprintf(stderr, "Unknown command line option %c\n", option);
        exit(1);
    }
  }

  return file_locker_options;
}

void print_FileLockerOptions(const FileLockerOptions* file_locker_options)
{
  printf("Directory: %s\n", file_locker_options->directory);
  printf("Action Public Key: %s\n", file_locker_options->action_public_key);
  printf("Action Private Key: %s\n", file_locker_options->action_private_key);
  printf("Validating Public Key: %s\n",
      file_locker_options->validating_public_key);
}

char* read_single_line_file(FILE* fin)
{
  char* contents = NULL;
  size_t getline_buf_size = 0;

  getline(&contents, &getline_buf_size, fin);
  strip_newline(contents);

  return contents;
}

