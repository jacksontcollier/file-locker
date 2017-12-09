#ifndef AESMODES_H
#define AESMODES_H

#include <stddef.h>

#include <openssl/evp.h>

typedef struct byte_buf
{
  unsigned char* data;
  size_t len;
} ByteBuf;

ByteBuf* new_ByteBuf();

typedef struct arg_flags
{
  char *key_file;
  char *in_file;
  char *out_file;
  char *iv_file;
} ArgFlags;

ArgFlags* new_ArgFlags();

ArgFlags* parse_arg_flags(const int argc, char * const argv[]);

typedef struct aes_key
{
  ByteBuf* hex_encoding;
  ByteBuf* byte_encoding;
  size_t hex_len;
  size_t byte_len;
  size_t bit_len;
} AesKey;

AesKey* new_AesKey();

AesKey* get_aes_key(const char* key_file);

void print_arg_flags(const ArgFlags *arg_flags);

ByteBuf* read_file_contents(const char *filename);

void write_file(const ByteBuf* file_buf, const char* filename);

unsigned char hex_2_dec(const unsigned char hex_char);

ByteBuf* hex_decode(const ByteBuf* hex_buf);

ByteBuf* get_cbc_plaintext(const char* plaintext_file);

size_t get_cbc_pkcs7pad_required(const ByteBuf* unpadded_plaintext);

ByteBuf* get_iv(const char* iv_file);

ByteBuf* generate_new_iv();

void aes_block_xor(const unsigned char* plaintext_block,
    const unsigned char* ciphertext_block, unsigned char* out);

ByteBuf* cbc_aes_encrypt(AesKey* aes_key, ByteBuf* cbc_plaintext, ByteBuf* iv);

ByteBuf* cbc_aes_decrypt(AesKey* aes_key, ByteBuf* cbc_ciphertext);

void write_cbc_decrypted_ciphertext(ByteBuf* cbc_plaintext, char* outfile);

ByteBuf* new_incremented_iv(const ByteBuf* iv);

typedef struct ctr_mode_block
{
  unsigned char *in_begin;
  unsigned char *out_begin;
  size_t len;
  ByteBuf *iv;
} CtrModeBlock;

CtrModeBlock* new_CtrModeBlock();

typedef struct ctr_mode_thread_data
{
  CtrModeBlock **blocks;
  size_t block_capacity;
  size_t num_blocks;
  AesKey *aes_key;
  EVP_CIPHER_CTX *ctx;
  ByteBuf *block_buf;
} CtrModeThreadData;

CtrModeThreadData* new_CtrModeThreadData();

ByteBuf* ctr_aes_encrypt(AesKey *aes_key, ByteBuf* ctr_plaintext, ByteBuf* iv);

void *ctr_thread_encrypt(void *data);

ByteBuf* ctr_aes_decrypt(AesKey *aes_key, ByteBuf* ctr_ciphertext);

#endif
