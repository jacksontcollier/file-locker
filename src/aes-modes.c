#include "aes-modes.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_BLOCK_BYTE_LEN 16
#define AES_128_BIT_KEY_LEN 128
#define AES_192_BIT_KEY_LEN 192
#define AES_256_BIT_KEY_LEN 256

#define CTR_MODE_NUM_THREADS 4

const char *arg_flag_options = "k:i:o:v:";

ArgFlags* new_ArgFlags()
{
  ArgFlags *arg_flags = (ArgFlags *) malloc(sizeof(ArgFlags));

  arg_flags->key_file = NULL;
  arg_flags->in_file = NULL;
  arg_flags->out_file = NULL;
  arg_flags->iv_file = NULL;

  return arg_flags;
}

ArgFlags* parse_arg_flags(const int argc, char * const argv[])
{
  int option;
  ArgFlags *arg_flags;

  arg_flags = new_ArgFlags();

  while ((option = getopt(argc, argv, arg_flag_options)) != -1) {
    switch(option) {
      case 'k':
        arg_flags->key_file = optarg;
        break;
      case 'i':
        arg_flags->in_file = optarg;
        break;
      case 'o':
        arg_flags->out_file = optarg;
        break;
      case 'v':
        arg_flags->iv_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown option\n");
        exit(1);
    }
  }

  if (arg_flags->key_file == NULL || arg_flags->in_file == NULL ||
      arg_flags->out_file == NULL) {
    fprintf(stderr, "-k -i -o options are required\n");
    exit(1);
  }

  return arg_flags;
}

void print_arg_flags(const ArgFlags *arg_flags)
{
  if (arg_flags->key_file != NULL) {
    printf("Key file: %s\n", arg_flags->key_file);
  }
  if (arg_flags->in_file != NULL) {
    printf("Input file: %s\n", arg_flags->in_file);
  }
  if (arg_flags->out_file != NULL) {
    printf("Output file: %s\n", arg_flags->out_file);
  }
  if (arg_flags->iv_file != NULL) {
    printf("IV file: %s\n", arg_flags->iv_file);
  }
}

ByteBuf* new_ByteBuf()
{
  ByteBuf* byte_buf;

  byte_buf = (ByteBuf *) malloc(sizeof(ByteBuf));
  byte_buf->data = NULL;
  byte_buf->len = 0;

  return byte_buf;
}

AesKey* new_AesKey()
{
  AesKey* aes_key;
  aes_key = (AesKey *) malloc(sizeof(AesKey));
  aes_key->hex_encoding = NULL;
  aes_key->byte_encoding = NULL;
  aes_key->hex_len = 0;
  aes_key->byte_len = 0;
  aes_key->bit_len = 0;

  return aes_key;
}

ByteBuf* read_file_contents(const char *filename)
{
  FILE* fin;
  ByteBuf* file_buf;
  size_t file_len;

  fin = fopen(filename, "r");
  fseek(fin, 0, SEEK_END);
  file_len = ftell(fin);
  fseek(fin, 0, SEEK_SET);

  file_buf = new_ByteBuf();
  file_buf->data = (unsigned char *) malloc(file_len);

  if (file_buf != NULL && file_buf->data != NULL) {
    file_buf->len = fread(file_buf->data, sizeof(unsigned char), file_len, fin);
  }
  fclose(fin);

  return file_buf;
}

void write_file(const ByteBuf* file_buf, const char* filename)
{
  FILE* fout;
  fout = fopen(filename, "w");
  fwrite(file_buf->data, 1, file_buf->len, fout);
  fclose(fout);

  return;
}

AesKey* get_aes_key(const char* key_file)
{
  AesKey* aes_key;

  aes_key = new_AesKey();
  aes_key->hex_encoding = read_file_contents(key_file);
  aes_key->hex_len = aes_key->hex_encoding->len;
  aes_key->byte_len = (aes_key->hex_len / 2);
  aes_key->bit_len = aes_key->byte_len * 8;
  aes_key->byte_encoding = hex_decode(aes_key->hex_encoding);

  return aes_key;
}

unsigned char hex_2_dec(const unsigned char hex_char)
{
  if (hex_char >= '0' && hex_char <= '9') {
    return hex_char - '0';
  }

  if (hex_char >= 'A' && hex_char <= 'F') {
    return (hex_char - 'A') + 10;
  }

  if (hex_char >= 'a' && hex_char <= 'f') {
    return (hex_char - 'a') + 10;
  }

  return hex_char;
}

ByteBuf* hex_decode(const ByteBuf* hex_buf)
{
  size_t i;
  size_t buf_size;
  ByteBuf* bytes;

  buf_size = (hex_buf->len / 2) + (hex_buf->len % 2);
  bytes = new_ByteBuf();
  bytes->data = (unsigned char *) malloc(buf_size);
  bytes->len = buf_size;

  if (bytes != NULL) {
    for (i = 0; i < hex_buf->len; i += 2) {
      bytes->data[i/2] = hex_2_dec(hex_buf->data[i]) << 4;
      if (i + 1 >= hex_buf->len) break;
      bytes->data[i/2] |= hex_2_dec(hex_buf->data[i+1]);
    }
  }

  return bytes;
}

ByteBuf* get_cbc_plaintext(const char* plaintext_file)
{
  size_t i;
  size_t pad_bytes_required;
  ByteBuf *unpadded_plaintext;
  ByteBuf *padded_plaintext;

  unpadded_plaintext = read_file_contents(plaintext_file);
  pad_bytes_required = get_cbc_pkcs7pad_required(unpadded_plaintext);
  padded_plaintext = new_ByteBuf();
  padded_plaintext->len = unpadded_plaintext->len + pad_bytes_required;
  padded_plaintext->data = (unsigned char *) malloc(padded_plaintext->len);

  memcpy(padded_plaintext->data, unpadded_plaintext->data,
      unpadded_plaintext->len);

  for (i = unpadded_plaintext->len; i < padded_plaintext->len; i++) {
    padded_plaintext->data[i] = (unsigned char) pad_bytes_required;
  }

  return padded_plaintext;
}

size_t get_cbc_pkcs7pad_required(const ByteBuf* unpadded_plaintext)
{
  return AES_BLOCK_BYTE_LEN - (unpadded_plaintext->len % AES_BLOCK_BYTE_LEN);
}

ByteBuf* get_iv(const char *iv_file)
{
  ByteBuf* iv;
  ByteBuf* iv_file_buf;

  if (iv_file == NULL) {
    iv = generate_new_iv();
  } else {
    iv_file_buf = read_file_contents(iv_file);
    iv = hex_decode(iv_file_buf);
  }

  return iv;
}

ByteBuf* generate_new_iv()
{
  /* Figured out how to do this by reading SO posts and openssl docs. */
  int sprng_bytes_received;
  ByteBuf* iv;

  sprng_bytes_received = 0;
  iv = new_ByteBuf();
  iv->len = AES_BLOCK_BYTE_LEN;
  iv->data = (unsigned char *) malloc(iv->len);

  while (!sprng_bytes_received) {
    sprng_bytes_received = RAND_bytes(iv->data, iv->len);
  }

  return iv;
}

void aes_block_xor(const unsigned char* plaintext_block,
    const unsigned char* ciphertext_block, unsigned char* out)
{
  size_t i;

  for (i = 0; i < AES_BLOCK_BYTE_LEN; i++) {
    out[i] = plaintext_block[i] ^ ciphertext_block[i];
  }

  return;
}

const EVP_CIPHER* get_evp_cipher_type(const AesKey *aes_key)
{
  if (aes_key->bit_len == AES_128_BIT_KEY_LEN) {
    return EVP_aes_128_ecb();
  } else if (aes_key->bit_len == AES_192_BIT_KEY_LEN) {
    return EVP_aes_192_ecb();
  } else if (aes_key->bit_len == AES_256_BIT_KEY_LEN) {
    return EVP_aes_256_ecb();
  } else {
    fprintf(stderr, "Invalid key length of %ld\n bits", aes_key->bit_len);
    exit(1);
  }
}

ByteBuf* cbc_aes_encrypt(AesKey* aes_key, ByteBuf* cbc_plaintext, ByteBuf* iv)
{
  int outlen;
  ByteBuf* cbc_ciphertext;
  EVP_CIPHER_CTX* ctx;
  unsigned char xor_out_buf[AES_BLOCK_BYTE_LEN];

  cbc_ciphertext = new_ByteBuf();
  cbc_ciphertext->len = iv->len + cbc_plaintext->len;
  cbc_ciphertext->data = (unsigned char *) malloc(cbc_ciphertext->len);

  /* prepend iv to ciphertext */
  memcpy(cbc_ciphertext->data, iv->data, AES_BLOCK_BYTE_LEN);

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, get_evp_cipher_type(aes_key), NULL,
      aes_key->byte_encoding->data, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  for (size_t i = 0; i < cbc_plaintext->len; i += AES_BLOCK_BYTE_LEN) {
    aes_block_xor(&cbc_plaintext->data[i], &cbc_ciphertext->data[i],
        xor_out_buf);
    EVP_EncryptUpdate(ctx, &cbc_ciphertext->data[i+AES_BLOCK_BYTE_LEN], &outlen,
        xor_out_buf, AES_BLOCK_BYTE_LEN);
  }
  EVP_CIPHER_CTX_free(ctx);

  return cbc_ciphertext;
}

ByteBuf* cbc_aes_decrypt(AesKey* aes_key, ByteBuf* cbc_ciphertext)
{
  int outlen;
  long i;
  ByteBuf* cbc_plaintext;
  EVP_CIPHER_CTX* ctx;
  unsigned char aes_out_buf[AES_BLOCK_BYTE_LEN];
  unsigned char plaintext_buf[AES_BLOCK_BYTE_LEN];

  cbc_plaintext = new_ByteBuf();
  cbc_plaintext->len = cbc_ciphertext->len - AES_BLOCK_BYTE_LEN;
  cbc_plaintext->data = (unsigned char *) malloc(cbc_plaintext->len);

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, get_evp_cipher_type(aes_key), NULL,
      aes_key->byte_encoding->data, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  for (i = cbc_plaintext->len - AES_BLOCK_BYTE_LEN; i >= 0;
      i -= AES_BLOCK_BYTE_LEN) {
    EVP_DecryptUpdate(ctx, aes_out_buf, &outlen,
        &cbc_ciphertext->data[i + AES_BLOCK_BYTE_LEN], AES_BLOCK_BYTE_LEN);
    aes_block_xor(aes_out_buf, &cbc_ciphertext->data[i], plaintext_buf);
    memcpy(&cbc_plaintext->data[i], plaintext_buf, AES_BLOCK_BYTE_LEN);
  }
  EVP_CIPHER_CTX_free(ctx);

  return cbc_plaintext;
}

void write_cbc_decrypted_ciphertext(ByteBuf* cbc_plaintext, char* outfile)
{
  size_t num_pad_bytes;
  size_t true_plaintext_len;
  FILE* fout;

  num_pad_bytes = (size_t) cbc_plaintext->data[cbc_plaintext->len-1];
  true_plaintext_len = cbc_plaintext->len - num_pad_bytes;

  fout = fopen(outfile, "w");
  fwrite(cbc_plaintext->data, 1, true_plaintext_len, fout);
  fclose(fout);

  return;
}

ByteBuf* new_incremented_iv(const ByteBuf* iv)
{
  int i;
  ByteBuf* incremented_iv;

  incremented_iv = new_ByteBuf();
  incremented_iv->len = AES_BLOCK_BYTE_LEN;
  incremented_iv->data = (unsigned char *) malloc(incremented_iv->len);

  memcpy(incremented_iv->data, iv->data, AES_BLOCK_BYTE_LEN);

  for (i = incremented_iv->len - 1; i >= 0; i--) {
    incremented_iv->data[i] = incremented_iv->data[i] + 1;
    if (incremented_iv->data[i] > 0) break;
  }

  return incremented_iv;
}

CtrModeBlock* new_CtrModeBlock()
{
  CtrModeBlock *block;

  block = (CtrModeBlock *) malloc(sizeof(CtrModeBlock));
  block->in_begin = NULL;
  block->out_begin = NULL;
  block->len = 0;
  block->iv = NULL;

  return block;
}

CtrModeThreadData* new_CtrModeThreadData()
{
  CtrModeThreadData *thread_data;

  thread_data = malloc(sizeof(CtrModeThreadData));
  thread_data->blocks = NULL;
  thread_data->block_capacity = 0;
  thread_data->num_blocks = 0;
  thread_data->aes_key = NULL;
  thread_data->ctx = NULL;
  thread_data->block_buf = new_ByteBuf();
  thread_data->block_buf->len = AES_BLOCK_BYTE_LEN;
  thread_data->block_buf->data = (unsigned char *) malloc(AES_BLOCK_BYTE_LEN);

  return thread_data;
}

ByteBuf* ctr_aes_encrypt(AesKey *aes_key, ByteBuf* ctr_plaintext, ByteBuf* iv)
{
  size_t i, block_count;
  size_t num_plaintext_blocks;
  CtrModeThreadData *thread_data[CTR_MODE_NUM_THREADS];
  CtrModeThreadData *assigned_thread;
  ByteBuf *ctr_ciphertext;
  ByteBuf *incremented_iv;
  EVP_CIPHER_CTX *ctx;
  CtrModeBlock *block;

  ctr_ciphertext = new_ByteBuf();
  ctr_ciphertext->len = ctr_plaintext->len + AES_BLOCK_BYTE_LEN;
  ctr_ciphertext->data = (unsigned char *) malloc(ctr_ciphertext->len);
  memcpy(ctr_ciphertext->data, iv->data, iv->len);

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, get_evp_cipher_type(aes_key), NULL,
      aes_key->byte_encoding->data, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  num_plaintext_blocks = ctr_plaintext->len / AES_BLOCK_BYTE_LEN;
  if (ctr_plaintext->len % AES_BLOCK_BYTE_LEN > 0) {
    num_plaintext_blocks++;
  }

  /* Create ctr mode data structure for each spawned thread */
  for (i = 0; i < CTR_MODE_NUM_THREADS; i++) {
    thread_data[i] = new_CtrModeThreadData();
    thread_data[i]->block_capacity = num_plaintext_blocks / CTR_MODE_NUM_THREADS;
    if (i < (num_plaintext_blocks % CTR_MODE_NUM_THREADS)) {
      thread_data[i]->block_capacity++;
    }
    thread_data[i]->blocks = (CtrModeBlock **) malloc(sizeof(CtrModeBlock *) *
        thread_data[i]->block_capacity);
    thread_data[i]->aes_key = aes_key;
    thread_data[i]->ctx = ctx;
  }

  incremented_iv = iv;

  block_count = 0;
  /* Partition plaintext into blocks, assign block to thread */
  for (i = 0; i < ctr_plaintext->len; i += AES_BLOCK_BYTE_LEN) {
    block = new_CtrModeBlock();
    block->in_begin = &(ctr_plaintext->data[i]);
    block->out_begin = &(ctr_ciphertext->data[i + AES_BLOCK_BYTE_LEN]);
    if (i + AES_BLOCK_BYTE_LEN <= ctr_plaintext->len) {
      block->len = AES_BLOCK_BYTE_LEN;
    } else {
      block->len = ctr_plaintext->len - i;
    }
    block->iv = incremented_iv;
    incremented_iv = new_incremented_iv(incremented_iv);
    assigned_thread = thread_data[block_count % CTR_MODE_NUM_THREADS];
    block_count++;
    assigned_thread->blocks[assigned_thread->num_blocks] = block;
    assigned_thread->num_blocks++;
  }

  pthread_t tcb_0, tcb_1, tcb_2, tcb_3;
  void *status;

  pthread_create(&tcb_0, NULL, ctr_thread_encrypt, thread_data[0]);
  pthread_create(&tcb_1, NULL, ctr_thread_encrypt, thread_data[1]);
  pthread_create(&tcb_2, NULL, ctr_thread_encrypt, thread_data[2]);
  pthread_create(&tcb_3, NULL, ctr_thread_encrypt, thread_data[3]);

  pthread_join(tcb_0, &status);
  pthread_join(tcb_1, &status);
  pthread_join(tcb_2, &status);
  pthread_join(tcb_3, &status);

  return ctr_ciphertext;
}

void *ctr_thread_encrypt(void *data)
{
  int outlen;
  size_t i;
  unsigned char xor_buf[AES_BLOCK_BYTE_LEN];
  CtrModeThreadData *thread_data;

  thread_data = (CtrModeThreadData *) data;

  for (i = 0; i < thread_data->num_blocks; i++) {
    EVP_EncryptUpdate(thread_data->ctx, thread_data->block_buf->data, &outlen,
        thread_data->blocks[i]->iv->data, thread_data->blocks[i]->iv->len);
    aes_block_xor(thread_data->blocks[i]->in_begin, thread_data->block_buf->data,
        xor_buf);
    memcpy(thread_data->blocks[i]->out_begin, xor_buf,
        thread_data->blocks[i]->len);
  }

  return NULL;
}

ByteBuf* ctr_aes_decrypt(AesKey *aes_key, ByteBuf* ctr_ciphertext)
{
  size_t i, block_count;
  size_t num_ciphertext_blocks;
  CtrModeThreadData *thread_data[CTR_MODE_NUM_THREADS];
  CtrModeThreadData *assigned_thread;
  ByteBuf *ctr_plaintext;
  ByteBuf *iv;
  ByteBuf *incremented_iv;
  EVP_CIPHER_CTX *ctx;
  CtrModeBlock *block;

  iv = new_ByteBuf();
  iv->len = AES_BLOCK_BYTE_LEN;
  iv->data = ctr_ciphertext->data;
  ctr_ciphertext->len = ctr_ciphertext->len - AES_BLOCK_BYTE_LEN;
  ctr_ciphertext->data = &(ctr_ciphertext->data[AES_BLOCK_BYTE_LEN]);

  ctr_plaintext = new_ByteBuf();
  ctr_plaintext->len = ctr_ciphertext->len;
  ctr_plaintext->data = (unsigned char *) malloc(ctr_plaintext->len);

  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, get_evp_cipher_type(aes_key), NULL,
      aes_key->byte_encoding->data, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  num_ciphertext_blocks = ctr_ciphertext->len / AES_BLOCK_BYTE_LEN;
  if (ctr_ciphertext->len % AES_BLOCK_BYTE_LEN > 0) {
    num_ciphertext_blocks++;
  }

  /* Create ctr mode data structure for each spawned thread */
  for (i = 0; i < CTR_MODE_NUM_THREADS; i++) {
    thread_data[i] = new_CtrModeThreadData();
    thread_data[i]->block_capacity = num_ciphertext_blocks / CTR_MODE_NUM_THREADS;
    if (i < (num_ciphertext_blocks % CTR_MODE_NUM_THREADS)) {
      thread_data[i]->block_capacity++;
    }
    thread_data[i]->blocks = (CtrModeBlock **) malloc(sizeof(CtrModeBlock *) *
        thread_data[i]->block_capacity);
    thread_data[i]->aes_key = aes_key;
    thread_data[i]->ctx = ctx;
  }

  incremented_iv = iv;

  block_count = 0;
  /* Partition ciphertext into blocks, assign block to thread */
  for (i = 0; i < ctr_ciphertext->len; i += AES_BLOCK_BYTE_LEN) {
    block = new_CtrModeBlock();
    block->in_begin = &(ctr_ciphertext->data[i]);
    block->out_begin = &(ctr_plaintext->data[i]);
    if (i + AES_BLOCK_BYTE_LEN <= ctr_ciphertext->len) {
      block->len = AES_BLOCK_BYTE_LEN;
    } else {
      block->len = ctr_ciphertext->len - i;
    }
    block->iv = incremented_iv;
    incremented_iv = new_incremented_iv(incremented_iv);
    assigned_thread = thread_data[block_count % CTR_MODE_NUM_THREADS];
    block_count++;
    assigned_thread->blocks[assigned_thread->num_blocks] = block;
    assigned_thread->num_blocks++;
  }

  pthread_t tcb_0, tcb_1, tcb_2, tcb_3;
  void *status;

  pthread_create(&tcb_0, NULL, ctr_thread_encrypt, thread_data[0]);
  pthread_create(&tcb_1, NULL, ctr_thread_encrypt, thread_data[1]);
  pthread_create(&tcb_2, NULL, ctr_thread_encrypt, thread_data[2]);
  pthread_create(&tcb_3, NULL, ctr_thread_encrypt, thread_data[3]);

  pthread_join(tcb_0, &status);
  pthread_join(tcb_1, &status);
  pthread_join(tcb_2, &status);
  pthread_join(tcb_3, &status);

  return ctr_plaintext;
}
