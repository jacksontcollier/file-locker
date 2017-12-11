#ifndef FILELOCKER_H
#define FILELOCKER_H

#include "aes-modes.h"
#include "padded-rsa.h"

#include <stdlib.h>
#include <stdio.h>

#define AES_192_BIT_KEY_BYTE_LEN 24

#define SYMMETRIC_KEY_MANIFEST_FILE "symmetric-key-manifest\0"
#define SYMMETRIC_KEY_MANIFEST_SIG_FILE "symmetric-key-manifest-sig\0"

typedef struct rsa_sig_options
{
  char* key_file;
  char* message_file;
  char* sig_file;
} RSASigOptions;

RSASigOptions* new_RSASigOptions();

RSASigOptions* parse_RSASigOptions(int argc, char * const argv[]);

void print_RSASigOptions(const RSASigOptions* rsa_sig_options);

unsigned char* sha_256_hash(char* data, size_t data_size);

BIGNUM* generate_rsa_sig(char* message, size_t message_len,
    SecretRSAKey* secret_rsa_key);

int rsa_sign(const RSASigOptions* rsa_sig_options);

int rsa_validate(const RSASigOptions* rsa_sig_options);

typedef struct cbc_mac_options
{
  char* key_file;
  char* message_file;
  char* output_file;
} CBCMacOptions;

CBCMacOptions* new_CBCMacOptions();

CBCMacOptions* parse_CBCMacOptions(int argc, char * const argv[]);

void print_CBCMacOptions(const CBCMacOptions* cbc_mac_options);

ByteBuf* generate_cbc_mac_tag(AesKey* aes_key, ByteBuf* padded_message);

int cbc_mac_tag(const CBCMacOptions* cbc_mac_options);

int cbc_mac_validate(const CBCMacOptions* cbc_mac_options);

char* get_casig_filename(char* key_filename);

typedef struct file_locker_options
{
  char* directory;
  char* action_public_key;
  char* action_private_key;
  char* validating_public_key;
} FileLockerOptions;

FileLockerOptions* new_FileLockerOptions();

FileLockerOptions* parse_FileLockerOptions(int argc, char * const argv[]);

void print_FileLockerOptions(const FileLockerOptions* file_locker_options);

int verify_action_public_key(char* action_pk_file, char* ca_pk_file);

ByteBuf* gen_192_bit_aes_key();

char* form_full_file_name(char* directory_name, char* file_name);

char* form_tag_file_name(char* full_file_name);

void lock_directory(char* directory, AesKey* aes_key);

void unlock_directory(char* directory, AesKey* aes_key);

char* read_single_line_file(FILE* fin);
#endif
