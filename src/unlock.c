#include "file-locker.h"

#include <string.h>

int main(int argc, char** argv)
{
  FileLockerOptions* file_locker_options = parse_FileLockerOptions(argc, argv);

  if (!verify_action_public_key(file_locker_options->action_public_key,
      file_locker_options->validating_public_key)) {
    printf("Locker's public key failed validation. Burn it down\n");
    exit(1);
  }

  /* Validate symmetric key manifest */
  RSASigOptions* manifest_sig_options = new_RSASigOptions();
  manifest_sig_options->key_file = file_locker_options->action_public_key;
  manifest_sig_options->message_file = SYMMETRIC_KEY_MANIFEST_FILE;
  manifest_sig_options->sig_file = SYMMETRIC_KEY_MANIFEST_SIG_FILE;

  if (!rsa_validate(manifest_sig_options)) {
    printf("Invalid signature on manifest\n");
    exit(1);
  }

  /* Read contents of manifest file into */
  ByteBuf* raw_encrypted_aes_key_192 = read_file_contents(SYMMETRIC_KEY_MANIFEST_FILE);
  char* null_terminated_aes = malloc(raw_encrypted_aes_key_192->len + 1);
  memcpy(null_terminated_aes, raw_encrypted_aes_key_192->data,
      raw_encrypted_aes_key_192->len);
  null_terminated_aes[raw_encrypted_aes_key_192->len] = '\0';

  BIGNUM* encrypted_aes_key_192_bn = BN_new();
  BN_dec2bn(&encrypted_aes_key_192_bn, null_terminated_aes);

  FILE* action_private_key_fin = fopen(file_locker_options->action_private_key,
      "r");
  SecretRSAKey* action_private_key = read_file_SecretRSAKey(
      action_private_key_fin);
  fclose(action_private_key_fin);

  BIGNUM* aes_key_192_bn = padded_rsa_decrypt(encrypted_aes_key_192_bn,
      action_private_key->N, action_private_key->d,
      action_private_key->num_bits);

  ByteBuf* aes_key_192 = new_ByteBuf();
  aes_key_192->len = BN_num_bytes(aes_key_192_bn);
  aes_key_192->data = malloc(aes_key_192->len);

  BN_bn2bin(aes_key_192_bn, aes_key_192->data);

  AesKey* aes_key = new_AesKey();
  aes_key->byte_encoding = aes_key_192;
  aes_key->byte_len = AES_192_BIT_KEY_BYTE_LEN;
  aes_key->bit_len = 192;

  unlock_directory(file_locker_options->directory, aes_key);
  remove(SYMMETRIC_KEY_MANIFEST_FILE);
  remove(SYMMETRIC_KEY_MANIFEST_SIG_FILE);

  return 0;
}
