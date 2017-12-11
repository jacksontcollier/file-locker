#include "file-locker.h"

int main(int argc, char** argv)
{
  FileLockerOptions* file_locker_options = parse_FileLockerOptions(argc, argv);

  if (!verify_action_public_key(file_locker_options->action_public_key,
      file_locker_options->validating_public_key)) {
    printf("Locker's public key failed validation. Burn it down\n");
    exit(1);
  }

  /* Read in action public key */
  FILE* action_public_key_fin = fopen(file_locker_options->action_public_key,
      "r");
  PublicRSAKey* action_public_key = read_file_PublicRSAKey(
      action_public_key_fin);
  fclose(action_public_key_fin);

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
  FILE* manifest_fin = fopen(SYMMETRIC_KEY_MANIFEST_FILE, "r");
  char* raw_encrypted_aes_key_192 = read_single_line_file(manifest_fin);

  BIGNUM* encrypted_aes_key_192_bn;
  BN_dec2bn(&encrypted_aes_key_192_bn, raw_encrypted_aes_key_192);

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

  fwrite(aes_key_192->data, 1, AES_192_BIT_KEY_BYTE_LEN, stdout);

  return 0;
}
