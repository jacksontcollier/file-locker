#include "file-locker.h"

int main(int argc, char** argv)
{
  FileLockerOptions* file_locker_options = parse_FileLockerOptions(argc, argv);

  if (!verify_action_public_key(file_locker_options->action_public_key,
      file_locker_options->validating_public_key)) {
    printf("Unlocker's public key failed validation. Burn it down\n");
    exit(1);
  }

  /* Read in action public key */
  FILE* action_public_key_fin = fopen(file_locker_options->action_public_key,
      "r");
  PublicRSAKey* action_public_key = read_file_PublicRSAKey(
      action_public_key_fin);
  fclose(action_public_key_fin);

  /* Generate aes key and convert to BIGNUM for rsa encryption */
  ByteBuf* aes_key_192 = gen_192_bit_aes_key();
  BIGNUM* aes_key_192_bn = BN_new();
  BN_bin2bn(aes_key_192->data, AES_192_BIT_KEY_BYTE_LEN, aes_key_192_bn);
  BIGNUM* encrypted_aes_key_bn = padded_rsa_encrypt(aes_key_192_bn,
      action_public_key->N, action_public_key->e,
      action_public_key->num_bits);

  /* Write encrypted aes key to symmetric-key-manifest */
  FILE* symmetric_key_manifest_fout = fopen(SYMMETRIC_KEY_MANIFEST_FILE, "w");
  fprintf(symmetric_key_manifest_fout, "%s", BN_bn2dec(encrypted_aes_key_bn));
  fclose(symmetric_key_manifest_fout);

  /* Sign the symmetric key manifest with locker's private key */
  RSASigOptions* manifest_sig_options = new_RSASigOptions();
  manifest_sig_options->key_file = file_locker_options->action_private_key;
  manifest_sig_options->message_file = SYMMETRIC_KEY_MANIFEST_FILE;
  manifest_sig_options->sig_file = SYMMETRIC_KEY_MANIFEST_SIG_FILE;
  rsa_sign(manifest_sig_options);

  return 0;
}
