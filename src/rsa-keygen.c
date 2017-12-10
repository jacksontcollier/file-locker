#include <string.h>

#include "aes-modes.h"
#include "file-locker.h"
#include "padded-rsa.h"

int main(int argc, char** argv)
{
  RSAKeygenOptions* keygen_options = parse_RSAKeygenOptions(argc, argv);
  RSAKey* rsa_key = gen_RSAKey(keygen_options->num_bits);

  FILE* public_key_out = fopen(keygen_options->public_key_file, "w");
  write_RSAKey(public_key_out, rsa_key->num_bits, BN_bn2dec(rsa_key->N),
               BN_bn2dec(rsa_key->e));
  fclose(public_key_out);

  FILE* secret_key_out = fopen(keygen_options->secret_key_file, "w");
  write_RSAKey(secret_key_out, rsa_key->num_bits, BN_bn2dec(rsa_key->N),
               BN_bn2dec(rsa_key->d));
  fclose(secret_key_out);

  SecretRSAKey* certificate_authority_secret_key;

  if (keygen_options->certificate_authority_file) {
    FILE* certificate_authority_fin = fopen(
        keygen_options->certificate_authority_file, "r");
    certificate_authority_secret_key = read_file_SecretRSAKey(
        certificate_authority_fin);
    fclose(certificate_authority_fin);
  } else {
    FILE* certificate_authority_fin = fopen(keygen_options->secret_key_file,
        "r");
    certificate_authority_secret_key = read_file_SecretRSAKey(
        certificate_authority_fin);
    fclose(certificate_authority_fin);
  }

  ByteBuf* public_key_file_contents = read_file_contents(
      keygen_options->public_key_file);

  /* Sign hash of public key file with certificate authority secret key */
  BIGNUM* rsa_sig_bn = generate_rsa_sig((char *) public_key_file_contents->data,
      public_key_file_contents->len, certificate_authority_secret_key);

  /* get casig filename */
  char* casig_file = malloc(
      strlen(keygen_options->public_key_file) + strlen("-casig\0") + 1);
  strcpy(casig_file, keygen_options->public_key_file);
  strcat(casig_file, "-casig\0");

  /* Open and write casig to casig file */
  FILE* casig_fout = fopen(casig_file, "w");
  fprintf(casig_fout, "%s", BN_bn2dec(rsa_sig_bn));
  fclose(casig_fout);
  return 0;
}
