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

  return 0;
}
