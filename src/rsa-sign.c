#include "file-locker.h"

int main(int argc, char** argv)
{
  RSASigOptions* rsa_sig_options = parse_RSASigOptions(argc, argv);
  rsa_sign(rsa_sig_options);

  return 0;
}
