#include "file-locker.h"

int main(int argc, char** argv)
{
  RSASigOptions* rsa_sig_options = parse_RSASigOptions(argc, argv);

  if (rsa_validate(rsa_sig_options)) {
    printf("True\n");
  } else {
    printf("False\n");
  }

  return 0;
}
