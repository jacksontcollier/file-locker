#include "file-locker.h"

int main(int argc, char** argv)
{
  CBCMacOptions* cbc_mac_options = parse_CBCMacOptions(argc, argv);

  if (cbc_mac_validate(cbc_mac_options)) {
    printf("True\n");
  } else {
    printf("False\n");
  }

  return 0;
}
