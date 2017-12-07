#include "file-locker.h"

int main(int argc, char** argv)
{
  CBCMacOptions* cbc_mac_options = parse_CBCMacOptions(argc, argv);
  print_CBCMacOptions(cbc_mac_options);

  return 0;
}
