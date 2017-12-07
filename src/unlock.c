#include "file-locker.h"

int main(int argc, char** argv)
{
  FileLockerOptions* file_locker_options = parse_FileLockerOptions(argc, argv);
  print_FileLockerOptions(file_locker_options);

  return 0;
}
