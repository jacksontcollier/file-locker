#include "file-locker.h"

int main(int argc, char** argv)
{
  FileLockerOptions* file_locker_options = parse_FileLockerOptions(argc, argv);

  if (!verify_action_public_key(file_locker_options->action_public_key,
      file_locker_options->validating_public_key)) {
    printf("Unlocker's public key failed validation. Burn it down\n");
    exit(1);
  }

  return 0;
}
