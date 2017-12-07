#ifndef FILELOCKER_H
#define FILELOCKER_H

typedef struct rsa_sig_options
{
  char* key_file;
  char* message_file;
  char* sig_file;
} RSASigOptions;

RSASigOptions* new_RSASigOptions();

RSASigOptions* parse_RSASigOptions(int argc, char * const argv[]);

void print_RSASigOptions(const RSASigOptions* rsa_sig_options);

typedef struct cbc_mac_options
{
  char* key_file;
  char* message_file;
  char* output_file;
} CBCMacOptions;

CBCMacOptions* new_CBCMacOptions();

CBCMacOptions* parse_CBCMacOptions(int argc, char * const argv[]);

void print_CBCMacOptions(const CBCMacOptions* cbc_mac_options);

typedef struct file_locker_options
{
  char* directory;
  char* action_public_key;
  char* action_private_key;
  char* validating_public_key;
} FileLockerOptions;

FileLockerOptions* new_FileLockerOptions();

FileLockerOptions* parse_FileLockerOptions(int argc, char * const argv[]);

void print_FileLockerOptions(const FileLockerOptions* file_locker_options);
#endif
