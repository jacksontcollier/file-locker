#include "file-locker.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char* rsa_sig_arg_options = "k:m:s:";

RSASigOptions* new_RSASigOptions()
{
  RSASigOptions* rsa_sig_options = malloc(sizeof(RSASigOptions));

  rsa_sig_options->key_file = NULL;
  rsa_sig_options->message_file = NULL;
  rsa_sig_options->sig_file = NULL;

  return rsa_sig_options;
}

RSASigOptions* parse_RSASigOptions(int argc, char * const argv[])
{
  int option;
  RSASigOptions* rsa_sig_options = new_RSASigOptions();

  while ((option = getopt(argc, argv, rsa_sig_arg_options)) != -1) {
    switch(option) {
      case 'k':
        rsa_sig_options->key_file = optarg;
        break;
      case 'm':
        rsa_sig_options->message_file = optarg;
        break;
      case 's':
        rsa_sig_options->sig_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);

    }
  }

  return rsa_sig_options;
}

void print_RSASigOptions(const RSASigOptions* rsa_sig_options)
{
  printf("Key file: %s\n", rsa_sig_options->key_file);
  printf("Message file: %s\n", rsa_sig_options->message_file);
  printf("Signature file: %s\n", rsa_sig_options->sig_file);
}

const char* cbc_mac_arg_options = "k:m:t:";

CBCMacOptions* new_CBCMacOptions()
{
  CBCMacOptions* cbc_mac_options = malloc(sizeof(CBCMacOptions));

  cbc_mac_options->key_file = NULL;
  cbc_mac_options->message_file = NULL;
  cbc_mac_options->output_file = NULL;

  return cbc_mac_options;
}

CBCMacOptions* parse_CBCMacOptions(int argc, char * const argv[])
{
  int option;
  CBCMacOptions* cbc_mac_options = new_CBCMacOptions();

  while ((option = getopt(argc, argv, cbc_mac_arg_options)) != -1) {
    switch(option) {
      case 'k':
        cbc_mac_options->key_file = optarg;
        break;
      case 'm':
        cbc_mac_options->message_file = optarg;
        break;
      case 't':
        cbc_mac_options->output_file = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  return cbc_mac_options;
}

void print_CBCMacOptions(const CBCMacOptions* cbc_mac_options)
{
  printf("Key file: %s\n", cbc_mac_options->key_file);
  printf("Message file: %s\n", cbc_mac_options->message_file);
  printf("Output file: %s\n", cbc_mac_options->output_file);
}

const char* file_locker_arg_options = "d:p:r:vk:";

FileLockerOptions* new_FileLockerOptions()
{
  FileLockerOptions* file_locker_options = malloc(sizeof(FileLockerOptions));

  file_locker_options->directory = NULL;
  file_locker_options->action_public_key = NULL;
  file_locker_options->action_private_key = NULL;
  file_locker_options->validating_public_key = NULL;

  return file_locker_options;
}

FileLockerOptions* parse_FileLockerOptions(int argc, char * const argv[])
{
  int option;
  int should_read_validating_public_key = 0;
  FileLockerOptions* file_locker_options = new_FileLockerOptions();

  while ((option = getopt(argc, argv, file_locker_arg_options)) != -1) {
    switch(option) {
      case 'd':
        file_locker_options->directory = optarg;
        break;
      case 'p':
        file_locker_options->action_public_key = optarg;
        break;
      case 'r':
        file_locker_options->action_private_key = optarg;
        break;
      case 'v':
        should_read_validating_public_key = 1;
        break;
      case 'k':
        if (should_read_validating_public_key) {
          file_locker_options->validating_public_key = optarg;
        }
        break;
      default:
        fprintf(stderr, "Unknown command line option %c\n", option);
        exit(1);
    }
  }

  return file_locker_options;
}

void print_FileLockerOptions(const FileLockerOptions* file_locker_options)
{
  printf("Directory: %s\n", file_locker_options->directory);
  printf("Action Public Key: %s\n", file_locker_options->action_public_key);
  printf("Action Private Key: %s\n", file_locker_options->action_private_key);
  printf("Validating Public Key: %s\n",
      file_locker_options->validating_public_key);
}

