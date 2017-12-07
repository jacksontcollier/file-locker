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
        file_locker_options->validating_public_key = optarg;
        break;
      default:
        fprintf(stderr, "Unknown command line option\n");
        exit(1);
    }
  }

  return file_locker_options;
}

