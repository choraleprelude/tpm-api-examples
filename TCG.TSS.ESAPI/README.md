# Build instructions

## Prerequisites

- All appropriate compiler toolchains: gcc in linux, cl in Windows
- TPM2-TSS needs to be installed and library/include paths known:
    https://github.com/tpm2-software/tpm2-tss
  - Then update the library and include paths of the makefiles used for Linux/Windows  
- Create target directory from current directory for binary outputs
  - mkdir target

## if linux
make

### Running in linux

See below windows examples. Just replace tcti from tbs to device (or mssim/swtpm for tpm simulator) 

## if windows
nmake /f makefile.nmake

Notes: Run as administrator in Windows if calling the create key API's

### Running in windows

```
$esapi_getrandom 12 tbs
0x66 0xf9 0x6c 0x64 0xa3 0x70 0x86 0xd2 0xa1 0x26 0x6b 0x2b

$esapi_create_persist_key p NULL 0x81810015 password tbs
main: initializing esys
keyhandle:0x81810015, keyauth:password
persist_handle: 0x81810015

$esapi_getcap handles-persistent tbs
- 0x81810015
- 0x81810022

$esapi_delete_persistent_key p NULL 0x81810015 tbs
persist_handle: 0x81810015

$esapi_getcap handles-persistent tbs
- 0x81810022
```
