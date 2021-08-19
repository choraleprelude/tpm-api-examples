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

## if windows
nmake /f makefile.nmake

Notes: Run as administrator in Windows if calling the create key API's
