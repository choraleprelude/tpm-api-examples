# Build instructions

## Prerequisites

- All appropriate compiler toolchains: gcc in linux, cl in Windows
- TPM2-TSS needs to be installed and library/include paths known:
    https://github.com/tpm2-software/tpm2-tss
  - Then update the library and include paths of the makefiles used for Linux/Windows  
- mkdir target

## if linux
make

## if windows
nmake /f makefile.nmake
