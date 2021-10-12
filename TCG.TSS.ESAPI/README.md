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

See below windows examples. Just replace tcti from `tbs` to 
- device (HW TPM) or
- tabrmd (resource manager) or
- mssim (microsoft tpm simulator) or
- swtpm (tpm simulator)

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

## Additional sample code running in Linux
- Notes: openssl and [tpm-tools](https://github.com/tpm2-software/tpm2-tools) are also needed to complete the test steps below:

```
$mkdir testimport2
$cd testimport2

# Import an openssl RSA key
$openssl genrsa -out platformprivate.pem 2048
$cd ..

$./target/esapi_import_persist_openssl_key p NULL 0x81810018 newkeyauth ./testimport2/platformprivate.pem mssim

$./target/esapi_getcap handles-persistent mssim
- 0x81810018

# Read the public key of the imported RSA key
$./target/esapi_readpublic_persistent_key 0x81810018 pem ./testimport2/newexportedpubkey.pem mssim

$ ls testimport2/
newexportedpubkey.pem  platformprivate.pem

# Test sign data
$ echo "testmessage for esapi" > testimport2/secrets.txt

$./target/esapi_sign_persistent_key p 0x81810018 newkeyauth sha256 ./testimport2/secrets.txt ./testimport2/sig.rssa.plain plain mssim

$openssl dgst -keyform pem -verify ./testimport2/newexportedpubkey.pem -sha256 -signature ./testimport2/sig.rssa.plain ./testimport2/secrets.txt
Verified OK

# Test encrypt and decrypt data
$openssl rsautl -encrypt -inkey ./testimport2/newexportedpubkey.pem -pubin -in ./testimport2/secrets.txt -out ./testimport2/secrets.txt.enc 

$./target/esapi_rsadecrypt_persistent_key 0x81810018 newkeyauth ./testimport2/secrets.txt.enc ./testimport2/secrets.txt.ptext mssim
persist_handle: 0x81810018
Decrypted message size:22

# store the encrypted secrets (secrets.txt.enc) in NV storage (size: 256)

$tpm2_nvdefine -C p -s 256 -a "ppread|ppwrite|authread|authwrite|platformcreate|write_stclear|read_stclear" 11 -p dataauth -T mssim
nv-index: 0x100000b

$tpm2_nvwrite 0x100000b -C p -i ./testimport2/secrets.txt.enc -T mssim

$tpm2_getcap handles-nv-index -T mssim
- 0x100000B

$./target/esapi_nvread_persistent 0x100000B dataauth ./testimport2/newsecrets.txt.enc mssim
persist_handle: 0x100000b
datasize = 256

$./target/esapi_rsadecrypt_persistent_key 0x81810018 newkeyauth ./testimport2/newsecrets.txt.enc ./testimport2/newsecrets.txt.ptext mssim
persist_handle: 0x81810018
Decrypted message size:22
```

# Developing in a docker container

A docker container image is also provided for fast prototyping, with all environments set up already in a Ubuntu 18.04 LTS image.

Container link in docker hub: https://hub.docker.com/repository/docker/choraleprelude/ubuntu-tpm-dev-env

## Running the docker container

sudo docker run -u root --rm -it choraleprelude/ubuntu-tpm-dev-env

## Start TPM2.0 simulator

cd /tpm/ibmtpm/src

./tpm_server

## Initiate/Verify TPM commands in another shell

From host machine, open another shell and key:
- sudo docker exec -ti -u root CONTAINER_ID bash
- tpm2_startup -c -T mssim
- tpm2_getrandom 6 -T mssim |xxd

### Start developing with TCG TSS ESAPI in this shell!

```
git clone git@github.com:choraleprelude/tpm-api-examples.git

cd tpm-api-examples/TCG.TSS.ESAPI

# Build the example code
mkdir target
make

# Run the example code and start developing!
./target/esapi_getrandom 12 mssim

```
