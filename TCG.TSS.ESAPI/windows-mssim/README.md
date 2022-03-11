## Why are we here
  - If for some reasons, the mssim TCTI could not be loaded in windows, you can follow the source code in this page to explicitly initiate the mssim TCTI.
  - Reference: https://www.mankier.com/3/Tss2_Tcti_Mssim_Init

## Run Microsoft TPM simulator
Download from: https://www.microsoft.com/en-us/download/details.aspx?id=52507

## Build
nmake -f makefile.nmake

## Run

```
$esapi_startup_getrandom_mssim 10 127.0.0.1 2321

0xb3 0xa0 0x23 0xee 0x64 0x10 0x94 0xcf 0x81 0xaa
```     
