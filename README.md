# tpm-api-examples
Examples of how to use TPM APIs for basic use cases
- Get random numbers
- Set TCTI - device, tbs (windows resource manager), TPM simulator
- Pass hierarchy and hierarchy auth during tpm access - owner, platform
- Set key auth
- Persist keys into TPM
- Delete persistent key from TPM
- Get TPM capability
- Decrypt data with persistent key
- Sign data with persistent key
- Read public key from a persistent ky in TPM
- Read NV data
- Import an openssl RSA key into TPM and persist it
- Decode TPM return code message with Tss2_RC_Decode()
- Flush context

## Notes
These are sample code to demonstrate how to use TPM APIs. Some parameters are hard-coded to make the code simpler, e.g., using RSA keys only. Additional improvements may also be needed to make the code more robust, e.g.: add proper error handling to flush context, etc.
