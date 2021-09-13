/*
Based on example from: 
    https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_readpublic.c
     and referencing esapi_delete_persistent_key.c 

Read public key from persistent key handle 
1. First get persistent handle with Esys_TR_FromTPMPublic
2. Call Esys_ReadPublic to read public key from persistent handle 
3. Output public key

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    unsigned long int tmp = strtoul(str, &endptr, 0);
    if (errno || tmp > UINT32_MAX) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = (uint32_t) tmp;
    return true;
}

typedef enum tpm2_convert_pubkey_fmt tpm2_convert_pubkey_fmt;
enum tpm2_convert_pubkey_fmt {
    pubkey_format_tss,
    pubkey_format_pem,
    pubkey_format_der,
    pubkey_format_tpmt,
    pubkey_format_err
};

#if OPENSSL_API_COMPAT < 0x10100000L
# define ERR_load_crypto_strings() \
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)
# define ERR_free_strings() while(0) continue
#endif

bool tpm2_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) { \
    \
        UINT##size converted; \
        UINT8 *bytes = (UINT8 *)&data; \
        UINT8 *tmp = (UINT8 *)&converted; \
    \
        size_t i; \
        for(i=0; i < sizeof(UINT##size); i ++) { \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1]; \
        } \
        \
        return converted; \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)
STRING_BYTES_ENDIAN_CONVERT(64)

UINT16 tpm2_util_endian_swap_16(UINT16 data);
UINT32 tpm2_util_endian_swap_32(UINT32 data);
UINT64 tpm2_util_endian_swap_64(UINT64 data);

#define STRING_BYTES_ENDIAN_HTON(size) \
    UINT##size tpm2_util_hton_##size(UINT##size data) { \
    \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        if (is_big_endian) { \
           return data; \
        } \
    \
        return tpm2_util_endian_swap_##size(data); \
    }

STRING_BYTES_ENDIAN_HTON(16)
STRING_BYTES_ENDIAN_HTON(32)
STRING_BYTES_ENDIAN_HTON(64)

UINT16 tpm2_util_hton_16(UINT16 data);
UINT32 tpm2_util_hton_32(UINT32 data);
UINT64 tpm2_util_hton_64(UINT64 data);

static bool convert_pubkey_RSA(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, BIO *bio) {

    bool ret = false;
    RSA *ssl_rsa_key = NULL;
    BIGNUM *e = NULL, *n = NULL;

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    // OpenSSL expects this in network byte order
    exponent = tpm2_util_hton_32(exponent);
    ssl_rsa_key = RSA_new();
    if (!ssl_rsa_key) {
        printf("Failed to allocate OpenSSL RSA structure\n");
        goto error;
    }

    e = BN_bin2bn((void*) &exponent, sizeof(exponent), NULL);
    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size,
    NULL);

    if (!n || !e) {
        printf("Failed to convert data to SSL internal format\n");
        goto error;
    }

    if (!RSA_set0_key(ssl_rsa_key, n, e, NULL)) {
        printf("Failed to set RSA modulus and exponent components\n");
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    int ssl_res = 0;

    switch (format) {
    case pubkey_format_pem:
        ssl_res = PEM_write_bio_RSA_PUBKEY(bio, ssl_rsa_key);
        break;
    // case pubkey_format_der:
    //     ssl_res = i2d_RSA_PUBKEY_bio(bio, ssl_rsa_key);
    //     break;
    default:
        printf("Invalid OpenSSL target format %d encountered \n", format);
        goto error;
    }

    if (ssl_res <= 0) {
        printf("OpenSSL public key conversion failed\n");
        goto error;
    }

    ret = true;

    error: if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }
    if (ssl_rsa_key) {
        RSA_free(ssl_rsa_key);
    }

    return ret;
}

static bool tpm2_convert_pubkey_bio(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, BIO *bio) {

    bool result = false;

    switch (public->type) {
    case TPM2_ALG_RSA:
        result = convert_pubkey_RSA(public, format, bio);
        break;
    // case TPM2_ALG_ECC:
    //     result = convert_pubkey_ECC(public, format, bio);
    //     break;
    default:
        printf("Unsupported key type for requested output format. Only RSA is supported.\n");
    }

    ERR_free_strings();
    return result;
}

static bool tpm2_convert_pubkey_ssl(TPMT_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path) {

    BIO *bio = path ? BIO_new_file(path, "wb") : BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio) {
        printf("Failed to open public key output file: %s\n", path);
        return false;
    }

    bool result = tpm2_convert_pubkey_bio(public, format, bio);
    BIO_free(bio);
    return result;
}

bool tpm2_convert_pubkey_save(TPM2B_PUBLIC *public,
        tpm2_convert_pubkey_fmt format, const char *path) {

    if (format == pubkey_format_pem) {
        return tpm2_convert_pubkey_ssl(&public->publicArea, format, path);
    // } else if (format == pubkey_format_tss) {
    //     return files_save_public(public, path);
    // } else if (format == pubkey_format_tpmt) {
    //     return files_save_template(&public->publicArea, path);
    }

    printf("Unsupported public key output format.\n");
    return false;
}

int main(int argc, char *argv[]) {

    TSS2_RC rv;

    if (argc < 5) {
        printf("Usage: esapi_readpublic_persistent_key keyHandle format output_path tcti (e.g.: esapi_readpublic_persistent_key 0x81000005 pem outputkey.pem mssim)\n");
        return 1;
    }

    // int rand_size;
    // sscanf (argv[1],"%d",&rand_size);

    /* Prepare TCTI context */
    const char *tcti_name = argv[4];
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize (tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("\nError: Tss2_TctiLdr_Initialize, response code: 0x%" PRIx32 "\n", rc);                
        exit (1);
    }

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ectx;
    rv = Esys_Initialize(&ectx, tcti_ctx, NULL);

    if (rv != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initializen\n");
        exit(1);
    }

    // prepare persistent handle
	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[1], &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}

    // prepare key handle
    ESYS_TR keyHandle = ESYS_TR_NONE;    

    rv = Esys_TR_FromTPMPublic(ectx, persist_handle,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &keyHandle);    
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_TR_FromTPMPublic error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

    // read public key
    TPM2B_PUBLIC *public;
    TPM2B_NAME *name;
    TPM2B_NAME *qualified_name;

    rv = Esys_ReadPublic(ectx, keyHandle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            &public, &name, &qualified_name);
    if (rv != TPM2_RC_SUCCESS) {
		fprintf(stderr, "Esys_ReadPublic error: 0x%x\n", rv);        
        return 1;
    }    

    char *output_path = argv[3];
    tpm2_convert_pubkey_fmt format;    

    if (strcmp(argv[2], "pem") == 0) {
        format = pubkey_format_pem;
    } else {
		fprintf(stderr, "Unsupported key format error: %s\n", argv[2]);        
        return 1;        
    }

    // output public key
    bool ret = tpm2_convert_pubkey_save(public, format, output_path);
    if (!ret) {
		fprintf(stderr, "Save key error\n");        
        return 1;   
    }    

    exit(0);
}

