/*
Based on examples from:

https://gist.github.com/williamcroberts/66a7dab3adfb973fbae3219954535009
https://github.com/tpm2-software/tpm2-tools/blob/master/lib/tpm2_util.c

*/

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

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

void create_primary(ESYS_CONTEXT *ectx, ESYS_TR *parent, char *hierarchy) {

    TPM2B_PUBLIC pub_templ = {
		.publicArea = {
			.type = TPM2_ALG_RSA,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
								 TPMA_OBJECT_RESTRICTED |
								 TPMA_OBJECT_DECRYPT |
								 TPMA_OBJECT_FIXEDTPM |
								 TPMA_OBJECT_FIXEDPARENT |
								 TPMA_OBJECT_SENSITIVEDATAORIGIN),
			.authPolicy = {
				 .size = 0,
			 },
			.parameters.rsaDetail = {
				 .symmetric = {
					 .algorithm = TPM2_ALG_AES,
					 .keyBits.aes = 128,
					 .mode.aes = TPM2_ALG_CFB},
				 .scheme = {
					  .scheme = TPM2_ALG_NULL
				  },
				 .keyBits = 2048,
				 .exponent = 0,
			 },
			.unique.rsa = {
				 .size = 0,
				 .buffer = {},
			 },
		},
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };


    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    // Configure hierarchy input
    ESYS_TR hierarchy_choice;

    if (strcmp(hierarchy, "o") == 0) {
        hierarchy_choice = ESYS_TR_RH_OWNER;
    } else if (strcmp(hierarchy, "p") == 0) {
        hierarchy_choice = ESYS_TR_RH_PLATFORM;
    } else {
		fprintf(stderr, "Wrong hierarchy parameter: %s\n", hierarchy);
		exit(1);
    }

    TSS2_RC rv = Esys_CreatePrimary(ectx, hierarchy_choice, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &pub_templ,
                           &outsideInfo, &creationPCR, parent,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "t1: Esys_CreatePrimary: 0x%x\n", rv);
		exit(1);
	}
}

// Referencing integration test code re: template for RSA keys:
//    https://github.com/tpm2-software/tpm2-tss/blob/master/test/integration/esys-save-and-load-context.int.c

void create_and_load_rsa_key(ESYS_CONTEXT *ectx, ESYS_TR parent, ESYS_TR *aes_key, char *hierarchy, char *key_handle, char *key_auth) {

	printf("keyhandle:%s, keyauth:%s\n", key_handle, key_auth);

    TPM2B_PUBLIC pub_templ = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN),

            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
					.algorithm = TPM2_ALG_NULL,
					.keyBits.aes = 0,
					.mode.aes = 0,
                 },
                 .scheme = {
                      .scheme =
                      TPM2_ALG_NULL,
                  },
                 .keyBits = 2048,
                 .exponent = 0
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {}
                 ,
             }
        }
	};

    TPM2B_DATA outsideInfo = {
        .size = 0,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
				/* TODO: Set this to a non-hard coded password, or better yet use a policy */
                 .size = 8,
                 .buffer = {key_auth[0], key_auth[1], key_auth[2], key_auth[3] 
                   , key_auth[4], key_auth[5], key_auth[6], key_auth[7]}
//                 .buffer = *key_auth_param
//                 .buffer = "password"
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TSS2_RC rv = Esys_Create(
		ectx,
		parent,
    	ESYS_TR_PASSWORD,
		ESYS_TR_NONE,
		ESYS_TR_NONE,
		&inSensitive,
		&pub_templ,
		&outsideInfo,
		&creationPCR,
		&outPrivate,
		&outPublic,
		&creationData,
		&creationHash,
		&creationTicket);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Create: 0x%x\n", rv);
		exit(1);
	}

	/* if you want this key again, save the TPM2B_PUBLIC and TPM2B_PRIVATE for
	 * future use. You just need to call load again.
	 */
	rv = Esys_Load(ectx,
			parent,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			outPrivate,
			outPublic,
			aes_key);
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Load: 0x%x\n", rv);
		exit(1);
	}

	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(key_handle, &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}

    // Configure hierarchy input
    ESYS_TR hierarchy_choice;

    if (strcmp(hierarchy, "o") == 0) {
        hierarchy_choice = ESYS_TR_RH_OWNER;
    } else if (strcmp(hierarchy, "p") == 0) {
        hierarchy_choice = ESYS_TR_RH_PLATFORM;
    } else {
		fprintf(stderr, "Wrong hierarchy parameter: %s\n", hierarchy);
		exit(1);
    }

	ESYS_TR out_tr;
    rv = Esys_EvictControl (ectx,
            hierarchy_choice,
            *aes_key,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,    
			persist_handle,
			&out_tr);
    if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_EvictControl: 0x%x\n", rv);
		exit(1);
	}
}

int main(int argc, char *argv[]) {

    if (argc < 5) {
        printf("Usage: esapi_create_persist_key hierarchy keyHandle keyauth tcti (e.g.: esapi_create_persist_key o 0x81000005 password mssim)\n  Note: (please set keyauth length = 8) \n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[4];
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize (tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("\nError: Tss2_TctiLdr_Initialize, response code: 0x%" PRIx32 "\n", rc);                
        exit (1);
    }

	printf("main: initializing esys\n");

	ESYS_CONTEXT *ectx = NULL;

	TSS2_RC rv = Esys_Initialize(&ectx,
			tcti_ctx, /* pass in TCTI */
			NULL);/* Use whatever ABI */
	if (rv != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: 0x%x\n", rv);
		return 1;
	}

	ESYS_TR parent = ESYS_TR_NONE;
	create_primary(ectx, &parent, argv[1]);

	ESYS_TR aes_key = ESYS_TR_NONE;
	create_and_load_rsa_key(ectx, parent, &aes_key, argv[1], argv[2], argv[3]);

	Esys_Finalize(&ectx);

	return 0;
}

