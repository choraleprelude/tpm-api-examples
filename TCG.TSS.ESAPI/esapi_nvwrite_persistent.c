/*
Based on example from: 
    hhttps://github.com/tpm2-software/tpm2-tss/blob/master/test/integration/esys-nv-certify.int.c
     and referencing esapi_nvread_persistent_key.c, esapi_import_persist_openssl_key.c

*/

#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

/* do not port to TSS below here */
typedef enum tool_rc tool_rc;
enum tool_rc {
    /* do not reorder or change, part of returned codes to exit */
    /* maps to common/returns.md */
    tool_rc_success = 0,
    tool_rc_general_error,
    tool_rc_option_error,
    tool_rc_auth_error,
    tool_rc_tcti_error,
    tool_rc_unsupported
};

int main(int argc, char *argv[]) {

    TSS2_RC rv;

    if (argc < 8) {
        printf("Usage: esapi_nvwrite_persistent hierarchy hierarchyauth NVindex NVauth input_path NVsize tcti (e.g.: esapi_nvwrite_persistent o ownerauth 10 nvauthpassword inputfile.txt 256 mssim)\n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[7];
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

    // set hierarchy auth
    TPM2B_AUTH h_authValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[2], "NULL") != 0) {
        char *h_auth = argv[2];

        h_authValue.size = strlen(h_auth);
        for (int i = 0; i < h_authValue.size; i++) {
            h_authValue.buffer[i] = h_auth[i];
        }
    }

    // Configure hierarchy input
    ESYS_TR hierarchy_choice;

    if (strcmp(argv[1], "o") == 0) {
        hierarchy_choice = ESYS_TR_RH_OWNER;            
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_OWNER, &h_authValue);
    } else if (strcmp(argv[1], "p") == 0) {
        hierarchy_choice = ESYS_TR_RH_PLATFORM;
        rv = Esys_TR_SetAuth(ectx, ESYS_TR_RH_PLATFORM, &h_authValue);
    } else {
		fprintf(stderr, "Wrong hierarchy parameter (main): %s\n", argv[1]);
		exit(1);
    }

    if (rv != TSS2_RC_SUCCESS) {
        printf("TR_SetAuth error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

    // set NV auth
    TPM2B_AUTH h_NVAuthValue = {
        .size = 0,
        .buffer = {0}
    };    

    if (strcmp(argv[4], "NULL") != 0) {
        char *h_nvauth = argv[4];

        h_NVAuthValue.size = strlen(h_nvauth);
        for (int i = 0; i < h_NVAuthValue.size; i++) {
            h_NVAuthValue.buffer[i] = h_nvauth[i];
        }
    }

    // Prepare NV index attribute info
    int nvsize = atoi(argv[6]);
    int nvindex = atoi(argv[3]);

    TPMA_NV ownerAttributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_OWNERREAD |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_AUTHREAD
                );

    TPMA_NV platformAttributes = (
                TPMA_NV_PPWRITE |
                TPMA_NV_PPREAD |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_AUTHREAD |
                TPMA_NV_PLATFORMCREATE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR
                );

    TPMA_NV nvAttributes;

    if (strcmp(argv[1], "o") == 0) {
        nvAttributes = ownerAttributes;            
    } else if (strcmp(argv[1], "p") == 0) {
        nvAttributes = platformAttributes;
    }    

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST + nvindex,
            .nameAlg = TPM2_ALG_SHA256,
            .attributes = nvAttributes,
            .authPolicy = {
                 .size = 0,
                 .buffer = {}
             },
            .dataSize = nvsize,
        }
    };

    // Define NV index
    ESYS_TR nvHandle = ESYS_TR_NONE;
    rv = Esys_NV_DefineSpace(ectx,
                            hierarchy_choice,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &h_NVAuthValue,
                            &publicInfo,
                            &nvHandle);

    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_NV_DefineSpace error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		return 1;
	}

    exit(0);
}
