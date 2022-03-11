/*
Based on examples from: 
    https://tpm2-software.github.io/tpm2-tss/getting-started/2019/02/05/Getting-Started.html
    https://www.mankier.com/3/Tss2_Tcti_Mssim_Init

*/

#include <stdlib.h>
#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tcti_mssim.h>

int main(int argc, char *argv[]) {

    TSS2_RC r;

    if (argc < 4) {
        printf("Usage: esapi_startup_getrandom_mssim size IP port (e.g.: esapi_startup_getrandom_mssim 8 127.0.0.1 2321)\n");
        return 1;
    }

    int rand_size;
    sscanf (argv[1],"%d",&rand_size);

    /* Prepare TCTI context */
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    size_t size;
    char conf[100];
    sprintf (conf, "host=%s,port=%s", argv[2], argv[3]);

    r = Tss2_Tcti_Mssim_Init (NULL, &size, NULL);
    if (r != TSS2_RC_SUCCESS) {
        printf ("\nFailed to get allocation size for mssim TCTI context: 0x%" PRIx32 "\n", r);
        exit (EXIT_FAILURE);
    }
    tcti_ctx = calloc (1, size);
    if (tcti_ctx == NULL) {
        printf ("\nAllocation for TCTI context failed\n");
        exit (EXIT_FAILURE);
    }
    r = Tss2_Tcti_Mssim_Init (tcti_ctx, &size, conf);
    if (r != TSS2_RC_SUCCESS) {
        printf ("\nFailed to initialize mssim TCTI context: 0x%" PRIx32 "\n", r);
        free (tcti_ctx);
        exit (EXIT_FAILURE);
    }

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    r = Esys_Initialize(&ctx, tcti_ctx, NULL);

        if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initializen\n");
        exit(1);
    }

    /* Startup TPM */
    r = Esys_Startup(ctx, TPM2_SU_CLEAR);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Startup\n");
        exit(1);
    }

    /* Get random data */
    TPM2B_DIGEST *random_bytes;
    r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, rand_size,
                       &random_bytes);

    if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_GetRandom\n");
        exit(1);
    }

    printf("\n");
    for (int i = 0; i < random_bytes->size; i++) {
        printf("0x%x ", random_bytes->buffer[i]);
    }
    printf("\n");
    exit(0);
}

