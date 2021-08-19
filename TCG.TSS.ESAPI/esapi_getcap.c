/*
Based on example from: https://tpm2-software.github.io/tpm2-tss/getting-started/2019/02/05/Getting-Started.html
    https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_getcap.c

Get capability

*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

/* convenience macro to convert flags into "1" / "0" strings */
#define prop_str(val) val ? "1" : "0"

/*
 * Iterate over an array of TPML_HANDLEs and dump out the handle
 * values.
 */
static void dump_handles(TPM2_HANDLE handles[], UINT32 count) {
    UINT32 i;

    for (i = 0; i < count; ++i)
        printf("- 0x%X\n", handles[i]);
}

/*
 * Print string representation of the TPMA_PERMANENT attributes.
 */
static void dump_permanent_attrs(TPMA_PERMANENT attrs) {
    printf("TPM2_PT_PERSISTENT:\n");
    printf("  ownerAuthSet:              %s\n",
            prop_str (attrs & TPMA_PERMANENT_OWNERAUTHSET));
    printf("  endorsementAuthSet:        %s\n",
            prop_str (attrs & TPMA_PERMANENT_ENDORSEMENTAUTHSET));
    printf("  lockoutAuthSet:            %s\n",
            prop_str (attrs & TPMA_PERMANENT_LOCKOUTAUTHSET));
    printf("  reserved1:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_RESERVED1_MASK));
    printf("  disableClear:              %s\n",
            prop_str (attrs & TPMA_PERMANENT_DISABLECLEAR));
    printf("  inLockout:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_INLOCKOUT));
    printf("  tpmGeneratedEPS:           %s\n",
            prop_str (attrs & TPMA_PERMANENT_TPMGENERATEDEPS));
    printf("  reserved2:                 %s\n",
            prop_str (attrs & TPMA_PERMANENT_RESERVED2_MASK));
}

/*
 * Print string representations of the TPMA_STARTUP_CLEAR attributes.
 */
static void dump_startup_clear_attrs(TPMA_STARTUP_CLEAR attrs) {
    printf("TPM2_PT_STARTUP_CLEAR:\n");
    printf("  phEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLE));
    printf("  shEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_SHENABLE));
    printf("  ehEnable:                  %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_EHENABLE));;
    printf("  phEnableNV:                %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_PHENABLENV));
    printf("  reserved1:                 %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_RESERVED1_MASK));
    printf("  orderly:                   %s\n",
            prop_str (attrs & TPMA_STARTUP_CLEAR_ORDERLY));
}

/*
 * Iterate over all variable properties, call the unique print function for each.
 */
static void dump_tpm_properties_var(TPMS_TAGGED_PROPERTY properties[],
        size_t count) {
    size_t i;

    for (i = 0; i < count; ++i) {
        TPM2_PT property = properties[i].property;
        UINT32 value = properties[i].value;
        switch (property) {
        case TPM2_PT_PERMANENT:
            dump_permanent_attrs((TPMA_PERMANENT) value);
            break;
        case TPM2_PT_STARTUP_CLEAR:
            dump_startup_clear_attrs((TPMA_STARTUP_CLEAR) value);
            break;
        case TPM2_PT_HR_NV_INDEX:
            printf("TPM2_PT_HR_NV_INDEX: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED:
            printf("TPM2_PT_HR_LOADED: 0x%X\n", value);
            break;
        case TPM2_PT_HR_LOADED_AVAIL:
            printf("TPM2_PT_HR_LOADED_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE:
            printf("TPM2_PT_HR_ACTIVE: 0x%X\n", value);
            break;
        case TPM2_PT_HR_ACTIVE_AVAIL:
            printf("TPM2_PT_HR_ACTIVE_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_TRANSIENT_AVAIL:
            printf("TPM2_PT_HR_TRANSIENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_HR_PERSISTENT:
            printf("TPM2_PT_HR_PERSISTENT: 0x%X\n", value);
            break;
        case TPM2_PT_HR_PERSISTENT_AVAIL:
            printf("TPM2_PT_HR_PERSISTENT_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS:
            printf("TPM2_PT_NV_COUNTERS: 0x%X\n", value);
            break;
        case TPM2_PT_NV_COUNTERS_AVAIL:
            printf("TPM2_PT_NV_COUNTERS_AVAIL: 0x%X\n", value);
            break;
        case TPM2_PT_ALGORITHM_SET:
            printf("TPM2_PT_ALGORITHM_SET: 0x%X\n", value);
            break;
        case TPM2_PT_LOADED_CURVES:
            printf("TPM2_PT_LOADED_CURVES: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_COUNTER:
            printf("TPM2_PT_LOCKOUT_COUNTER: 0x%X\n", value);
            break;
        case TPM2_PT_MAX_AUTH_FAIL:
            printf("TPM2_PT_MAX_AUTH_FAIL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_INTERVAL:
            printf("TPM2_PT_LOCKOUT_INTERVAL: 0x%X\n", value);
            break;
        case TPM2_PT_LOCKOUT_RECOVERY:
            printf("TPM2_PT_LOCKOUT_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_NV_WRITE_RECOVERY:
            printf("TPM2_PT_NV_WRITE_RECOVERY: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_0:
            printf("TPM2_PT_AUDIT_COUNTER_0: 0x%X\n", value);
            break;
        case TPM2_PT_AUDIT_COUNTER_1:
            printf("TPM2_PT_AUDIT_COUNTER_1: 0x%X\n", value);
            break;
        default:
            printf("unknown%X: 0x%X\n", value, value);
            break;
        }
    }
}

static bool dump_tpm_capability(TPM2_CAP capability, UINT32 property, TPMU_CAPABILITIES *capabilities) {

    bool result = true;
    switch (capability) {
    // case TPM2_CAP_ALGS:
    //     dump_algorithms(capabilities->algorithms.algProperties,
    //             capabilities->algorithms.count);
    //     break;
    // case TPM2_CAP_COMMANDS:
    //     result = dump_command_attr_array(
    //             capabilities->command.commandAttributes,
    //             capabilities->command.count);
    //     break;
    case TPM2_CAP_TPM_PROPERTIES:
        switch (property) {
        // case TPM2_PT_FIXED:
        //     dump_tpm_properties_fixed(capabilities->tpmProperties.tpmProperty,
        //             capabilities->tpmProperties.count);
        //     break;
        case TPM2_PT_VAR:
            dump_tpm_properties_var(capabilities->tpmProperties.tpmProperty,
                    capabilities->tpmProperties.count);
            break;
        default:
            return false;
        }
        break;
    // case TPM2_CAP_ECC_CURVES:
    //     dump_ecc_curves(capabilities->eccCurves.eccCurves,
    //             capabilities->eccCurves.count);
    //     break;
    case TPM2_CAP_HANDLES:
        switch (property & TPM2_HR_RANGE_MASK) {
        case TPM2_HR_TRANSIENT:
        case TPM2_HR_PERSISTENT:
        case TPM2_HR_PERMANENT:
        case TPM2_HR_PCR:
        case TPM2_HR_NV_INDEX:
        case TPM2_HT_LOADED_SESSION << TPM2_HR_SHIFT:
        case TPM2_HT_SAVED_SESSION << TPM2_HR_SHIFT:
            dump_handles(capabilities->handles.handle,
                    capabilities->handles.count);
            break;
        default:
            return false;
        }
        break;
    // case TPM2_CAP_PCRS:
    //     pcr_print_pcr_selections(&capabilities->assignedPCR);
    //     break;
    default:
        return false;
    }
    return result;
}

int main(int argc, char *argv[]) {

    TSS2_RC r;

    if (argc < 3) {
        printf("Usage: esapi_getcap capability tcti (e.g.: esapi_getcap handles-persistent mssim)\n   Notes: Supported capabilities: (handles-persistent, properties-variable)\n");
        return 1;
    }

    // int rand_size;
    // sscanf (argv[1],"%d",&rand_size);

    /* Prepare TCTI context */
    const char *tcti_name = argv[2];
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_RC rc = Tss2_TctiLdr_Initialize (tcti_name, &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("\nError: Tss2_TctiLdr_Initialize, response code: 0x%" PRIx32 "\n", rc);                
        exit (1);
    }

    /* Initialize the ESAPI context */
    ESYS_CONTEXT *ctx;
    r = Esys_Initialize(&ctx, tcti_ctx, NULL);

        if (r != TSS2_RC_SUCCESS){
        printf("\nError: Esys_Initializen\n");
        exit(1);
    }

    /* Get cap data */
    TPM2_CAP                       capability;
    UINT32                         property;
    UINT32                         propertyCount;
    TPMS_CAPABILITY_DATA           *capabilityData;
    TPMI_YES_NO                    moreData;

    if (strcmp(argv[1], "handles-persistent") == 0) {
        capability = TPM2_CAP_HANDLES;
        property = TPM2_PERSISTENT_FIRST;
        propertyCount = TPM2_MAX_CAP_HANDLES;
    } else if (strcmp(argv[1], "properties-variable") == 0) {
        capability = TPM2_CAP_TPM_PROPERTIES;
        property = TPM2_PT_VAR;
        propertyCount = TPM2_MAX_TPM_PROPERTIES;
    } else {
		fprintf(stderr, "Error: Unsupported capability\n");
        exit(1);        
    }

    r = Esys_GetCapability(ctx,
                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           capability, property, propertyCount,
                           &moreData, &capabilityData);

    if (r != TSS2_RC_SUCCESS){
		fprintf(stderr, "Error: Esys_GetCapability: 0x%x\n", r);
        exit(1);
    }

    bool result = dump_tpm_capability(capability, property, &capabilityData->data);

    // printf("\n");
    // for (int i = 0; i < random_bytes->size; i++) {
    //     printf("0x%x ", random_bytes->buffer[i]);
    // }
    // printf("\n");
    exit(0);
}

