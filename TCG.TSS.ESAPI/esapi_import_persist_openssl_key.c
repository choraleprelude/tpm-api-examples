/*
Based on examples from:

esapi_create_persist_key.c , 
https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_import.c

1. Create primary key
2. Import an external RSA private key with primary key as parent
    - Key was created with: openssl genrsa -out platformprivate.pem 2048
3. Persist the imported child key with evictcontrol

*/

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>

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
				 .buffer = {0}
			 }
		}
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {0}
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

#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

tool_rc tpm2_readpublic(ESYS_CONTEXT *esys_context, ESYS_TR object_handle,
        TPM2B_PUBLIC **out_public, TPM2B_NAME **name,
        TPM2B_NAME **qualified_name) {

    TSS2_RC rval = Esys_ReadPublic(esys_context, object_handle,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            out_public, name, qualified_name);
    if (rval != TPM2_RC_SUCCESS) {
        printf("Esys_ReadPublic error: (0x%X) - %s\n", rval, Tss2_RC_Decode(rval));
		return 1;        
    }

    return tool_rc_success;
}

static tool_rc readpublic(ESYS_CONTEXT *ectx, ESYS_TR handle,
        TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, handle, public, NULL, NULL);
}

#define DEFAULT_CREATE_ATTRS \
     TPMA_OBJECT_DECRYPT|TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_FIXEDTPM \
    |TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN \
    |TPMA_OBJECT_USERWITHAUTH

static void setup_default_attrs(TPMA_OBJECT *attrs, bool has_policy, bool has_auth, char *object_alg) {

    /* Handle Default Setup */
    *attrs = DEFAULT_CREATE_ATTRS;

    /* imported objects arn't created inside of the TPM so this gets turned down */
    *attrs &= ~TPMA_OBJECT_SENSITIVEDATAORIGIN;
    *attrs &= ~TPMA_OBJECT_FIXEDTPM;
    *attrs &= ~TPMA_OBJECT_FIXEDPARENT;

    /* The default for a keyedhash object with no scheme is just for sealing */
    if (!strcmp("keyedhash", object_alg)) {
        *attrs &= ~TPMA_OBJECT_SIGN_ENCRYPT;
        *attrs &= ~TPMA_OBJECT_DECRYPT;
    } else if (!strncmp("hmac", object_alg, 4)) {
        *attrs &= ~TPMA_OBJECT_DECRYPT;
    }

    /*
     * IMPORTANT: if the object we're creating has a policy and NO authvalue, turn off userwith auth
     * so empty passwords don't work on the object.
     */
    if (has_policy && !has_auth) {
        *attrs &= ~TPMA_OBJECT_USERWITHAUTH;
    }
}

typedef enum tpm2_alg_util_flags tpm2_alg_util_flags;
enum tpm2_alg_util_flags {
    tpm2_alg_util_flags_none       = 0,
    tpm2_alg_util_flags_hash       = 1 << 0,
    tpm2_alg_util_flags_keyedhash  = 1 << 1,
    tpm2_alg_util_flags_symmetric  = 1 << 2,
    tpm2_alg_util_flags_asymmetric = 1 << 3,
    tpm2_alg_util_flags_kdf        = 1 << 4,
    tpm2_alg_util_flags_mgf        = 1 << 5,
    tpm2_alg_util_flags_sig        = 1 << 6,
    tpm2_alg_util_flags_mode       = 1 << 7,
    tpm2_alg_util_flags_base       = 1 << 8,
    tpm2_alg_util_flags_misc       = 1 << 9,
    tpm2_alg_util_flags_enc_scheme = 1 << 10,
    tpm2_alg_util_flags_rsa_scheme = 1 << 11,
    tpm2_alg_util_flags_any        = ~0
};

typedef struct alg_pair alg_pair;
struct alg_pair {
    const char *name;
    TPM2_ALG_ID id;
    tpm2_alg_util_flags flags;
    tpm2_alg_util_flags _flags;
};

typedef enum alg_iter_res alg_iter_res;
enum alg_iter_res {
    stop,
    go,
    found
};

static alg_iter_res find_match(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata) {

    alg_pair *search_data = (alg_pair *) userdata;

    /*
     * if name, then search on name, else
     * search by id.
     */
    if (search_data->name && !strcmp(search_data->name, name)) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->id = id;
            search_data->_flags = flags;
        }
        return res;
    } else if (search_data->id == id) {
        alg_iter_res res = search_data->flags & flags ? found : stop;
        if (res == found) {
            search_data->name = name;
            search_data->_flags = flags;
        }
        return res;
    }

    return go;
}

typedef alg_iter_res (*alg_iter)(TPM2_ALG_ID id, const char *name,
        tpm2_alg_util_flags flags, void *userdata);

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

static void tpm2_alg_util_for_each_alg(alg_iter iterator, void *userdata) {

    static const alg_pair algs[] = {

        // Assymetric
        { .name = "rsa", .id = TPM2_ALG_RSA, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },
        { .name = "ecc", .id = TPM2_ALG_ECC, .flags = tpm2_alg_util_flags_asymmetric|tpm2_alg_util_flags_base },

        // Symmetric
        { .name = "tdes", .id = TPM2_ALG_TDES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "aes", .id = TPM2_ALG_AES, .flags = tpm2_alg_util_flags_symmetric },
        { .name = "camellia", .id = TPM2_ALG_CAMELLIA, .flags = tpm2_alg_util_flags_symmetric },

        // Hash
        { .name = "sha1", .id = TPM2_ALG_SHA1, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha256", .id = TPM2_ALG_SHA256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha384", .id = TPM2_ALG_SHA384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha512", .id = TPM2_ALG_SHA512, .flags = tpm2_alg_util_flags_hash },
        { .name = "sm3_256", .id = TPM2_ALG_SM3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_256", .id = TPM2_ALG_SHA3_256, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_384", .id = TPM2_ALG_SHA3_384, .flags = tpm2_alg_util_flags_hash },
        { .name = "sha3_512", .id = TPM2_ALG_SHA3_512, .flags = tpm2_alg_util_flags_hash },

        // Keyed hash
        { .name = "hmac", .id = TPM2_ALG_HMAC, tpm2_alg_util_flags_keyedhash | tpm2_alg_util_flags_sig },
        { .name = "xor", .id = TPM2_ALG_XOR, tpm2_alg_util_flags_keyedhash },
        { .name = "cmac", .id = TPM2_ALG_CMAC, .flags = tpm2_alg_util_flags_sig },

        // Mask Generation Functions
        { .name = "mgf1", .id = TPM2_ALG_MGF1, .flags = tpm2_alg_util_flags_mgf },

        // Signature Schemes
        { .name = "rsassa", .id = TPM2_ALG_RSASSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "rsapss", .id = TPM2_ALG_RSAPSS, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdsa", .id = TPM2_ALG_ECDSA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecdaa", .id = TPM2_ALG_ECDAA, .flags = tpm2_alg_util_flags_sig },
        { .name = "ecschnorr", .id = TPM2_ALG_ECSCHNORR, .flags = tpm2_alg_util_flags_sig },

        // Assyemtric Encryption Scheme
        { .name = "oaep", .id = TPM2_ALG_OAEP, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "rsaes", .id = TPM2_ALG_RSAES, .flags = tpm2_alg_util_flags_enc_scheme | tpm2_alg_util_flags_rsa_scheme },
        { .name = "ecdh", .id = TPM2_ALG_ECDH, .flags = tpm2_alg_util_flags_enc_scheme },


        // XXX are these sigs?
        { .name = "sm2", .id = TPM2_ALG_SM2, .flags = tpm2_alg_util_flags_sig },
        { .name = "sm4", .id = TPM2_ALG_SM4, .flags = tpm2_alg_util_flags_sig },

        // Key derivation functions
        { .name = "kdf1_sp800_56a", .id = TPM2_ALG_KDF1_SP800_56A, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf2", .id = TPM2_ALG_KDF2, .flags = tpm2_alg_util_flags_kdf },
        { .name = "kdf1_sp800_108", .id = TPM2_ALG_KDF1_SP800_108, .flags = tpm2_alg_util_flags_kdf },
        { .name = "ecmqv", .id = TPM2_ALG_ECMQV, .flags = tpm2_alg_util_flags_kdf },

        // Modes
        { .name = "ctr", .id = TPM2_ALG_CTR, .flags = tpm2_alg_util_flags_mode },
        { .name = "ofb", .id = TPM2_ALG_OFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "cbc", .id = TPM2_ALG_CBC, .flags = tpm2_alg_util_flags_mode },
        { .name = "cfb", .id = TPM2_ALG_CFB, .flags = tpm2_alg_util_flags_mode },
        { .name = "ecb", .id = TPM2_ALG_ECB, .flags = tpm2_alg_util_flags_mode },

        { .name = "symcipher", .id = TPM2_ALG_SYMCIPHER, .flags = tpm2_alg_util_flags_base },
        { .name = "keyedhash", .id = TPM2_ALG_KEYEDHASH, .flags = tpm2_alg_util_flags_base },

        // Misc
        { .name = "null", .id = TPM2_ALG_NULL, .flags = tpm2_alg_util_flags_misc | tpm2_alg_util_flags_rsa_scheme },
    };

    size_t i;
    for (i = 0; i < ARRAY_LEN(algs); i++) {
        const alg_pair *alg = &algs[i];
        alg_iter_res result = iterator(alg->id, alg->name, alg->flags,
                userdata);
        if (result != go) {
            return;
        }
    }
}

const char *tpm2_alg_util_algtostr(TPM2_ALG_ID id, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = NULL, .id = id, .flags = flags };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata.name;
}

bool tpm2_util_string_to_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t) tmp;
    return true;
}

TPM2_ALG_ID tpm2_alg_util_strtoalg(const char *name, tpm2_alg_util_flags flags) {

    alg_pair userdata = { .name = name, .id = TPM2_ALG_ERROR, .flags = flags };

    if (name) {
        tpm2_alg_util_for_each_alg(find_match, &userdata);
    }

    return userdata.id;
}

TPM2_ALG_ID tpm2_alg_util_from_optarg(const char *optarg,
        tpm2_alg_util_flags flags) {

    TPM2_ALG_ID halg;
    bool res = tpm2_util_string_to_uint16(optarg, &halg);
    if (!res) {
        halg = tpm2_alg_util_strtoalg(optarg, flags);
    } else {
        if (!tpm2_alg_util_algtostr(halg, flags)) {
            return TPM2_ALG_ERROR;
        }
    }
    return halg;
}

typedef enum alg_parser_rc alg_parser_rc;
enum alg_parser_rc {
    alg_parser_rc_error,
    alg_parser_rc_continue,
    alg_parser_rc_done
};

static alg_parser_rc handle_rsa(const char *ext, TPM2B_PUBLIC *public) {

    public->publicArea.type = TPM2_ALG_RSA;
    TPMS_RSA_PARMS *r = &public->publicArea.parameters.rsaDetail;
    r->exponent = 0;

    size_t len = ext ? strlen(ext) : 0;
    if (len == 0 || ext[0] == '\0') {
        ext = "2048";
    }

    // Deal with bit size
    if (!strncmp(ext, "1024", 4)) {
        r->keyBits = 1024;
        ext += 4;
    } else if (!strncmp(ext, "2048", 4)) {
        r->keyBits = 2048;
        ext += 4;
    } else if (!strncmp(ext, "4096", 4)) {
        r->keyBits = 4096;
        ext += 4;
    } else if (!strncmp(ext, "3072", 4)) {
        r->keyBits = 3072;
        ext += 4;
    } else {
        r->keyBits = 2048;
    }

    /* rsa extension should be consumed at this point */
    return ext[0] == '\0' ? alg_parser_rc_continue : alg_parser_rc_error;
}

static alg_parser_rc handle_object(const char *object, TPM2B_PUBLIC *public) {

    if (!strncmp(object, "rsa", 3)) {
        object += 3;
        return handle_rsa(object, public);
    // } else if (!strncmp(object, "ecc", 3)) {
    //     object += 3;
    //     return handle_ecc(object, public);
    // } else if (!strncmp(object, "aes", 3)) {
    //     object += 3;
    //     return handle_aes(object, public);
    // } else if (!strncmp(object, "camellia", 8)) {
    //     object += 8;
    //     return handle_camellia(object, public);
    // } else if (!strcmp(object, "hmac")) {
    //     return handle_hmac(public);
    // } else if (!strcmp(object, "xor")) {
    //     return handle_xor(public);
    // } else if (!strcmp(object, "keyedhash")) {
    //     return handle_keyedhash(public);
    }

    return alg_parser_rc_error;
}

tpm2_alg_util_flags tpm2_alg_util_algtoflags(TPM2_ALG_ID id) {

    alg_pair userdata = { .name = NULL, .id = id, .flags =
            tpm2_alg_util_flags_any, ._flags = tpm2_alg_util_flags_none };

    tpm2_alg_util_for_each_alg(find_match, &userdata);

    return userdata._flags;
}

#define do_scheme_halg(scheme, advance, alg) \
    do { \
        scheme += advance; \
        s->scheme.scheme = alg; \
        do_scheme_hash_alg = true; \
        found = true; \
    } while (0)

static alg_parser_rc handle_scheme_sign(const char *scheme,
        TPM2B_PUBLIC *public) {

    char buf[256];

    if (!scheme || scheme[0] == '\0') {
        scheme = "null";
    }

    int rc = snprintf(buf, sizeof(buf), "%s", scheme);
    if (rc < 0 || (size_t) rc >= sizeof(buf)) {
        return alg_parser_rc_error;
    }

    // Get the scheme and symetric details
    TPMS_ASYM_PARMS *s = &public->publicArea.parameters.asymDetail;

    if (!strcmp(scheme, "null")) {
        public->publicArea.parameters.asymDetail.scheme.scheme = TPM2_ALG_NULL;
        return alg_parser_rc_continue;
    }

    char *halg = NULL;
    char *split = strchr(scheme, '-');
    if (split) {
        *split = '\0';
        halg = split + 1;
    }

    bool found = false;
    bool do_scheme_hash_alg = false;

    if (public->publicArea.type == TPM2_ALG_ECC) {
        printf("ECC not supported \n");
        exit(1);

        // if (!strncmp(scheme, "ecdsa", 5)) {
        //     do_scheme_halg(scheme, 5, TPM2_ALG_ECDSA);
        // } else if (!strncmp(scheme, "ecdh", 4)) {
        //     do_scheme_halg(scheme, 4, TPM2_ALG_ECDH);
        // } else if (!strncmp(scheme, "ecschnorr", 9)) {
        //     do_scheme_halg(scheme, 9, TPM2_ALG_ECSCHNORR);
        // } else if (!strncmp(scheme, "ecdaa", 5)) {
        //     do_scheme_halg(scheme, 5, TPM2_ALG_ECDAA);
        //     /*
        //      * ECDAA has both a commit-counter value and hashing algorithm.
        //      * The default commit-counter value is set to zero to use the first
        //      * commit-id.
        //      */
        //     if (scheme[0] == '\0') {
        //         scheme = "0";
        //     }

        //     TPMS_SIG_SCHEME_ECDAA *e = &s->scheme.details.ecdaa;

        //     bool res = tpm2_util_string_to_uint16(scheme, &e->count);
        //     if (!res) {
        //         return alg_parser_rc_error;
        //     }
        // } else if (!strcmp("null", scheme)) {
        //     s->scheme.scheme = TPM2_ALG_NULL;
        // }
    } else {
        if (!strcmp(scheme, "rsaes")) {
            /*
             * rsaes has no hash alg or details, so it MUST
             * match exactly, notice strcmp and NOT strNcmp!
             */
            s->scheme.scheme = TPM2_ALG_RSAES;
            found = true;
        } else if (!strcmp("null", scheme)) {
            s->scheme.scheme = TPM2_ALG_NULL;
            found = true;
        } else if (!strncmp("rsapss", scheme, 6)) {
            do_scheme_halg(scheme, 6, TPM2_ALG_RSAPSS);
        } else if (!strncmp("rsassa", scheme, 6)) {
            do_scheme_halg(scheme, 6, TPM2_ALG_RSASSA);
        } else if (!strncmp(scheme, "oaep", 4)) {
            do_scheme_halg(scheme, 4, TPM2_ALG_OAEP);
        }
    }

    /* If we're not expecting a hash alg then halg should be NULL */
    if ((!do_scheme_hash_alg && halg) || !found) {
        return alg_parser_rc_error;
    }

    /* if we're expecting a hash alg and none provided default */
    if (do_scheme_hash_alg && !halg) {
        halg = "sha256";
    }

    /*
     * If the scheme is set, both the encrypt and decrypt attributes cannot be set,
     * check to see if this is the case, and turn down:
     *  - DECRYPT - If its a signing scheme.
     *  - ENCRYPT - If its an asymmetric enc scheme.
     */
    if (s->scheme.scheme != TPM2_ALG_NULL) {
        bool is_both_set = !!(public->publicArea.objectAttributes
                & (TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_DECRYPT));
        if (is_both_set) {
            tpm2_alg_util_flags flags = tpm2_alg_util_algtoflags(
                    s->scheme.scheme);
            TPMA_OBJECT turn_down_flags =
                    (flags & tpm2_alg_util_flags_sig) ?
                            TPMA_OBJECT_DECRYPT : TPMA_OBJECT_SIGN_ENCRYPT;
            public->publicArea.objectAttributes &= ~turn_down_flags;
        }
    }

    if (do_scheme_hash_alg) {
    public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg =
                tpm2_alg_util_strtoalg(halg, tpm2_alg_util_flags_hash);
        if (public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg
                == TPM2_ALG_ERROR) {
            return alg_parser_rc_error;
        }
    }

    return alg_parser_rc_continue;
}

static alg_parser_rc handle_scheme(const char *scheme, TPM2B_PUBLIC *public) {

    switch (public->publicArea.type) {
    case TPM2_ALG_RSA:
    case TPM2_ALG_ECC:
        return handle_scheme_sign(scheme, public);
    // case TPM2_ALG_KEYEDHASH:
    //     return handle_scheme_keyedhash(scheme, public);
    default:
        return alg_parser_rc_error;
    }

    return alg_parser_rc_error;
}

static alg_parser_rc handle_sym_common(const char *ext, TPMT_SYM_DEF_OBJECT *s) {

    if (ext == NULL || ext[0] == '\0') {
        ext = "128";
    }

    if (!strncmp(ext, "128", 3)) {
        s->keyBits.sym = 128;
    } else if (!strncmp(ext, "192", 3)) {
        s->keyBits.sym = 192;
    } else if (!strncmp(ext, "256", 3)) {
        s->keyBits.sym = 256;
    } else {
        return alg_parser_rc_error;
    }

    ext += 3;

    if (*ext == '\0') {
        ext = "null";
    }

    s->mode.sym = tpm2_alg_util_strtoalg(ext,
            tpm2_alg_util_flags_mode | tpm2_alg_util_flags_misc);
    if (s->mode.sym == TPM2_ALG_ERROR) {
        return alg_parser_rc_error;
    }

    return alg_parser_rc_done;
}

static alg_parser_rc handle_asym_detail(const char *detail,
        TPM2B_PUBLIC *public) {

    bool is_restricted = !!(public->publicArea.objectAttributes
            & TPMA_OBJECT_RESTRICTED);
    bool is_rsapps = public->publicArea.parameters.asymDetail.scheme.scheme
            == TPM2_ALG_RSAPSS;

    switch (public->publicArea.type) {
    case TPM2_ALG_RSA:
    case TPM2_ALG_ECC:

        if (!detail || detail[0] == '\0') {
            detail = is_restricted || is_rsapps ? "aes128cfb" : "null";
        }

        TPMT_SYM_DEF_OBJECT *s = &public->publicArea.parameters.symDetail.sym;

        if (!strncmp(detail, "aes", 3)) {
            s->algorithm = TPM2_ALG_AES;
            return handle_sym_common(detail + 3, s);
        } else if (!strncmp(detail, "camellia", 8)) {
            s->algorithm = TPM2_ALG_CAMELLIA;
            return handle_sym_common(detail + 8, s);
        } else if (!strcmp(detail, "null")) {
            s->algorithm = TPM2_ALG_NULL;
            return alg_parser_rc_done;
        }
        /* no default */
    }

    return alg_parser_rc_error;
}

bool tpm2_alg_util_handle_ext_alg(const char *alg_spec, TPM2B_PUBLIC *public) {

    char buf[256];

    if (!alg_spec) {
        return false;
    }

    int rc = snprintf(buf, sizeof(buf), "%s", alg_spec);
    if (rc < 0 || (size_t) rc >= sizeof(buf)) {
        goto error;
    }

    char *object = NULL;
    char *scheme = NULL;
    char *symdetail = NULL;

    char *b = buf;
    char *tok = NULL;
    char *saveptr = NULL;
    unsigned i = 0;

#ifdef __linux__     
    while ((tok = strtok_r(b, ":", &saveptr))) {
#elif _WIN32
    // https://stackoverflow.com/questions/39501494/strtok-r-unresolved-external-symbol    
    while ((tok = strtok_s(b, ":", &saveptr))) {
#endif
        b = NULL;

        switch (i) {
        case 0:
            object = tok;
            break;
        case 1:
            scheme = tok;
            break;
        case 2:
            symdetail = tok;
            break;
        default:
            goto error;
        }
        i++;
    }

    if (i == 0) {
        goto error;
    }

    alg_parser_rc prc = handle_object(object, public);
    if (prc == alg_parser_rc_done) {
        /* we must have exhausted all the entries or it's an error */
        return scheme || symdetail ? false : true;
    }

    if (prc == alg_parser_rc_error) {
        return false;
    }

    /*
     * at this point we either have scheme or asym detail, if it
     * doesn't process as a scheme shuffle it to asym detail
     */
    for (i = 0; i < 2; i++) {
        prc = handle_scheme(scheme, public);
        if (prc == alg_parser_rc_done) {
            /* we must have exhausted all the entries or it's an error */
            return symdetail ? false : true;
        }

        if (prc == alg_parser_rc_error) {
            /*
             * if symdetail is set scheme must be consumed
             * unless scheme has been skipped by setting it
             * to NULL
             */
            if (symdetail && scheme) {
                return false;
            }

            symdetail = scheme;
            scheme = NULL;
            continue;
        }

        /* success in processing scheme */
        break;
    }

    /* handle asym detail */
    prc = handle_asym_detail(symdetail, public);
    if (prc != alg_parser_rc_done) {
        goto error;
    }

    return true;

    error:
    printf("Could not handle algorithm spec: \"%s\"", alg_spec);
    return false;
}

tool_rc tpm2_alg_util_public_init(char *alg_details, char *name_halg, char *attrs,
        char *auth_policy,  TPMA_OBJECT def_attrs, TPM2B_PUBLIC *public) {

    memset(public, 0, sizeof(*public));

    /* load a policy from a path if present */
    if (auth_policy) {
    // public->publicArea.authPolicy.size =
    //             sizeof(public->publicArea.authPolicy.buffer);
    //     bool res = files_load_bytes_from_path(auth_policy,
    //         public->publicArea.authPolicy.buffer,
    //             &public->publicArea.authPolicy.size);
    //     if (!res) {
    //         return tool_rc_general_error;
    //     }
    }

    /* Set the hashing algorithm used for object name */
    // public->publicArea.nameAlg = name_halg ?
    //     tpm2_alg_util_from_optarg(name_halg, tpm2_alg_util_flags_hash) :
    //     TPM2_ALG_SHA256;

    public->publicArea.nameAlg = TPM2_ALG_SHA256;

    if (public->publicArea.nameAlg == TPM2_ALG_ERROR) {
        printf("Invalid name hashing algorithm, got\"%s\"\n", name_halg);
        return tool_rc_unsupported;
    }

    /* Set specified attributes or use default */
    if (attrs) {
        // bool res = tpm2_attr_util_obj_from_optarg(attrs,
        //         &public->publicArea.objectAttributes);
        // if (!res) {
        //     return tool_rc_unsupported;
        // }
    } else {
        public->publicArea.objectAttributes = def_attrs;
    }

    /*
     * Some defaults may not be OK with the specified algorithms, if their defaults,
     * tweak the Object Attributes, if specified by user, complain things will not
     * work together and suggest attributes. This allows the user to verify what the
     * want.
     */
    TPM2B_PUBLIC tmp = *public;
    bool res = tpm2_alg_util_handle_ext_alg(alg_details, &tmp);
    if (!res) {
        printf("Could not handle algorithm: \"%s\"\n", alg_details);
        return tool_rc_unsupported;
    }

    if (attrs && tmp.publicArea.objectAttributes !=
        public->publicArea.objectAttributes) {

        // char *proposed_attrs = tpm2_attr_util_obj_attrtostr(
        //         tmp.publicArea.objectAttributes);
        // LOG_ERR("Specified attributes \"%s\" and algorithm specifier \"%s\" do "
        //         "not work together, try attributes: \"%s\"", attrs, alg_details,
        //         proposed_attrs);
        // free(proposed_attrs);
        // return tool_rc_unsupported;
    }

    *public = tmp;

    return tool_rc_success;
}

INT16 tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id) {

    switch (id) {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

typedef enum tpm2_openssl_load_rc tpm2_openssl_load_rc;
enum tpm2_openssl_load_rc {
    lprc_error = 0, /* an error has occurred */
    lprc_private = 1 << 0, /* successfully loaded a private portion of object */
    lprc_public = 1 << 1, /* successfully loaded a public portion of object */
};

typedef struct evp_pkey_st EVP_PKEY;

static bool handle_ossl_pass(const char *passin, char **pass) {

    return true;

    // pfn_ossl_pw_handler pfn = NULL;

    // if (!passin) {
    //     *pass = NULL;
    //     return true;
    // }

    // if (!strncmp("pass:", passin, 5)) {
    //     passin += 5;
    //     pfn = do_pass;
    // } else if (!strncmp("env:", passin, 4)) {
    //     pfn = do_env;
    //     passin += 4;
    // } else if (!strncmp("file:", passin, 5)) {
    //     pfn = do_file;
    //     passin += 5;
    // } else if (!strncmp("fd:", passin, 3)) {
    //     pfn = do_fd;
    //     passin += 3;
    // } else if (!strcmp("stdin", passin)) {
    //     pfn = do_stdin;
    // } else {
    //     LOG_ERR("Unknown OSSL style password argument, got: \"%s\"", passin);
    //     return false;
    // }

    // return pfn(passin, pass);
}

const EVP_MD *tpm2_openssl_md_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
    /* no return, not possible */
}

static bool load_private_RSA_from_key(EVP_PKEY *key, TPM2B_SENSITIVE *priv) {

    bool result = false;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *p = NULL; /* the private key exponent */

    RSA *k = EVP_PKEY_get0_RSA(key);
    if (!k) {
        printf("Could not retrieve RSA key");
        goto out;
    }
    RSA_get0_factors(k, &p, NULL);
#else
    BIGNUM *p = NULL; /* the private key exponent */

    int rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
    if (!rc) {
        LOG_ERR("Could not read private key");
        goto out;
    }
#endif

    TPMT_SENSITIVE *sa = &priv->sensitiveArea;

    sa->sensitiveType = TPM2_ALG_RSA;

    TPM2B_PRIVATE_KEY_RSA *pkr = &sa->sensitive.rsa;

    unsigned priv_bytes = BN_num_bytes(p);
    if (priv_bytes > sizeof(pkr->buffer)) {
        printf("Expected prime \"d\" to be less than or equal to %zu,"
                " got: %u", sizeof(pkr->buffer), priv_bytes);
        goto out;
    }

    pkr->size = priv_bytes;

    int success = BN_bn2bin(p, pkr->buffer);
    if (!success) {
        ERR_print_errors_fp(stderr);
        printf("Could not copy private exponent \"d\"");
        goto out;
    }
    result = true;
out:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* k,p point to internal structrues and must not be freed after use */
#else
    BN_free(p);
#endif
    return result;
}

static bool load_public_RSA_from_key(EVP_PKEY *key, TPM2B_PUBLIC *pub) {

    bool result = false;
    TPMT_PUBLIC *pt = &pub->publicArea;
    pt->type = TPM2_ALG_RSA;

    TPMS_RSA_PARMS *rdetail = &pub->publicArea.parameters.rsaDetail;
    rdetail->scheme.scheme = TPM2_ALG_NULL;
    rdetail->symmetric.algorithm = TPM2_ALG_NULL;
    rdetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

    /* NULL out sym details */
    TPMT_SYM_DEF_OBJECT *sym = &rdetail->symmetric;
    sym->algorithm = TPM2_ALG_NULL;
    sym->keyBits.sym = 0;
    sym->mode.sym = TPM2_ALG_NULL;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *n; /* modulus */
    const BIGNUM *e; /* public key exponent */

    RSA *k = EVP_PKEY_get0_RSA(key);
    if (!k) {
        printf("Could not retrieve RSA key");
        goto out;
    }

    RSA_get0_key(k, &n, &e, NULL);
#else
    BIGNUM *n = NULL; /* modulus */
    BIGNUM *e = NULL; /* public key exponent */

    int rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
    if (!rc) {
        LOG_ERR("Could not read public modulus N");
        goto out;
    }

    rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
    if (!rc) {
        LOG_ERR("Could not read public exponent E");
        goto out;
    }
#endif
    /*
     * The size of the modulus is the key size in RSA, store this as the
     * keyBits in the RSA details.
     */
    rdetail->keyBits = BN_num_bytes(n) * 8;
    switch (rdetail->keyBits) {
    case 1024: /* falls-through */
    case 2048: /* falls-through */
    case 4096: /* falls-through */
        break;
    default:
        printf("RSA key-size %u is not supported", rdetail->keyBits);
        goto out;
    }

    /* copy the modulus to the unique RSA field */
    pt->unique.rsa.size = rdetail->keyBits / 8;
    int success = BN_bn2bin(n, pt->unique.rsa.buffer);
    if (!success) {
        printf("Could not copy public modulus N");
        goto out;
    }

    unsigned long exp = BN_get_word(e);
    if (exp == 0xffffffffL) {
        printf("Could not copy public exponent E");
        goto out;
    }
    rdetail->exponent = exp;

    result = true;
out:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* k,n,e point to internal structrues and must not be freed after use */
#else
    BN_free(n);
    BN_free(e);
#endif
    return result;
}

static tpm2_openssl_load_rc load_private_RSA_from_pem(FILE *f, const char *path,
        const char *passin, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    EVP_PKEY *k = NULL;

    tpm2_openssl_load_rc rc = lprc_error;

    char *pass = NULL;
    bool result = handle_ossl_pass(passin, &pass);
    if (!result) {
        return lprc_error;
    }

    k = PEM_read_PrivateKey(f, NULL, NULL, (void *) pass);
    free(pass);
    if (!k) {
        ERR_print_errors_fp(stderr);
        printf("Reading PEM file \"%s\" failed", path);
        return lprc_error;
    }

    bool loaded_priv = load_private_RSA_from_key(k, priv);
    if (!loaded_priv) {
        return lprc_error;
    } else {
        rc |= lprc_private;
    }

    bool loaded_pub = load_public_RSA_from_key(k, pub);
    if (!loaded_pub) {
        goto out;
    } else {
        rc |= lprc_public;
    }
out:
    EVP_PKEY_free(k);
    return rc;
}

tpm2_openssl_load_rc tpm2_openssl_load_private(const char *path,
        const char *passin, const char *object_auth, TPM2B_PUBLIC *template, TPM2B_PUBLIC *pub,
        TPM2B_SENSITIVE *priv) {


    FILE *f = fopen(path, "r");
    if (!f) {
        printf("Could not open file \"%s\", error: %s\n", path, strerror(errno));
        return 0;
    }

    *pub = *template;

    tpm2_openssl_load_rc rc = lprc_error;

    switch (template->publicArea.type) {
    case TPM2_ALG_RSA:
        rc = load_private_RSA_from_pem(f, path, passin, pub, priv);
        break;
    // case TPM2_ALG_SYMCIPHER:
    //     if (passin) {
    //         LOG_ERR("No password can be used for protecting AES key");
    //         rc = lprc_error;
    //     } else if (template->publicArea.parameters.asymDetail.symmetric.algorithm != TPM2_ALG_AES) {
    //         LOG_ERR("Cannot handle non-aes symmetric objects, got: 0x%x",
    //                 template->publicArea.parameters.asymDetail.symmetric.algorithm);
    //         rc = lprc_error;
    //     } else {
    //         rc = load_private_AES_from_file(f, path, pub, priv);
    //     }
    //     break;
    // case TPM2_ALG_HMAC:
    //     /* falls-thru */
    // case TPM2_ALG_KEYEDHASH:
    //     if (passin) {
    //         LOG_ERR("No password can be used for protecting %s key",
    //                 TPM2_ALG_HMAC ? "HMAC" : "Keyed Hash");
    //         rc = lprc_error;
    //     } else {
    //         rc = load_private_KEYEDHASH_from_file(f, path, pub, priv);
	// }
    //   break;
    // case TPM2_ALG_ECC:
    //     rc = load_private_ECC_from_pem(f, path, passin, pub, priv);
    //     break;
    default:
        printf("Cannot handle algorithm, got: %s \n", tpm2_alg_util_algtostr(template->publicArea.type,
            tpm2_alg_util_flags_any));
        rc = lprc_error;
    }

    fclose(f);

    if (object_auth) {
        // tpm2_session *tmp;
        // tool_rc tmp_rc = tpm2_auth_util_from_optarg(NULL, object_auth, &tmp, true);
        // if (tmp_rc != tool_rc_success) {
        //     LOG_ERR("Invalid key authorization");
        //     return false;
        // }

        // const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
        TPM2B_AUTH k_authValue = {
            .size = 0,
            .buffer = {0}
        };    

        if (strcmp(object_auth, "NULL") != 0) {
            const char *k_auth = object_auth;

            k_authValue.size = strlen(k_auth);
            for (int i = 0; i < k_authValue.size; i++) {
                k_authValue.buffer[i] = k_auth[i];
            }
        }

        priv->sensitiveArea.authValue = k_authValue;

        // tpm2_session_close(&tmp);
    }

    return rc;
}

static inline bool tpm2_openssl_did_load_public(
        tpm2_openssl_load_rc load_status) {
    return (load_status & lprc_public);
}

EVP_PKEY *convert_pubkey_RSA(TPMT_PUBLIC *public) {

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsa_key = NULL;
#else
    OSSL_PARAM_BLD *build = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
#endif
    BIGNUM *e = NULL, *n = NULL;
    EVP_PKEY *pkey = NULL;

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size, NULL);
    if (!n) {
        printf("Failed to convert data to SSL internal format");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    rsa_key = RSA_new();
    if (!rsa_key) {
        printf("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_new();
    if (!e) {
        printf("Failed to convert data to SSL internal format");
        goto error;
    }
    int rc = BN_set_word(e, exponent);
    if (!rc) {
        printf("Failed to convert data to SSL internal format");
        goto error;
    }

    rc = RSA_set0_key(rsa_key, n, e, NULL);
    if (!rc) {
        printf("Failed to set RSA modulus and exponent components");
        goto error;
    }

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    pkey = EVP_PKEY_new();
    if (!pkey) {
        printf("Failed to allocate OpenSSL EVP structure");
        goto error;
    }

    rc = EVP_PKEY_assign_RSA(pkey, rsa_key);
    if (!rc) {
        printf("Failed to set OpenSSL EVP structure");
        EVP_PKEY_free(pkey);
        pkey = NULL;
        goto error;
    }
    /* rsa key is now owner by the EVP_PKEY struct */
    rsa_key = NULL;
#else
    build = OSSL_PARAM_BLD_new();
    if (!build) {
        print_ssl_error("Failed to allocate OpenSSL parameters");
        goto error;
    }

    int rc = OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n);
    if (!rc) {
        print_ssl_error("Failed to set RSA modulus");
        goto error;
    }

    rc = OSSL_PARAM_BLD_push_uint32(build, OSSL_PKEY_PARAM_RSA_E, exponent);
    if (!rc) {
        print_ssl_error("Failed to set RSA exponent");
        goto error;
    }

    params = OSSL_PARAM_BLD_to_param(build);
    if (!params) {
        print_ssl_error("Failed to build OpenSSL parameters");
        goto error;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        print_ssl_error("Failed to allocate RSA key context");
        goto error;
    }

    rc = EVP_PKEY_fromdata_init(ctx);
    if (rc <= 0) {
        print_ssl_error("Failed to initialize RSA key creation");
        goto error;
    }

    rc = EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (rc <= 0) {
        print_ssl_error("Failed to create a RSA public key");
        goto error;
    }
#endif
error:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA_free(rsa_key);
#else
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(build);
#endif
    BN_free(n);
    BN_free(e);
    return pkey;
}

static bool share_secret_with_tpm2_rsa_public_key(TPM2B_DIGEST *protection_seed,
        TPM2B_PUBLIC *parent_pub, const unsigned char *label, int label_len,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool rval = false;
    EVP_PKEY_CTX *ctx = NULL;

    EVP_PKEY *pkey = convert_pubkey_RSA(&parent_pub->publicArea);
    if (pkey == NULL) {
        printf("Failed to retrieve public key");
        return false;
    }

    TPMI_ALG_HASH parent_name_alg = parent_pub->publicArea.nameAlg;

    /*
     * RSA Secret Sharing uses a randomly generated seed (Part 1, B.10.3).
     */
    protection_seed->size = tpm2_alg_util_get_hash_size(parent_name_alg);
    int rc = RAND_bytes(protection_seed->buffer, protection_seed->size);
    if (rc != 1) {
        printf("Failed to get random bytes");
        goto error;
    }

    /*
     * The seed value will be OAEP encrypted with a given L parameter.
     */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        printf("Failed EVP_PKEY_CTX_new");
        goto error;
    }

    rc = EVP_PKEY_encrypt_init(ctx);
    if (rc <= 0) {
        printf("Failed EVP_PKEY_encrypt_init");
        goto error;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (rc <= 0) {
        printf("Failed EVP_PKEY_CTX_set_rsa_padding");
        goto error;
    }

    rc = EVP_PKEY_CTX_set_rsa_oaep_md(ctx,
            tpm2_openssl_md_from_tpmhalg(parent_name_alg));
    if (rc <= 0) {
        printf("Failed EVP_PKEY_CTX_set_rsa_oaep_md");
        goto error;
    }

    // the library will take ownership of the label
    char *newlabel = strdup((const char *)label);
    if (newlabel == NULL) {
        printf("Failed to allocate label");
        goto error;
    }

    rc = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, newlabel, label_len);
    if (rc <= 0) {
        printf("Failed EVP_PKEY_CTX_set0_rsa_oaep_label");
        free(newlabel);
        goto error;
    }

    size_t outlen = sizeof(TPMU_ENCRYPTED_SECRET);
    if (EVP_PKEY_encrypt(ctx, encrypted_protection_seed->secret, &outlen,
            protection_seed->buffer, protection_seed->size) <= 0) {
        printf("Failed EVP_PKEY_encrypt\n");
        goto error;
    }
    encrypted_protection_seed->size = outlen;
    rval = true;

error:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rval;
}

bool tpm2_identity_util_share_secret_with_public_key(
        TPM2B_DIGEST *protection_seed, TPM2B_PUBLIC *parent_pub,
        const unsigned char *label, int label_len,
        TPM2B_ENCRYPTED_SECRET *encrypted_protection_seed) {
    bool result = false;
    TPMI_ALG_PUBLIC alg = parent_pub->publicArea.type;

    switch (alg) {
    case TPM2_ALG_RSA:
        result = share_secret_with_tpm2_rsa_public_key(protection_seed,
                parent_pub, label, label_len, encrypted_protection_seed);
        break;
    // case TPM2_ALG_ECC:
    //     result = ecdh_derive_seed_and_encrypted_seed(parent_pub,
    //             label, label_len,
    //             protection_seed, encrypted_protection_seed);
    //     break;
    default:
        printf("Cannot handle algorithm, got: %s",
                tpm2_alg_util_algtostr(alg, tpm2_alg_util_flags_any));
        return false;
    }

    return result;
}

bool tpm2_openssl_import_keys(
        TPM2B_PUBLIC *parent_pub,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        const char *object_auth_value,
        const char *input_key_file,
        const char *passin,
        TPM2B_PUBLIC *template,
        TPM2B_SENSITIVE *out_private,
        TPM2B_PUBLIC *out_public
    ) {

    bool result;

    /*
     * The TPM Requires that the name algorithm for the child be less than the name
     * algorithm of the parent when the parent's scheme is NULL.
     *
     * This check can be seen in the simulator at:
     *   - File: CryptUtil.c
     *   - Func: CryptSecretDecrypt()
     *   - Line: 2019
     *   - Decription: Limits the size of the hash algorithm to less then the parent's name-alg when scheme is NULL.
     */
    UINT16 hash_size = tpm2_alg_util_get_hash_size(template->publicArea.nameAlg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(
            parent_pub->publicArea.nameAlg);
    if (hash_size > parent_hash_size) {
        printf("Hash selected is larger then parent hash size, coercing to "
                 "parent hash algorithm: %s\n",
                tpm2_alg_util_algtostr(parent_pub->publicArea.nameAlg,
                        tpm2_alg_util_flags_hash));
        template->publicArea.nameAlg = parent_pub->publicArea.nameAlg;
    }

    /*
     * Generate and encrypt seed, if requested
     */
    if (encrypted_seed)
    {
        TPM2B_DIGEST *seed = &out_private->sensitiveArea.seedValue;
        static const unsigned char label[] = { 'D', 'U', 'P', 'L', 'I', 'C', 'A', 'T', 'E', '\0' };
        result = tpm2_identity_util_share_secret_with_public_key(seed, parent_pub,
            label, sizeof(label), encrypted_seed);
        if (!result) {
            printf("Failed Seed Encryption\n");
            return false;
        }
    }

    /*
     * Populate all the private and public data fields we can based on the key type and the PEM files read in.
     */
    tpm2_openssl_load_rc status = tpm2_openssl_load_private(input_key_file,
            passin, object_auth_value, template, out_public, out_private);
    if (status == lprc_error) {
        return false;
    }

    if (!tpm2_openssl_did_load_public(status)) {
        printf("Did not find public key information in file: \"%s\" \n",
                input_key_file);
        return false;
    }

    return true;
}

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }

bool tpm2_identity_create_name(TPM2B_PUBLIC *public, TPM2B_NAME *pubname) {

    /*
     * A TPM2B_NAME is the name of the algorithm, followed by the hash.
     * Calculate the name by:
     * 1. Marshaling the name algorithm
     * 2. Marshaling the TPMT_PUBLIC past the name algorithm from step 1.
     * 3. Hash the TPMT_PUBLIC portion in marshaled data.
     */
    TSS2_RC rval;

    TPMI_ALG_HASH name_alg = public->publicArea.nameAlg;

    // Step 1 - set beginning of name to hash alg
    size_t hash_offset = 0;
    rval = Tss2_MU_UINT16_Marshal(name_alg, pubname->name, pubname->size,
            &hash_offset);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing the name size");
        return false;
    }

    // Step 2 - marshal TPMTP
    TPMT_PUBLIC marshaled_tpmt;
    size_t tpmt_marshalled_size = 0;
    rval = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea,
            (uint8_t *) &marshaled_tpmt, sizeof(public->publicArea),
            &tpmt_marshalled_size);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing the public area");
        return false;
    }

    // Step 3 - Hash the data into name just past the alg type.
    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(name_alg);
    if (!md) {
        printf("Algorithm not supported: %x", name_alg);
        return false;
    }

    unsigned int hash_size;
    int rc = EVP_Digest(&marshaled_tpmt, tpmt_marshalled_size,
                        pubname->name + hash_offset, &hash_size, md, NULL);
    if (!rc) {
        printf("Hash calculation failed");
        return false;
    }

    //Set the name size, UINT16 followed by HASH
    pubname->size = hash_size + hash_offset;

    return true;
}

typedef struct {
    UINT16 size;
    BYTE buffer[0];
} TPM2B;

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

UINT16 tpm2_util_endian_swap_16(UINT16 data);
UINT32 tpm2_util_hton_32(UINT32 data);

bool tpm2_util_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append) {

    if (!result || !append) {
        return false;
    }

    if (((UINT32)result->size + append->size) > TPM2_MAX_DIGEST_BUFFER) {
        return false;
    }

    memcpy(&result->buffer[result->size], append->buffer, append->size);
    result->size += append->size;

    return true;
}

TSS2_RC tpm2_kdfa(TPMI_ALG_HASH hash_alg, TPM2B *key, char *label,
        TPM2B *context_u, TPM2B *context_v, UINT16 bits,
        TPM2B_MAX_BUFFER *result_key) {
    TPM2B_DIGEST tpm2b_label, tpm2b_bits, tpm2b_i_2;
    TPM2B_DIGEST *buffer_list[8];
    TSS2_RC rval = TPM2_RC_SUCCESS;
    int i, j;
    UINT16 bytes = bits / 8;

    result_key->size = 0;

    tpm2b_i_2.size = 4;

    tpm2b_bits.size = 4;
    UINT32 bits_be = tpm2_util_hton_32(bits);
    memcpy(&tpm2b_bits.buffer[0], &bits_be, sizeof(bits_be));

    for(i = 0; label[i] != 0 ;i++ );

    tpm2b_label.size = i + 1;
    for (i = 0; i < tpm2b_label.size; i++) {
        tpm2b_label.buffer[i] = label[i];
    }

    result_key->size = 0;

    i = 1;

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(hash_alg);
    if (!md) {
        printf("Algorithm not supported for hmac: %x", hash_alg);
        return TPM2_RC_HASH;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX *ctx = HMAC_CTX_new();
#else
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(hmac);
#endif
    if (!ctx) {
        printf("HMAC context allocation failed");
        return TPM2_RC_MEMORY;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    int rc = HMAC_Init_ex(ctx, key->buffer, key->size, md, NULL);
#else
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST,
                                                 (char *)EVP_MD_get0_name(md), 0);
    params[1] = OSSL_PARAM_construct_end();
    int rc = EVP_MAC_init(ctx, key->buffer, key->size, params);
#endif
    if (!rc) {
        printf("HMAC Init failed: %s", ERR_error_string(rc, NULL));
        rval = TPM2_RC_MEMORY;
        goto err;
    }

    // TODO Why is this a loop? It appears to only execute once.
    while (result_key->size < bytes) {
        TPM2B_DIGEST tmpResult;
        // Inner loop
        bits_be = tpm2_util_hton_32(i);
        memcpy(&tpm2b_i_2.buffer[0], &bits_be, sizeof(bits_be));

        j = 0;
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_i_2);
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_label);
        buffer_list[j++] = (TPM2B_DIGEST *) context_u;
        buffer_list[j++] = (TPM2B_DIGEST *) context_v;
        buffer_list[j++] = (TPM2B_DIGEST *) &(tpm2b_bits);
        buffer_list[j] = (TPM2B_DIGEST *) 0;

        int c;
        for (c = 0; c < j; c++) {
            TPM2B_DIGEST *digest = buffer_list[c];
#if OPENSSL_VERSION_NUMBER < 0x30000000L
            int rc = HMAC_Update(ctx, digest->buffer, digest->size);
#else
            int rc = EVP_MAC_update(ctx, digest->buffer, digest->size);
#endif
            if (!rc) {
                printf("HMAC Update failed: %s", ERR_error_string(rc, NULL));
                rval = TPM2_RC_MEMORY;
                goto err;
            }
        }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
        unsigned size = sizeof(tmpResult.buffer);
        int rc = HMAC_Final(ctx, tmpResult.buffer, &size);
#else
        size_t size;
        int rc = EVP_MAC_final(ctx, tmpResult.buffer, &size, sizeof(tmpResult.buffer));
#endif
        if (!rc) {
            printf("HMAC Final failed: %s", ERR_error_string(rc, NULL));
            rval = TPM2_RC_MEMORY;
            goto err;
        }

        tmpResult.size = size;

        bool res = tpm2_util_concat_buffer(result_key, (TPM2B *) &tmpResult);
        if (!res) {
            rval = TSS2_SYS_RC_BAD_VALUE;
            goto err;
        }
    }

    // Truncate the result to the desired size.
    result_key->size = bytes;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    HMAC_CTX_free(ctx);
#else
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(hmac);
#endif

    return rval;
}

static TPM2_KEY_BITS get_pub_asym_key_bits(TPM2B_PUBLIC *public) {

    TPMU_PUBLIC_PARMS *p = &public->publicArea.parameters;
    switch (public->publicArea.type) {
    case TPM2_ALG_ECC:
        /* fall-thru */
    case TPM2_ALG_RSA:
        return p->asymDetail.symmetric.keyBits.sym;
        /* no default */
    }

    return 0;
}

bool tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
        TPM2B_PUBLIC *parent_pub, TPM2B_NAME *pubname,
        TPM2B_DIGEST *protection_seed, TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key) {

    TPM2B null_2b = { .size = 0 };

    TPMI_ALG_HASH parent_alg = parent_pub->publicArea.nameAlg;
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_alg);

    TSS2_RC rval = tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "INTEGRITY",
            &null_2b, &null_2b, parent_hash_size * 8, protection_hmac_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    TPM2_KEY_BITS pub_key_bits = get_pub_asym_key_bits(parent_pub);

    rval = tpm2_kdfa(parent_alg, (TPM2B *) protection_seed, "STORAGE",
            (TPM2B *) pubname, &null_2b, pub_key_bits, protection_enc_key);
    if (rval != TPM2_RC_SUCCESS) {
        return false;
    }

    return true;
}

static const EVP_CIPHER *tpm_alg_to_ossl(TPMT_SYM_DEF_OBJECT *sym) {

    switch (sym->algorithm) {
    case TPM2_ALG_AES: {
        switch (sym->keyBits.aes) {
        case 128:
            return EVP_aes_128_cfb();
        case 256:
            return EVP_aes_256_cfb();
            /* no default */
        }
    }
        /* no default */
    }

    printf("Unsupported parent key symmetric parameters");

    return NULL;
}

static bool aes_encrypt_buffers(TPMT_SYM_DEF_OBJECT *sym,
        uint8_t *encryption_key, uint8_t *buf1, size_t buf1_len, uint8_t *buf2,
        size_t buf2_len, TPM2B_MAX_BUFFER *cipher_text) {

    bool result = false;

    unsigned offset = 0;
    size_t total_len = buf1_len + buf2_len;

    if (total_len > sizeof(cipher_text->buffer)) {
        printf("Plaintext too big, got %zu, expected less then %zu", total_len,
                sizeof(cipher_text->buffer));
        return false;
    }

    const EVP_CIPHER *cipher = tpm_alg_to_ossl(sym);
    if (!cipher) {
        return false;
    }

    const unsigned char iv[512] = { 0 };

    if (((unsigned long) EVP_CIPHER_iv_length(cipher)) > sizeof(iv)) {
        printf("IV size is bigger then IV buffer size");
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int rc = EVP_EncryptInit_ex(ctx, cipher, NULL, encryption_key, iv);
    if (!rc) {
        return false;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t *bufs[2] = { buf1, buf2 };

    size_t lens[ARRAY_LEN(bufs)] = { buf1_len, buf2_len };

    unsigned i;
    for (i = 0; i < ARRAY_LEN(bufs); i++) {

        uint8_t *b = bufs[i];
        size_t l = lens[i];

        if (!b) {
            continue;
        }

        int output_len = total_len - offset;

        rc = EVP_EncryptUpdate(ctx, &cipher_text->buffer[offset], &output_len,
                b, l);
        if (!rc) {
            printf("Encrypt failed");
            goto out;
        }

        offset += l;
    }

    int tmp_len = 0;
    rc = EVP_EncryptFinal_ex(ctx, NULL, &tmp_len);
    if (!rc) {
        printf("Encrypt failed final \n");
        goto out;
    }

    cipher_text->size = total_len;

    result = true;

out:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

bool tpm2_identity_util_calculate_inner_integrity(TPMI_ALG_HASH name_alg,
        TPM2B_SENSITIVE *sensitive, TPM2B_NAME *pubname,
        TPM2B_DATA *enc_sensitive_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_inner_integrity) {

    TSS2_RC rval;

    //Marshal sensitive area
    uint8_t buffer_marshalled_sensitiveArea[TPM2_MAX_DIGEST_BUFFER] = { 0 };
    size_t marshalled_sensitive_size = 0;
    rval = Tss2_MU_TPMT_SENSITIVE_Marshal(&sensitive->sensitiveArea,
            buffer_marshalled_sensitiveArea + sizeof(uint16_t),
            TPM2_MAX_DIGEST_BUFFER, &marshalled_sensitive_size);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing the sensitive data");
        return false;
    }

    size_t marshalled_sensitive_size_info = 0;
    rval = Tss2_MU_UINT16_Marshal(marshalled_sensitive_size,
            buffer_marshalled_sensitiveArea, sizeof(uint16_t),
            &marshalled_sensitive_size_info);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing the sensitive size");
        return false;
    }

    //concatenate NAME
    memcpy(buffer_marshalled_sensitiveArea + marshalled_sensitive_size +
        marshalled_sensitive_size_info, pubname->name, pubname->size);

    //Digest marshalled-sensitive || name
    uint8_t *marshalled_sensitive_and_name_digest =
            buffer_marshalled_sensitiveArea + marshalled_sensitive_size
                    + marshalled_sensitive_size_info + pubname->size;
    size_t digest_size_info = 0;
    UINT16 hash_size = tpm2_alg_util_get_hash_size(name_alg);
    rval = Tss2_MU_UINT16_Marshal(hash_size, marshalled_sensitive_and_name_digest,
            sizeof(uint16_t), &digest_size_info);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing the name size");
        return false;
    }

    const EVP_MD *md = tpm2_openssl_md_from_tpmhalg(name_alg);
    if (!md) {
        printf("Algorithm not supported: %x", name_alg);
        return false;
    }
    int rc = EVP_Digest(buffer_marshalled_sensitiveArea,
                        marshalled_sensitive_size_info + marshalled_sensitive_size
                            + pubname->size,
                        marshalled_sensitive_and_name_digest + digest_size_info,
                        NULL, md, NULL);
    if (!rc) {
        printf("Hash calculation failed");
        return false;
    }

    //Inner integrity
    encrypted_inner_integrity->size = marshalled_sensitive_size_info
            + marshalled_sensitive_size + pubname->size;

    return aes_encrypt_buffers(sym_alg, enc_sensitive_key->buffer,
            marshalled_sensitive_and_name_digest, hash_size + digest_size_info,
            buffer_marshalled_sensitiveArea,
            marshalled_sensitive_size_info + marshalled_sensitive_size,
            encrypted_inner_integrity);
}

static void hmac_outer_integrity(TPMI_ALG_HASH parent_name_alg,
        uint8_t *buffer1, uint16_t buffer1_size, uint8_t *buffer2,
        uint16_t buffer2_size, uint8_t *hmac_key,
        TPM2B_DIGEST *outer_integrity_hmac) {

    uint8_t to_hmac_buffer[TPM2_MAX_DIGEST_BUFFER];
    memcpy(to_hmac_buffer, buffer1, buffer1_size);
    memcpy(to_hmac_buffer + buffer1_size, buffer2, buffer2_size);
    uint32_t size = 0;

    UINT16 hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    HMAC(tpm2_openssl_md_from_tpmhalg(parent_name_alg), hmac_key, hash_size,
            to_hmac_buffer, buffer1_size + buffer2_size,
            outer_integrity_hmac->buffer, &size);
    outer_integrity_hmac->size = size;
}

void tpm2_identity_util_calculate_outer_integrity(TPMI_ALG_HASH parent_name_alg,
        TPM2B_NAME *pubname, TPM2B_MAX_BUFFER *marshalled_sensitive,
        TPM2B_MAX_BUFFER *protection_hmac_key,
        TPM2B_MAX_BUFFER *protection_enc_key, TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //Calculate dupSensitive
    encrypted_duplicate_sensitive->size = marshalled_sensitive->size;

    aes_encrypt_buffers(sym_alg, protection_enc_key->buffer,
            marshalled_sensitive->buffer, marshalled_sensitive->size,
            NULL, 0, encrypted_duplicate_sensitive);
    //Calculate outerHMAC
    hmac_outer_integrity(parent_name_alg, encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size, pubname->name, pubname->size,
            protection_hmac_key->buffer, outer_hmac);
}

static bool create_import_key_private_data(TPM2B_PRIVATE *private,
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    private->size = sizeof(parent_hash_size) + parent_hash_size
            + encrypted_duplicate_sensitive->size;

    size_t hmac_size_offset = 0;
    TSS2_RC rval = Tss2_MU_UINT16_Marshal(parent_hash_size, private->buffer,
            sizeof(parent_hash_size), &hmac_size_offset);
    if (rval != TPM2_RC_SUCCESS)
    {
        printf("Error serializing parent hash size");
        return false;
    }

    memcpy(private->buffer + hmac_size_offset, outer_hmac->buffer,
            parent_hash_size);
    memcpy(private->buffer + hmac_size_offset + parent_hash_size,
            encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size);

    return true;
}

typedef struct tpm2_session tpm2_session;

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object {
    TPM2_HANDLE handle;
    ESYS_TR tr_handle;
    const char *path;
    tpm2_session *session;
};

tool_rc tpm2_import(ESYS_CONTEXT *esys_context, tpm2_loaded_object *parent_obj,
        const TPM2B_DATA *encryption_key, const TPM2B_PUBLIC *object_public,
        const TPM2B_PRIVATE *duplicate, const TPM2B_ENCRYPTED_SECRET *in_sym_seed,
        const TPMT_SYM_DEF_OBJECT *symmetric_alg, TPM2B_PRIVATE **out_private,
        TPM2B_DIGEST *cp_hash, ESYS_TR new_parent, ESYS_TR *rsa_key) {

    // ESYS_TR parentobj_shandle = ESYS_TR_NONE;
    // tool_rc rc = tpm2_auth_util_get_shandle(esys_context, parent_obj->tr_handle,
    //         parent_obj->session, &parentobj_shandle);
    // if (rc != tool_rc_success) {
    //     LOG_ERR("Couldn't get shandle for phandle");
    //     return rc;
    // }

//     if (cp_hash) {
//         /*
//          * Need sys_context to be able to calculate CpHash
//          */
//         TSS2_SYS_CONTEXT *sys_context = NULL;
//         rc = tpm2_getsapicontext(esys_context, &sys_context);
//         if(rc != tool_rc_success) {
//             LOG_ERR("Failed to acquire SAPI context.");
//             return rc;
//         }

//         TSS2_RC rval = Tss2_Sys_Import_Prepare(sys_context,
//             parent_obj->handle, encryption_key, object_public, duplicate,
//             in_sym_seed, symmetric_alg);
//         if (rval != TPM2_RC_SUCCESS) {
//             LOG_PERR(Tss2_Sys_Import_Prepare, rval);
//             return tool_rc_general_error;
//         }

//         TPM2B_NAME *name1 = NULL;
//         rc = tpm2_tr_get_name(esys_context, parent_obj->tr_handle, &name1);
//         if (rc != tool_rc_success) {
//             goto tpm2_import_free_name1;
//         }

//         cp_hash->size = tpm2_alg_util_get_hash_size(
//             tpm2_session_get_authhash(parent_obj->session));
//         rc = tpm2_sapi_getcphash(sys_context, name1, NULL, NULL,
//             tpm2_session_get_authhash(parent_obj->session), cp_hash);

//         /*
//          * Exit here without making the ESYS call since we just need the cpHash
//          */
// tpm2_import_free_name1:
//         Esys_Free(name1);
//         goto tpm2_import_skip_esapi_call;
//     }

    TPM2_RC rval = Esys_Import(esys_context, new_parent,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, encryption_key,
            object_public, duplicate, in_sym_seed, symmetric_alg, out_private);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Esys_Import error: (0x%X) - %s\n", rval, Tss2_RC_Decode(rval));
		exit(1);        
    }

    // load imported key
	rval = Esys_Load(esys_context,
			new_parent,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,
			*out_private,
			object_public,
			rsa_key);
	if (rval != TSS2_RC_SUCCESS) {
        printf("Esys_Load error: (0x%X) - %s\n", rval, Tss2_RC_Decode(rval));
		exit(1);
	}    

tpm2_import_skip_esapi_call:
    return rval;
}

static tool_rc key_import(ESYS_CONTEXT *ectx, TPM2B_PUBLIC *parent_pub,
        TPM2B_SENSITIVE *privkey, TPM2B_PUBLIC *pubkey,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        TPM2B_PRIVATE **imported_private, ESYS_TR new_parent, ESYS_TR *rsa_key) {

    TPMI_ALG_HASH name_alg = pubkey->publicArea.nameAlg;

    TPM2B_DIGEST *seed = &privkey->sensitiveArea.seedValue;

    /*
     * Create the protection encryption key that gets encrypted with the parents public key.
     */
    TPM2B_DATA enc_sensitive_key = {
        .size = parent_pub->publicArea.parameters.rsaDetail.symmetric.keyBits.sym / 8
    };

    if(enc_sensitive_key.size < 16) {
        printf("Calculated wrapping keysize is less than 16 bytes, got: %u", enc_sensitive_key.size);
        return tool_rc_general_error;
    }

    int ossl_rc = RAND_bytes(enc_sensitive_key.buffer, enc_sensitive_key.size);
    if (ossl_rc != 1) {
        printf("RAND_bytes failed: %s", ERR_error_string(ERR_get_error(), NULL));
        return tool_rc_general_error;
    }

    /*
     * Calculate the object name.
     */
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    bool res = tpm2_identity_create_name(pubkey, &pubname);
    if (!res) {
        return tool_rc_general_error;
    }

    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    res = tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            parent_pub, &pubname, seed, &hmac_key, &enc_key);
    if (!res) {
        return tool_rc_general_error;
    }

    TPM2B_MAX_BUFFER encrypted_inner_integrity = TPM2B_EMPTY_INIT;
    res = tpm2_identity_util_calculate_inner_integrity(name_alg, privkey, &pubname,
            &enc_sensitive_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_inner_integrity);
    if (!res) {
        return tool_rc_general_error;
    }

    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(parent_pub->publicArea.nameAlg,
            &pubname, &encrypted_inner_integrity, &hmac_key, &enc_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_duplicate_sensitive, &outer_hmac);

    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    res = create_import_key_private_data(&private, parent_pub->publicArea.nameAlg,
            &encrypted_duplicate_sensitive, &outer_hmac);
    if (!res) {
        return tool_rc_general_error;
    }

    TPMT_SYM_DEF_OBJECT *sym_alg =
            &parent_pub->publicArea.parameters.rsaDetail.symmetric;

//    if (!ctx.cp_hash_path) {
    return tpm2_import(ectx, NULL, &enc_sensitive_key, pubkey,
            &private, encrypted_seed, sym_alg, imported_private, NULL, new_parent, rsa_key);
//    }

    // TPM2B_DIGEST cp_hash = { .size = 0 };
    // tool_rc rc = tpm2_import(ectx, &ctx.parent.object, &enc_sensitive_key, pubkey,
    //         &private, encrypted_seed, sym_alg, imported_private, &cp_hash);
    // if (rc != tool_rc_success) {
    //     return rc;
    // }

    // bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    // if (!result) {
    //     rc = tool_rc_general_error;
    // }
    // return rc;
}

void openssl_import(ESYS_CONTEXT *ectx, ESYS_TR new_parent, ESYS_TR *rsa_key, char *hierarchy, char *key_handle, char *key_auth, char *input_key) {

	printf("keyhandle:%s, keyauth:%s\n", key_handle, key_auth);

    bool free_ppub = false;
    tool_rc tmp_rc;
    tool_rc rc = tool_rc_general_error;
    TPM2B_PUBLIC ppub = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *parent_pub = NULL;
    bool result;    

    tmp_rc = readpublic(ectx, new_parent, &parent_pub);
    free_ppub = true;
    result = tmp_rc == tool_rc_success;

    if (!result) {
        printf("Failed loading parent key public.\n");
        exit (1);
    }

    TPM2B_SENSITIVE private = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;    

    TPMA_OBJECT attrs = 0;
    char *object_alg = "rsa"; // hard-coded algorithm rsa (-G rsa)
    if (1) {
        setup_default_attrs(&attrs, 0, 1, object_alg);
    }

    /*
     * Backwards Compat: the tool sets name-alg by default to the parent name alg if not specified
     * but the tpm2_alg_util_public_init defaults to sha256. Specify the alg if not specified.
     */
    char *name_alg;
    if (!name_alg) {
        name_alg = (char *)tpm2_alg_util_algtostr(parent_pub->publicArea.nameAlg,
                tpm2_alg_util_flags_hash);
        if (!name_alg) {
            printf("Invalid parent name algorithm, got 0x%x\n",
                    parent_pub->publicArea.nameAlg);
            exit (1);
        }
    }

    TPM2B_PUBLIC template = { 0 };
    rc = tpm2_alg_util_public_init(object_alg, name_alg,
        NULL, NULL, attrs, &template);
    if (rc != tool_rc_success) {
        exit (1);
    }

    result = tpm2_openssl_import_keys(
        parent_pub,
        &encrypted_seed,
        key_auth,
        input_key,
        NULL, // passin = NULL
        &template,
        &private,
        &public
    );
    if (!result) {
        exit (1);
    }

    TPM2B_PRIVATE *imported_private = NULL;
    tmp_rc = key_import(ectx, parent_pub, &private, &public, &encrypted_seed,
            &imported_private, new_parent, rsa_key);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        goto keyout;
    }

keyout:
//    Esys_Free(imported_private);
out:
    if (free_ppub) {
        Esys_Free(parent_pub);
    }

//    return rc;    
}

int main(int argc, char *argv[]) {

    if (argc < 7) {
        printf("Usage: esapi_import_persist_openssl_key hierarchy hierarchyauth keyHandle keyauth input_key tcti (e.g.: esapi_import_persist_openssl_key o ownerauth 0x81000005 password priv.pem mssim)\n   Notes: Set hierarchy or key auth = NULL if no password needed\n");
        return 1;
    }

    /* Prepare TCTI context */
    const char *tcti_name = argv[6];
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
		fprintf(stderr, "TR_SetAuth error: 0x%x\n", rv);
		return 1;
	}

    // Create primary
	ESYS_TR parent = ESYS_TR_NONE;
	create_primary(ectx, &parent, argv[1]);

    // import and load external key
	ESYS_TR rsa_key = ESYS_TR_NONE;
	openssl_import(ectx, parent, &rsa_key, argv[1], argv[3], argv[4], argv[5]);

    printf("Done import_and_load_rsa_key\n");    

	TPMI_DH_PERSISTENT persist_handle;	
    bool result = tpm2_util_string_to_uint32(argv[3], &persist_handle);
    if (!result) {
        fprintf(stderr, "Could not convert persistent handle to a number\n");
        exit(1);
    } else {
		printf("persist_handle: %#x\n", persist_handle);
	}

    // Persist imported key
    ESYS_TR out_tr;
    rv = Esys_EvictControl (ectx,
            hierarchy_choice,
            rsa_key,
			ESYS_TR_PASSWORD,
			ESYS_TR_NONE,
			ESYS_TR_NONE,    
			persist_handle,
			&out_tr);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_EvictControl error: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		exit(1);
	}

    // flush all transient objects
    rv = Esys_FlushContext(ectx, parent);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext error - parent: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		exit(1);
	}    

    rv = Esys_FlushContext(ectx, rsa_key);
    if (rv != TSS2_RC_SUCCESS) {
        printf("Esys_FlushContext error - rsa_key: (0x%X) - %s\n", rv, Tss2_RC_Decode(rv));
		exit(1);
	}

	Esys_Finalize(&ectx);

	return 0;
}

