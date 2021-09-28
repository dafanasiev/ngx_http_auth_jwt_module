#define json_char u_char
#define json_int_t ngx_int_t

#include "json-parser/json.h"
#include "json-parser/json.c"

#define MIN_BASE64_PADDING_SIZE 0
#define MAX_BASE64_PADDING_SIZE 2
#define MIN_JWT_SIGN_SIZE_BYTES (ngx_base64_encoded_length(256/8) - MAX_BASE64_PADDING_SIZE)    //url base64 encoding strip off padding
#define MAX_JWT_SIGN_SIZE_BYTES 512

#define JWT_ALG_NONE  0UL
#define JWT_ALG_HS256 1UL<<1UL
#define JWT_ALG_HS384 1UL<<2UL
#define JWT_ALG_HS512 1UL<<3UL
#define JWT_ALG_RS256 1UL<<4UL
#define JWT_ALG_RS384 1UL<<5UL
#define JWT_ALG_RS512 1UL<<6UL
#define JWT_ALG_ES256 1UL<<7UL
#define JWT_ALG_ES384 1UL<<8UL
#define JWT_ALG_ES512 1UL<<9UL
#define JWT_ALG_ANY (JWT_ALG_HS256|\
                     JWT_ALG_HS384|\
                     JWT_ALG_HS512|\
                     JWT_ALG_RS256|\
                     JWT_ALG_RS384|\
                     JWT_ALG_RS512|\
                     JWT_ALG_ES256|\
                     JWT_ALG_ES384|\
                     JWT_ALG_ES512)

typedef struct {
    uint32_t alg;
    ngx_str_t kid;
} jwt_header_wkp_t;

typedef struct {
    time_t nbf;
    time_t exp;
} jwt_body_wkp_t;

typedef struct {
    u_char sign_bytes[MAX_JWT_SIGN_SIZE_BYTES];
    size_t sign_bytes_len;

#if OPENSSL_VERSION_NUMBER>=0x10100000L     //1.1.0+
    u_char *ecdsa_sign_bytes;  //fill in runtime when check ECkeys
    size_t ecdsa_sign_bytes_len;
#endif
} jwt_sign_wkp_t;

typedef struct {
    ngx_str_t origin_raw;   //READ_ONLY: original http request jwt token
    ngx_str_t header_raw;   //READ_ONLY: pointer to origin_raw
    ngx_str_t body_raw;     //READ_ONLY: pointer to origin_raw
    ngx_str_t sign_raw;     //READ_ONLY: pointer to origin_raw
} jwt_t;

static void *js_mem_alloc(size_t n, int zero, void *user_data);

static void js_mem_free(void *p, void *user_data);

static ngx_int_t jwt_init(ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf, /*out*/ jwt_t **jwt);

static ngx_int_t jwt_decode_header(ngx_http_request_t *r, jwt_t *jwt, /*out*/ jwt_header_wkp_t *jwt_hwkp);

static ngx_int_t jwt_decode_body(ngx_http_request_t *r, jwt_t *jwt, /*out*/ jwt_body_wkp_t *jwt_bwkp);

static ngx_int_t jwt_decode_sign(ngx_http_request_t *r, jwt_t *jwt, /*out*/ jwt_sign_wkp_t *jwt_swkp);

static ulong jwt_str_alg(const u_char *alg, size_t len);

static size_t jwt_decode_base64url(u_char *d, const u_char *s, size_t slen);

static int jwt_verify(ngx_http_request_t *r,
                      jwt_t *jwt,
                      ngx_int_t jwt_alg,
                      ngx_http_auth_jwt_key_t *key,
                      jwt_sign_wkp_t *jwt_swkp);

static int jwt_verify_sha_hmac(ngx_http_request_t *r,
                               jwt_t *jwt,
                               ngx_int_t jwt_alg,
                               ngx_http_auth_jwt_key_t *key,
                               jwt_sign_wkp_t *jwt_swkp);

static int jwt_verify_sha_pem(ngx_http_request_t *r,
                              jwt_t *jwt,
                              ngx_int_t jwt_alg,
                              ngx_http_auth_jwt_key_t *key,
                              jwt_sign_wkp_t *jwt_swkp);
//-impl-

static void *js_mem_alloc(size_t n, int zero, void *user_data) {
    ngx_pool_t *pool = (ngx_pool_t *) user_data;
    void *rv;
    if (zero) {
        rv = ngx_pcalloc(pool, n);
    } else {
        rv = ngx_palloc(pool, n);
    }

    //printf("ALLOC: %p (%ld)\n", rv, n);
    return rv;
}

static void js_mem_free(void *p, void *user_data) {
    ngx_pool_t *pool = (ngx_pool_t *) user_data;
    ngx_pfree(pool, p);
    //printf("FREE : %p\n", p);
}

static ulong jwt_str_alg(const u_char *alg, size_t len) {
    if (alg == NULL)
        return JWT_ALG_NONE;

    if (len == 4) {
        if (!ngx_strncmp(alg, "none", 4))
            return JWT_ALG_NONE;
    }

    if (len == 5) {
        if (!ngx_strncmp(alg, "HS256", 5))
            return JWT_ALG_HS256;
        if (!ngx_strncmp(alg, "HS384", 5))
            return JWT_ALG_HS384;
        if (!ngx_strncmp(alg, "HS512", 5))
            return JWT_ALG_HS512;
        if (!ngx_strncmp(alg, "RS256", 5))
            return JWT_ALG_RS256;
        if (!ngx_strncmp(alg, "RS384", 5))
            return JWT_ALG_RS384;
        if (!ngx_strncmp(alg, "RS512", 5))
            return JWT_ALG_RS512;
        if (!ngx_strncmp(alg, "ES256", 5))
            return JWT_ALG_ES256;
        if (!ngx_strncmp(alg, "ES384", 5))
            return JWT_ALG_ES384;
        if (!ngx_strncmp(alg, "ES512", 5))
            return JWT_ALG_ES512;
    }

    return JWT_ALG_NONE;
}

// получаем токен из запроса  - базовые проверки что это потенциально jwt токен:
// - что в запросе имеется и не превышает лимитов
// - что имеет три компоненты
static ngx_int_t jwt_init(ngx_http_request_t *r,
                          const ngx_http_auth_jwt_loc_conf_t *conf,
                          jwt_t **jwt) {
    static const ngx_str_t bearer = ngx_string("Bearer ");
    const ngx_int_t flag = conf->jwt_flag;

    u_char *jwt_raw;
    size_t jwt_raw_len;

    if (flag == NGX_HTTP_AUTH_JWT_BEARER) {
        if (r->headers_in.authorization == NULL) {
            return NGX_DECLINED;
        }

        ngx_str_t header = r->headers_in.authorization->value;

        // If the "Authorization" header value is less than "Bearer X" length, there is no reason to continue.
        if (header.len < bearer.len + MIN_INCOME_JWT_TOKEN_SIZE_BYTES) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid authorization header length");
            return NGX_DECLINED;
        }
        // If the "Authorization" header does not starts with "Bearer ", return NULL.
        if (ngx_strncmp(header.data, bearer.data, bearer.len) != 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "JWT: Invalid authorization header content: only Bearer supported");
            return NGX_DECLINED;
        }

        jwt_raw_len = (size_t) header.len - bearer.len;
        jwt_raw = header.data + bearer.len;
    } else if (flag == NGX_HTTP_AUTH_JWT_VARIABLE) {
        ngx_http_variable_value_t *value = ngx_http_get_indexed_variable(r, conf->jwt_var_index);

        if (value == NULL || value->not_found != 0U || value->len < MIN_INCOME_JWT_TOKEN_SIZE_BYTES) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "JWT: Variable not found or empty or its value too small for jwt.");
            return NGX_DECLINED;
        }

        jwt_raw_len = value->len;
        jwt_raw = value->data;
    } else {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: Invalid flag [%d]", flag);
        return NGX_ERROR;
    }

    if (jwt_raw_len > MAX_INCOME_JWT_TOKEN_SIZE_BYTES) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "JWT: income token size [%d] is too big, max allowed: [%d] bytes", jwt_raw_len,
                      MAX_INCOME_JWT_TOKEN_SIZE_BYTES);
        return NGX_ERROR;
    }
    while (jwt_raw_len && (*jwt_raw == ' ' || *jwt_raw == '\t')) {
        --jwt_raw_len;
        ++jwt_raw;
    }
    if (jwt_raw_len < MIN_INCOME_JWT_TOKEN_SIZE_BYTES) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "JWT: income token size [%d] is too small, min allowed: [%d] bytes", jwt_raw_len,
                      MIN_INCOME_JWT_TOKEN_SIZE_BYTES);
        return NGX_DECLINED;
    }


    // Find the jwt components
    size_t headerEnd;
    size_t bodyEnd;
    for (headerEnd = 0; jwt_raw[headerEnd] != '.'; ++headerEnd) {
        if (headerEnd == jwt_raw_len) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: Invalid token: unable to detect head");
            return NGX_ERROR;
        }
    }
    for (bodyEnd = headerEnd + 1; jwt_raw[bodyEnd] != '.'; ++bodyEnd) {
        if (bodyEnd == jwt_raw_len) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: Invalid token: unable to detect body");
            return NGX_ERROR;
        }
    }

    size_t sign_size = jwt_raw_len - (bodyEnd + 1);
    if (sign_size < MIN_JWT_SIGN_SIZE_BYTES) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "JWT: Invalid token: sign too small, min allowed: %d, got: %d", MIN_JWT_SIGN_SIZE_BYTES,
                      sign_size);
        return NGX_ERROR;
    }
    if (sign_size > MAX_JWT_SIGN_SIZE_BYTES) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "JWT: Invalid token: sign too big, max allowed: %d, got: %d", MAX_JWT_SIGN_SIZE_BYTES, sign_size);
        return NGX_ERROR;
    }

    jwt_t *rv = ngx_pcalloc(r->pool, sizeof(jwt_t));

    rv->origin_raw.len = jwt_raw_len;
    rv->origin_raw.data = jwt_raw;

    rv->header_raw.len = headerEnd - 0;
    rv->header_raw.data = jwt_raw;

    rv->body_raw.len = bodyEnd - (headerEnd + 1);
    rv->body_raw.data = jwt_raw + (headerEnd + 1);

    rv->sign_raw.len = sign_size;
    rv->sign_raw.data = jwt_raw + (bodyEnd + 1);

    *jwt = rv;
    return NGX_OK;
}

static ngx_int_t jwt_decode_header(ngx_http_request_t *r,
                                   jwt_t *jwt,
                                   jwt_header_wkp_t *jwt_hwkp) {
    ngx_int_t i;

    ngx_str_t header;
    header.len = ngx_base64_decoded_length(jwt->header_raw.len);
    header.data = ngx_palloc(r->pool, header.len);
    if (header.data == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to mem alloc for header data");
        header.len = 0;
        return NGX_ERROR;
    }
    if (NGX_OK != ngx_decode_base64url(&header, &jwt->header_raw)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to decode header from base64url");
        return NGX_ERROR;
    }

    //decode
    json_settings jss = {
            .user_data = r->pool,
            .max_memory = MAX_JWT_HEADER_MAX_MEM,
            .mem_alloc = js_mem_alloc,
            .mem_free = js_mem_free,
            .settings = 0x0,
            .value_extra = 0
    };
    char jse[json_error_max];
    json_value *js = json_parse_ex(&jss, header.data, header.len, jse);
    if (js == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to json parse header: %s", jse);
        return NGX_ERROR;
    }
    if (js->type != json_object) {
        json_value_free_ex(&jss, js);
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: invalid header: json must be object");
        return NGX_ERROR;
    }

    for (i = 0; i < js->u.object.length; ++i) {
        json_object_entry *kvp = &js->u.object.values[i];
        if (kvp->value->type != json_string) {
            continue;
        }

        // interested keys
        if (kvp->name_length == 3) {
            if (ngx_strncmp(kvp->name, (u_char *) "kid", 3) == 0) {
                jwt_hwkp->kid.len = kvp->value->u.string.length;
                jwt_hwkp->kid.data = kvp->value->u.string.ptr;
            } else if (ngx_strncmp(kvp->name, (u_char *) "alg", 3) == 0) {
                jwt_hwkp->alg = jwt_str_alg(kvp->value->u.string.ptr, kvp->value->u.string.length);
            }
        }
    }

    //json_value_free_ex(&jss, js); //not need: we use ngx_palloc
    return NGX_OK;
}

static ngx_int_t jwt_decode_body(ngx_http_request_t *r,
                                 jwt_t *jwt,
                                 jwt_body_wkp_t *jwt_bwkp) {
    ngx_int_t i;

    ngx_str_t body;
    body.len = ngx_base64_decoded_length(jwt->body_raw.len);
    body.data = ngx_palloc(r->pool, body.len);
    if (body.data == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to mem alloc for body data");
        body.len = 0;
        return NGX_ERROR;
    }
    if (NGX_OK != ngx_decode_base64url(&body, &jwt->body_raw)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to decode body from base64url");
        return NGX_ERROR;
    }

    //decode
    json_settings jss = {
            .user_data = r->pool,
            .max_memory = MAX_JWT_BODY_MAX_MEM,
            .mem_alloc = js_mem_alloc,
            .mem_free = js_mem_free,
            .settings = 0x0,
            .value_extra = 0
    };
    char jse[json_error_max];
    json_value *js = json_parse_ex(&jss, body.data, body.len, jse);
    if (js == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to json parse body: %s", jse);
        return NGX_ERROR;
    }
    if (js->type != json_object) {
        json_value_free_ex(&jss, js);
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: invalid body: json must be object");
        return NGX_ERROR;
    }
    for (i = 0; i < js->u.object.length; ++i) {
        json_object_entry *kvp = &js->u.object.values[i];
        if (kvp->value->type != json_integer) {
            continue;
        }

        //interested keys
        if (kvp->name_length == 3) {
            if (ngx_strncmp(kvp->name, (u_char *) "nbf", 3) == 0) {
                jwt_bwkp->nbf = kvp->value->u.integer;
            } else if (ngx_strncmp(kvp->name, (u_char *) "exp", 3) == 0) {
                jwt_bwkp->exp = kvp->value->u.integer;
            }
        }
    }

    //json_value_free_ex(&jss, js); //not need: we use ngx_palloc
    return NGX_OK;
}

static ngx_int_t jwt_decode_sign(ngx_http_request_t *r,
                                 jwt_t *jwt,
                                 jwt_sign_wkp_t *jwt_swkp) {
    (void) r;
    size_t decodedLength = ngx_base64_decoded_length(jwt->sign_raw.len);
    if (decodedLength > sizeof(jwt_swkp->sign_bytes)) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "JWT: unable to decode sign: too big sign, decodedLength=%d, maxAllowedLength=%d",
                      decodedLength,
                      sizeof(jwt_swkp->sign_bytes));
        return NGX_ERROR;
    }

    jwt_swkp->sign_bytes_len = jwt_decode_base64url(jwt_swkp->sign_bytes, jwt->sign_raw.data, jwt->sign_raw.len);

#if OPENSSL_VERSION_NUMBER>=0x10100000L     //1.1.0+
    jwt_swkp->ecdsa_sign_bytes = NULL;
    jwt_swkp->ecdsa_sign_bytes_len = 0;
#endif

    return NGX_OK;
}

static int jwt_verify(ngx_http_request_t *r,
                      jwt_t *jwt,
                      ngx_int_t jwt_alg,
                      ngx_http_auth_jwt_key_t *key,
                      jwt_sign_wkp_t *jwt_swkp) {
    switch (jwt_alg) {
        /* HMAC */
        case JWT_ALG_HS256:
        case JWT_ALG_HS384:
        case JWT_ALG_HS512:
            return jwt_verify_sha_hmac(r, jwt, jwt_alg, key, jwt_swkp);

            /* RSA */
        case JWT_ALG_RS256:
        case JWT_ALG_RS384:
        case JWT_ALG_RS512:

            /* ECC */
        case JWT_ALG_ES256:
        case JWT_ALG_ES384:
        case JWT_ALG_ES512:
            return jwt_verify_sha_pem(r, jwt, jwt_alg, key, jwt_swkp);

            /* You wut, mate? */
        default:
            return EINVAL;
    }
}

static int jwt_verify_sha_hmac(ngx_http_request_t *r,
                               jwt_t *jwt,
                               ngx_int_t jwt_alg,
                               ngx_http_auth_jwt_key_t *key,
                               jwt_sign_wkp_t *jwt_swkp) {
    unsigned char calc_bytes[EVP_MAX_MD_SIZE];
    unsigned int calc_bytes_len;

    (void) r;

    const EVP_MD *alg;
    switch (jwt_alg) {
        case JWT_ALG_HS256:
            alg = EVP_sha256();
            break;
        case JWT_ALG_HS384:
            alg = EVP_sha384();
            break;
        case JWT_ALG_HS512:
            alg = EVP_sha512();
            break;
        default:
            return EINVAL;
    }

    HMAC(alg,
         key->jwt_key.data,
         (int) key->jwt_key.len,
         (const unsigned char *) jwt->origin_raw.data,
         jwt->header_raw.len + 1 + jwt->body_raw.len,
         calc_bytes,
         &calc_bytes_len);

    /* And now... */
    if (jwt_swkp->sign_bytes_len != calc_bytes_len) {
        return EINVAL;
    }
    if (ngx_memcmp(calc_bytes, jwt_swkp->sign_bytes, calc_bytes_len) != 0) {
        return EINVAL;
    };

    return 0;
}

static int jwt_verify_sha_pem(ngx_http_request_t *r,
                              jwt_t *jwt,
                              ngx_int_t jwt_alg,
                              ngx_http_auth_jwt_key_t *key,
                              jwt_sign_wkp_t *jwt_swkp) {
    unsigned char *sig = jwt_swkp->sign_bytes;
    if (sig == NULL) {
        // no signature
        return EINVAL;
    }
    int sig_len = (int) jwt_swkp->sign_bytes_len;

    if (key->jwt_key_evp_type == EVP_PKEY_NONE) {
        //non EVP key in config - can't verify using that key
        return EINVAL;
    }

    const EVP_MD *evp_alg;
    int evp_type;
    switch (jwt_alg) {
        /* RSA */
        case JWT_ALG_RS256:
            evp_alg = EVP_sha256();
            evp_type = EVP_PKEY_RSA;
            break;
        case JWT_ALG_RS384:
            evp_alg = EVP_sha384();
            evp_type = EVP_PKEY_RSA;
            break;
        case JWT_ALG_RS512:
            evp_alg = EVP_sha512();
            evp_type = EVP_PKEY_RSA;
            break;

            /* ECC */
        case JWT_ALG_ES256:
            evp_alg = EVP_sha256();
            evp_type = EVP_PKEY_EC;
            break;
        case JWT_ALG_ES384:
            evp_alg = EVP_sha384();
            evp_type = EVP_PKEY_EC;
            break;
        case JWT_ALG_ES512:
            evp_alg = EVP_sha512();
            evp_type = EVP_PKEY_EC;
            break;

        default:
            return EINVAL;
    }

    if (evp_type != key->jwt_key_evp_type) {
        //unable to verify by that key
        return EINVAL;
    }

    /* Convert EC sigs back to ASN1. */
    if (key->jwt_key_evp_type == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER>=0x10100000L     //1.1.0+
        if (jwt_swkp->ecdsa_sign_bytes == NULL) {
            int degree, bn_len;
            unsigned char *p;
            EC_KEY *ec_key;

            ECDSA_SIG *ec_sig = ECDSA_SIG_new();
            if (ec_sig == NULL) {
                return ENOMEM;
            }

            /* Get the actual ec_key */
            ec_key = EVP_PKEY_get1_EC_KEY(key->jwt_key_evp);
            if (ec_key == NULL) {
                ECDSA_SIG_free(ec_sig);
                return ENOMEM;
            }

            degree = EC_GROUP_get_degree(EC_KEY_get0_group(ec_key));

            EC_KEY_free(ec_key);

            bn_len = (degree + 7) / 8;
            if ((bn_len * 2) != sig_len) {
                ECDSA_SIG_free(ec_sig);
                return EINVAL;
            }

            BIGNUM *ec_sig_r = BN_bin2bn(sig, bn_len, NULL);
            BIGNUM *ec_sig_s = BN_bin2bn(sig + bn_len, bn_len, NULL);
            if (ec_sig_r == NULL || ec_sig_s == NULL) {
                ECDSA_SIG_free(ec_sig);
                return EINVAL;
            }

            ECDSA_SIG_set0(ec_sig, ec_sig_r, ec_sig_s);

            sig_len = i2d_ECDSA_SIG(ec_sig, NULL);
            sig = ngx_palloc(r->pool, sig_len);
            if (sig == NULL) {
                ECDSA_SIG_free(ec_sig);
                return ENOMEM;
            }

            p = sig;
            sig_len = i2d_ECDSA_SIG(ec_sig, &p);

            if (sig_len == 0) {
                ECDSA_SIG_free(ec_sig);
                return EINVAL;
            }

            jwt_swkp->ecdsa_sign_bytes = sig;
            jwt_swkp->ecdsa_sign_bytes_len = sig_len;
        } else {
            sig = jwt_swkp->ecdsa_sign_bytes;
            sig_len = (int) jwt_swkp->ecdsa_sign_bytes_len;
        }
#else
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to check by EC keys - you openssl version id too old");
        return EINVAL;
#endif
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        return ENOMEM;
    }


    /* Initialize the DigestVerify operation using evp_alg */
    if (EVP_DigestVerifyInit(mdctx, NULL, evp_alg, NULL, key->jwt_key_evp) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return EINVAL;
    }

    /* Call update with the message */
    if (EVP_DigestVerifyUpdate(mdctx,
                               (const unsigned char *) jwt->origin_raw.data,
                               jwt->header_raw.len + 1 + jwt->body_raw.len) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return EINVAL;
    }

    /* Now check the sig for validity. */
    if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1) {
        EVP_MD_CTX_destroy(mdctx);
        return EINVAL;
    }

    return NGX_OK;
}

static size_t jwt_decode_base64url(u_char *d, const u_char *s, size_t slen) {
    static u_char basis[] = {
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
            77, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
            77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
            77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    size_t len;
    u_char *pd;
    pd = d;

    for (len = 0; len < slen; len++) {
        if (s[len] == '=') {
            break;
        }

        if (basis[s[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    while (len > 3) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    return d - pd;
}
