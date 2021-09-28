#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

//TODO: move consts to config
#define MIN_INCOME_JWT_TOKEN_SIZE_BYTES (4U+1U+4U+1U+1U) // len(b64('{}')) + len('.')  +   len(b64('{}')) + len('.') + one_sig_byte
#define MAX_INCOME_JWT_TOKEN_SIZE_BYTES (2*1024)

//TODO: move consts to config
#define MAX_JWT_HEADER_MAX_MEM ((size_t)1*1048)
#define MAX_JWT_BODY_MAX_MEM ((size_t)8*1024)


typedef struct {
    ngx_flag_t enable;
} ngx_http_auth_jwt_main_conf_t;

typedef struct {
    ngx_str_t jwt_key;          // Forwarded key (with auth_jwt_key) - array of bytes

    EVP_PKEY *jwt_key_evp;       // decoded (if can) key as EVP_PKEY. NULL if cant decode
    int jwt_key_evp_type;        // decoded (if can) key as EVP_PKEY type. 0 if cant decode

    ngx_uint_t jwt_algorithm;   // allowed JWT_ALG_xxx bitmask
    ngx_str_t jwt_kid;          // JWT kid of that key
} ngx_http_auth_jwt_key_t;

typedef struct {
    ngx_uint_t jwt_bypass_methods;      // HTTP methods names mask
    ngx_int_t jwt_flag;                 // Function of "auth_jwt": on -> 1 | off -> 0 | $variable -> 2
    ngx_int_t jwt_var_index;            // Used only if jwt_flag==2 to fetch the $variable value
    ngx_array_t *jwt_keys;              // arrayOf(*ngx_http_auth_jwt_key_t)
} ngx_http_auth_jwt_loc_conf_t;

#define NGX_HTTP_AUTH_JWT_OFF        0
#define NGX_HTTP_AUTH_JWT_BEARER     1
#define NGX_HTTP_AUTH_JWT_VARIABLE   2

#define NGX_HTTP_AUTH_JWT_ENCODING_HEX     0
#define NGX_HTTP_AUTH_JWT_ENCODING_BASE64  1
#define NGX_HTTP_AUTH_JWT_ENCODING_UTF8    2
#define NGX_HTTP_AUTH_JWT_ENCODING_FILE    3

#include "jwt.c"

typedef struct {
    u_char *name;
    uint32_t value;
} ngx_http_auth_jwt_kvp_ui32_t;

//#region supported jwt algorithms
static ngx_http_auth_jwt_kvp_ui32_t ngx_http_auth_jwt_algorithms[] = {
        {(u_char *) ("HS256"), JWT_ALG_HS256},
        {(u_char *) ("HS384"), JWT_ALG_HS384},
        {(u_char *) ("HS512"), JWT_ALG_HS512},
        {(u_char *) ("RS256"), JWT_ALG_RS256},
        {(u_char *) ("RS384"), JWT_ALG_RS384},
        {(u_char *) ("RS512"), JWT_ALG_RS512},
        {(u_char *) ("ES256"), JWT_ALG_ES256},
        {(u_char *) ("ES384"), JWT_ALG_ES384},
        {(u_char *) ("ES512"), JWT_ALG_ES512},
        {(u_char *) ("any"),   JWT_ALG_ANY},
        {NULL,                 JWT_ALG_NONE}
};
//#endregion

//#region ngx http methods
static ngx_http_auth_jwt_kvp_ui32_t ngx_methods_names[] = {
        {(u_char *) "GET",       (uint32_t) NGX_HTTP_GET},
        {(u_char *) "HEAD",      (uint32_t) NGX_HTTP_HEAD},
        {(u_char *) "POST",      (uint32_t) NGX_HTTP_POST},
        {(u_char *) "PUT",       (uint32_t) NGX_HTTP_PUT},
        {(u_char *) "DELETE",    (uint32_t) NGX_HTTP_DELETE},
        {(u_char *) "MKCOL",     (uint32_t) NGX_HTTP_MKCOL},
        {(u_char *) "COPY",      (uint32_t) NGX_HTTP_COPY},
        {(u_char *) "MOVE",      (uint32_t) NGX_HTTP_MOVE},
        {(u_char *) "OPTIONS",   (uint32_t) NGX_HTTP_OPTIONS},
        {(u_char *) "PROPFIND",  (uint32_t) NGX_HTTP_PROPFIND},
        {(u_char *) "PROPPATCH", (uint32_t) NGX_HTTP_PROPPATCH},
        {(u_char *) "LOCK",      (uint32_t) NGX_HTTP_LOCK},
        {(u_char *) "UNLOCK",    (uint32_t) NGX_HTTP_UNLOCK},
        {(u_char *) "PATCH",     (uint32_t) NGX_HTTP_PATCH},
        {NULL,                   (uint32_t) 0UL}
};
//#endregion

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);

// Configuration functions
static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);

static void *ngx_http_auth_jwt_create_main_conf(ngx_conf_t *cf);

static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

// Declaration functions
static char *ngx_conf_set_auth_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_conf_set_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_conf_set_auth_jwt_bypass_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

#ifdef SUPPORT_NGX_VARS
static ngx_int_t ngx_http_auth_jwt_header_json(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_jwt_grant_json(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_jwt_header_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_auth_jwt_grant_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
#endif

//#region commands definitions
static ngx_command_t ngx_http_auth_jwt_commands[] = {

        // auth_jwt_key value [hex | base64 | utf8 | file] [HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512];
        {ngx_string("auth_jwt_key"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234,
         ngx_conf_set_auth_jwt_key,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        // auth_jwt $variable | off | on;
        {ngx_string("auth_jwt"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_auth_jwt,
         NGX_HTTP_LOC_CONF_OFFSET,
         0,
         NULL},

        // auth_jwt_bypass_methods method1 [, ...];
        {ngx_string("auth_jwt_bypass_methods"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
         ngx_conf_set_auth_jwt_bypass_methods,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_bypass_methods),
         NULL},

        ngx_null_command
};
//#endregion

#ifdef SUPPORT_NGX_VARS
//#region vars definitions
static ngx_http_variable_t ngx_http_auth_jwt_variables[] = {
        {
                ngx_string("jwt_header"),
                NULL,
                ngx_http_auth_jwt_header_json,
                0,
                NGX_HTTP_VAR_CHANGEABLE,
                0
        },
        {
                ngx_string("jwt_grant"),
                NULL,
                ngx_http_auth_jwt_grant_json,
                0,
                NGX_HTTP_VAR_CHANGEABLE,
                0
        },
        {
                ngx_string("jwt_header_"),
                NULL,
                ngx_http_auth_jwt_header_var,
                0,
                NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_PREFIX,
                0
        },
        {
                ngx_string("jwt_grant_"),
                NULL,
                ngx_http_auth_jwt_grant_var,
                0,
                NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_PREFIX,
                0
        },
        {
                ngx_null_string,
                NULL,
                NULL,
                0,
                0,
                0
        },
};
//#endregion
#endif

//#region module declaration stuff
static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
        ngx_http_auth_jwt_add_variables, /* preconfiguration */
        ngx_http_auth_jwt_init,      /* postconfiguration */

        ngx_http_auth_jwt_create_main_conf, /* create main configuration */
        NULL,                               /* init main configuration */

        NULL,                               /* create server configuration */
        NULL,                               /* merge server configuration */

        ngx_http_auth_jwt_create_loc_conf,  /* create location configuration */
        ngx_http_auth_jwt_merge_loc_conf    /* merge location configuration */
};


ngx_module_t ngx_http_auth_jwt_module = {
        NGX_MODULE_V1,
        &ngx_http_auth_jwt_module_ctx,     /* module context */
        ngx_http_auth_jwt_commands,        /* module directives */
        NGX_HTTP_MODULE,                   /* module type */
        NULL,                              /* init master */
        NULL,                              /* init module */
        NULL,                              /* init process */
        NULL,                              /* init thread */
        NULL,                              /* exit thread */
        NULL,                              /* exit process */
        NULL,                              /* exit master */
        NGX_MODULE_V1_PADDING
};
//#endregion

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r) {
    const ngx_http_auth_jwt_loc_conf_t *conf;
    ngx_uint_t i;
    jwt_t *jwt;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

    // Pass through if "auth_jwt" is "off"
    if (conf->jwt_flag == NGX_HTTP_AUTH_JWT_OFF) {
        return NGX_DECLINED;
    }

    // Pass through some requests without token authentication
    if ((conf->jwt_bypass_methods & r->method) == r->method) {
        return NGX_DECLINED;
    }

    if (conf->jwt_keys == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JWT: unable to process request: no keys in config");
        return NGX_ERROR;
    }

    // Init from raw jwt. Note: jwt_init use ngx_palloc, and nginx cleanup mem at request end
    if (jwt_init(r, conf, &jwt) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
        return NGX_HTTP_UNAUTHORIZED;
    }

    jwt_header_wkp_t jwt_hwkp = {
            .kid = ngx_null_string,
            .alg = JWT_ALG_NONE
    };

    if (jwt_decode_header(r, jwt, &jwt_hwkp)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to parse jwt header");
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (jwt_hwkp.alg == JWT_ALG_NONE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "JWT: unsupported jwt alg or alg not set or alg set to none");
        return NGX_HTTP_UNAUTHORIZED;
    }

    jwt_body_wkp_t jwt_bwkp = {
            .nbf = 0,
            .exp = 0
    };
    if (jwt_decode_body(r, jwt, &jwt_bwkp)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to parse jwt body");
        return NGX_HTTP_UNAUTHORIZED;
    }

    // Validate the exp date of the JWT
    time_t exp = jwt_bwkp.exp;
    if (exp > 0 && exp < r->start_sec) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: the jwt has expired [exp=%ld]", (long) exp);
        return NGX_HTTP_UNAUTHORIZED;
    }

    // Validate the nbf date of the JWT
    if (jwt_bwkp.nbf > r->start_sec) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: the jwt has too new [nbf=%ld]", (long) jwt_bwkp.nbf);
        return NGX_HTTP_UNAUTHORIZED;
    }

    jwt_sign_wkp_t jwt_swkp;
    if (jwt_decode_sign(r, jwt, &jwt_swkp)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: failed to parse jwt sign");
        return NGX_HTTP_UNAUTHORIZED;
    }

    // Validate by keys
    const ngx_str_t *jwt_kid_data = &jwt_hwkp.kid;
    ngx_http_auth_jwt_key_t *keys = conf->jwt_keys->elts;
    if (jwt_kid_data->len > 0) {
        for (i = 0; i < conf->jwt_keys->nelts; i++) {
            ngx_http_auth_jwt_key_t *key = &keys[i];
            size_t conf_kid_len = key->jwt_kid.len;
            if (conf_kid_len == 0) {
                // ignore keys without kid
                continue;
            }

            // if jwt contains kid && conf_key too -> compare kid's
            if (conf_kid_len != jwt_kid_data->len) {
                continue;
            }
            if (ngx_memn2cmp(key->jwt_kid.data, jwt_kid_data->data, conf_kid_len, conf_kid_len) != 0) {
                continue;
            }

            // found key with same kid, now validate by that key

            // Validate the algorithm
            if ((key->jwt_algorithm & jwt_hwkp.alg) != jwt_hwkp.alg) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid algorithm in jwt: %d for key with kid",
                              jwt_hwkp.alg);
                return NGX_HTTP_UNAUTHORIZED;
            }

            // Validate sign
            if (jwt_verify(r, jwt, jwt_hwkp.alg, key, &jwt_swkp)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: jwt failed to validate sign");
                return NGX_HTTP_UNAUTHORIZED;
            } else {
                // Sign valid
                return NGX_OK;
            }
        }
    }

    for (i = 0; i < conf->jwt_keys->nelts; i++) {
        ngx_http_auth_jwt_key_t *key = &keys[i];

        if (jwt_kid_data->len > 0 && key->jwt_kid.len != 0) {
            // already checked
            continue;
        }

        // Try to validate the algorithm
        if ((key->jwt_algorithm & jwt_hwkp.alg) != jwt_hwkp.alg) {
            // this key not alower to use with token alg
            continue;
        }

        // Validate sign
        if (jwt_verify(r, jwt, jwt_hwkp.alg, key, &jwt_swkp)) {
            continue;
        } else {
            // Sign valid
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid jwt - none of configured keys can validate it");
    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_auth_jwt_main_conf_t *conf;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_jwt_module);
    if (!conf->enable) return NGX_OK;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_jwt_handler;

    return NGX_OK;
}


static void *ngx_http_auth_jwt_create_main_conf(ngx_conf_t *cf) {
    ngx_http_auth_jwt_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_main_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: conf==NULL");
        return NULL;
    }

    return conf;
}


static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_jwt_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: conf==NULL");
        return NULL;
    }

    // Initialize variables
    conf->jwt_flag = NGX_CONF_UNSET;
    conf->jwt_var_index = NGX_CONF_UNSET;
    conf->jwt_bypass_methods = NGX_CONF_UNSET_UINT;
    conf->jwt_keys = NULL;

    return conf;
}


static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    (void) cf;   //ignore unused-parameter
    ngx_http_auth_jwt_loc_conf_t *prev = parent;
    ngx_http_auth_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->jwt_var_index, prev->jwt_var_index, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->jwt_flag, prev->jwt_flag, NGX_HTTP_AUTH_JWT_OFF);
    ngx_conf_merge_uint_value(conf->jwt_bypass_methods, prev->jwt_bypass_methods, 0);

    if (conf->jwt_keys == NULL) {
        //TODO: merge array?
        conf->jwt_keys = prev->jwt_keys;
    }

    return NGX_CONF_OK;
}

// Convert an hexadecimal string to a binary string
static int hex_to_binary(u_char *dest, u_char *src, const size_t n) {
    size_t i;
    u_char *p = &dest[0];
    ngx_int_t dst;
    for (i = 0; i < n; i += 2) {
        dst = ngx_hextoi(&src[i], 2);

        if (dst == NGX_ERROR || dst > 255) {
            return NGX_ERROR;
        }

        *p++ = (u_char) dst;
    }

    return NGX_OK;
}

// Parse auth_jwt_key directive
static char *ngx_conf_set_auth_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    (void) cmd;   //ignore unused-parameter
    ngx_http_auth_jwt_loc_conf_t *ajlc = (ngx_http_auth_jwt_loc_conf_t *) conf;

    ngx_str_t *value;
    ngx_uint_t encoding;
    size_t i;
    ngx_http_auth_jwt_kvp_ui32_t *kvp;
    ngx_array_t *jwt_keys;
    ngx_http_auth_jwt_key_t *kv;

    jwt_keys = ajlc->jwt_keys;
    if (jwt_keys == NULL) {
        ajlc->jwt_keys = jwt_keys = ngx_array_create(cf->pool, 1, sizeof(ngx_http_auth_jwt_key_t));
        if (jwt_keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    kv = ngx_array_push(jwt_keys);
    if (kv == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_t *key = &kv->jwt_key;
    value = cf->args->elts;

    // If there is only the key string;
    if (cf->args->nelts == 2) {
        encoding = NGX_HTTP_AUTH_JWT_ENCODING_UTF8;
    }
        // We can have (auth_jwt_key $value $encoding [HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512] [kid])
    else if (cf->args->nelts >= 3) {
        if (ngx_strncmp(value[2].data, "file", 4) == 0) {
            encoding = NGX_HTTP_AUTH_JWT_ENCODING_FILE;
        } else if (ngx_strncmp(value[2].data, "hex", 3) == 0) {
            encoding = NGX_HTTP_AUTH_JWT_ENCODING_HEX;
        } else if (ngx_strncmp(value[2].data, "base64", 6) == 0) {
            encoding = NGX_HTTP_AUTH_JWT_ENCODING_BASE64;
        } else if (ngx_strncmp(value[2].data, "utf8", 4) == 0) {
            encoding = NGX_HTTP_AUTH_JWT_ENCODING_UTF8;
        } else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: unsupported key encoding");
            return NGX_CONF_ERROR;
        }

        // we have (auth_jwt_key $value $encoding $alg [kid])
        if (cf->args->nelts >= 4) {
            kv->jwt_algorithm = JWT_ALG_NONE;
            const size_t lA = value[3].len;
            const char *pC = (char *) value[3].data;
            const char *pP = (char *) value[3].data;
            i = 0;
            do {
                if (i == lA || *pC == ',') {
                    for (kvp = ngx_http_auth_jwt_algorithms; kvp->name; kvp++) {
                        if (ngx_strncmp(kvp->name, pP, pC - pP) == 0) {
                            pP = ++pC;
                            kv->jwt_algorithm |= kvp->value;
                            goto next;
                        }
                    }

                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                                       "JWT: unknown/unsupported JWT algorithm in module configuration");
                    return NGX_CONF_ERROR;
                }

                next:
                ++i;
                ++pC;
            } while (i <= lA);

            // we have  (auth_jwt_key $value $encoding $alg $kid)
            if (cf->args->nelts == 5) {
                kv->jwt_kid.len = value[4].len;
                kv->jwt_kid.data = value[4].data;
            } else {
                // no kid setup
                kv->jwt_kid.len = 0;
                kv->jwt_kid.data = NULL;
            }
        } else {
            // no one alg setup -> "any" by default
            kv->jwt_algorithm = JWT_ALG_ANY;
        }
    } else {
        return NGX_CONF_ERROR;
    }

    ngx_str_t *keystr = &value[1];

    if (keystr->len == 0 || keystr->data == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid key");
        return NGX_CONF_ERROR;
    }

    switch (encoding) {
        case NGX_HTTP_AUTH_JWT_ENCODING_HEX: {
            // Parse provided key
            if (keystr->len % 2) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid hex string");
                return NGX_CONF_ERROR;
            }

            key->data = ngx_palloc(cf->pool, keystr->len / 2);
            key->len = keystr->len / 2;

            if (hex_to_binary(key->data, keystr->data, keystr->len) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Failed to turn hex key into binary");
                return NGX_CONF_ERROR;
            }

            break;
        }
        case NGX_HTTP_AUTH_JWT_ENCODING_BASE64: {
            key->len = ngx_base64_decoded_length(keystr->len);
            key->data = ngx_palloc(cf->pool, key->len);

            if (ngx_decode_base64(key, keystr) != NGX_OK) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Failed to turn base64 key into binary");
                return NGX_CONF_ERROR;
            }

            break;
        }
        case NGX_HTTP_AUTH_JWT_ENCODING_UTF8: {
            key->data = keystr->data;
            key->len = keystr->len;
            break;
        }
        case NGX_HTTP_AUTH_JWT_ENCODING_FILE: {
            ngx_file_info_t fi;
            ngx_file_info(keystr->data, &fi);
            ngx_int_t st_size = ngx_file_size(&fi);

            ngx_fd_t fd = ngx_open_file(keystr->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
            if (fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                                   ngx_open_file_n " \"%s\" failed",
                                   keystr->data);
                return NGX_CONF_ERROR;
            }

            key->len = st_size;
            key->data = ngx_pcalloc(cf->pool, key->len);

            if (ngx_read_fd(fd, key->data, key->len) != (ssize_t) key->len) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "jwt_key file: unexpected end of file");
                ngx_close_file(fd);
                return NGX_CONF_ERROR;
            }

            ngx_close_file(fd);
            break;
        }
        default:
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: unsupported key encoding");
            return NGX_CONF_ERROR;
    }

    // setup defaults
    kv->jwt_key_evp_type = EVP_PKEY_NONE;
    kv->jwt_key_evp = NULL;

    // try to convert key to EVP
    BIO *bio = BIO_new_mem_buf(key->data, (int) key->len);
    if (bio != NULL) {
        /* This uses OpenSSL's default passphrase callback if needed. */
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);     //TODO: memleak - never free
        if (pkey != NULL) {
            kv->jwt_key_evp = pkey;
            kv->jwt_key_evp_type = EVP_PKEY_id(pkey);
        }
        BIO_free(bio);
    }

    return NGX_CONF_OK;
}

// Parse auth_jwt_bypass_methods
static char *ngx_conf_set_auth_jwt_bypass_methods(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_uint_t i;
    ngx_str_t *value;
    ngx_uint_t *jwt_bypass_methods = (ngx_uint_t *) ((char *) conf + cmd->offset);
    ngx_http_auth_jwt_kvp_ui32_t *kvp;

    *jwt_bypass_methods = 0;
    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; i++) {
        for (kvp = ngx_methods_names; kvp->name; kvp++) {

            if (ngx_strcasecmp(value[i].data, kvp->name) == 0) {
                *jwt_bypass_methods |= kvp->value;
                goto next;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid method \"%V\"", &value[i]);
        return NGX_CONF_ERROR;

        next:
        continue;
    }

    return NGX_CONF_OK;
}

// Parse auth_jwt directive
static char *ngx_conf_set_auth_jwt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    (void) cmd;
    ngx_http_auth_jwt_loc_conf_t *ajcf = conf;

    ngx_int_t *flag = &ajcf->jwt_flag;
    ngx_int_t *index = &ajcf->jwt_var_index;

    if (*flag != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    const ngx_str_t *value = cf->args->elts;

    const ngx_str_t var = value[1];

    if (var.len == 0) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid value");
        return NGX_CONF_ERROR;
    }

    // Check if enabled, if not: return conf.
    if (var.len == 3 && ngx_strncmp(var.data, "off", 3) == 0) {
        *flag = NGX_HTTP_AUTH_JWT_OFF;
    }
        // If enabled and "on" we will get token from "Authorization" header.
    else if (var.len == 2 && ngx_strncmp(var.data, "on", 2) == 0) {
        *flag = NGX_HTTP_AUTH_JWT_BEARER;
    }
        // Else we will get token from passed variable.
    else {
        *flag = NGX_HTTP_AUTH_JWT_VARIABLE;

        if (var.data[0] != '$') {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid variable name %s", var.data);
            return NGX_CONF_ERROR;
        }

        ngx_str_t str = {.data = var.data + 1, .len = var.len - 1};

        *index = ngx_http_get_variable_index(cf, &str);
        if (*index == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Can get index for {data: %s, len: %d}", var.data, var.len);
            return NGX_CONF_ERROR;
        }
    }

    ngx_http_auth_jwt_main_conf_t *mconf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_jwt_module);
    mconf->enable = 1;
    return NGX_CONF_OK;
}

#ifndef SUPPORT_NGX_VARS

static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf) {
    (void) cf;
    return NGX_OK;
}

#else
static ngx_int_t ngx_http_auth_jwt_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *v;
    for (v = ngx_http_auth_jwt_variables; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) return NGX_ERROR;
        *var = *v;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_auth_jwt_header_json(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    (void) data;   //ignore unused-parameter
    v->not_found = 1;
    return NGX_OK;
    /*jwt_t *jwt = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    if (!jwt) return NGX_OK;
    const char *value = jwt_get_headers_json(jwt, NULL);
    if (!value) return NGX_OK;
    v->data = (u_char *) value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;*/
}

static ngx_int_t ngx_http_auth_jwt_grant_json(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    (void) data;   //ignore unused-parameter
    v->not_found = 1;
    return NGX_OK;
    /*jwt_t *jwt = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    if (!jwt) return NGX_OK;
    const char *value = jwt_get_grants_json(jwt, NULL);
    if (!value) return NGX_OK;
    v->data = (u_char *) value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;*/
}

static ngx_int_t ngx_http_auth_jwt_header_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    return NGX_OK;
    /*jwt_t *jwt = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    if (!jwt) return NGX_OK;

    ngx_str_t *name = (ngx_str_t *) data;
    const char *header = (char *) auth_jwt_safe_string(r->pool, name->data + sizeof("jwt_header_") - 1, name->len - (sizeof("jwt_header_") - 1));

    const char *value = jwt_get_header(jwt, header);
    if (!value) value = jwt_get_headers_json(jwt, header);
    if (!value) return NGX_OK;
    v->data = (u_char *) value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;*/
}

static ngx_int_t ngx_http_auth_jwt_grant_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    v->not_found = 1;
    return NGX_OK;
    /*jwt_t *jwt = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    if (!jwt) return NGX_OK;

    ngx_str_t *name = (ngx_str_t *) data;
    const char *grant = (char *) auth_jwt_safe_string(r->pool, name->data + sizeof("jwt_grant_") - 1, name->len - (sizeof("jwt_grant_") - 1));

    const char *value = jwt_get_grant(jwt, grant);
    if (!value) value = jwt_get_grants_json(jwt, grant);
    if (!value) return NGX_OK;
    v->data = (u_char *) value;
    v->len = ngx_strlen(value);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;*/
}
#endif

