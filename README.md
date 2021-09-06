# ngx_http_auth_jwt_module
Based on https://github.com/RekGRpth/nginx-jwt-module

## Module:

### Example Configuration:
```nginx
server {
    auth_jwt_key "0123456789abcdef" hex; # Your key as hex string
    auth_jwt     off;

    location /secured-by-cookie/ {
        auth_jwt $cookie_MyCookieName;
    }

    location /secured-by-auth-header/ {
        auth_jwt on;
    }

    location /secured-by-auth-header-too/ {
        auth_jwt_key "another-secret"; # Your key as utf8 string
        auth_jwt on;
    }

    location /secured-by-rsa-key/ {
        auth_jwt_key /etc/keys/rsa-public.pem file; # Your key from a PEM file
        auth_jwt on;
    }

    location /not-secure/ {}
}
```

> Note: don't forget to [load](http://nginx.org/en/docs/ngx_core_module.html#load_module) the module in the main context: <br>`load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;`

### Directives:

    Syntax:	 auth_jwt $variable | on | off;
    Default: auth_jwt off;
    Context: http, server, location

Enables validation of JWT.<hr>

    Syntax:	 auth_jwt_key value [encoding];
    Default: ——
    Context: http, server, location

Specifies the key for validating JWT signature (must be hexadecimal).<br>
The *encoding* otpion may be `hex | utf8 | base64 | file` (default is `utf8`).<br>
The `file` option requires the *value* to be a valid file path (pointing to a PEM encoded key).

<hr>

    Syntax:	 auth_jwt_alg any | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512;
    Default: auth_jwt_alg any;
    Context: http, server, location

Specifies which algorithm the server expects to receive in the JWT.

### Embedded Variables:

Module supports embedded variables:

    $jwt_header

returns whole header

    $jwt_grant

returns whole grant

    $jwt_header_name

returns header.name

    $jwt_grant_name

returns grant.name
