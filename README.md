# ngx_http_auth_jwt_module
Based on https://github.com/RekGRpth/nginx-jwt-module

## Module:

### Directives:

    Syntax:	 auth_jwt $variable | on | off;
    Default: auth_jwt off;
    Context: http, server, location

Enables validation of JWT.

---
    Syntax:	 auth_jwt_key value [encoding] [algos] [kid];
    Default: ——
    Context: http, server, location

Specifies the key for validating JWT signature (must be hexadecimal).<br/>
The `encoding` option may be `hex | utf8 | base64 | file` (default is `utf8`).<br/>
The `file` option requires the `value` to be a valid file path (pointing to a PEM encoded key).<br/>
The `algos` options specifies which algorithms (defaults is `any`) the server expects to receive in the JWT (comma-separated string list). <br/>
- Example: `"HS256,HS384,HS512"` <br/>
- Supported: `any | HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512`

The `kid`, if present, specifies which kid ([RFC7515: 4.1.4. "kid" (Key ID) Header Parameter](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4)) the server expects to receive in the JWT.

---
    Syntax:	 auth_jwt_bypass_methods GET | HEAD | POST | PUT | DELETE | MKCOL | COPY | MOVE | OPTIONS | PROPFIND | PROPPATCH | LOCK | UNLOCK | PATCH ...;
    Default: ——
    Context: http, server, location
    Example: auth_jwt_bypass_methods "GET" "OPTIONS" "HEAD" 

Specifies HTTP methods that should be **bypassed** by module.

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
